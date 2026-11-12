using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ValkyrieSamlBridge.Integration.Tests;

// A small HTTPS stand-in for the OIDC provider. It implements
// discovery, the authorization endpoint with PKCE and prompt=none, and the token endpoint.
// Tests change its behavior through the public properties.
public sealed class OidcProviderStub : IAsyncDisposable
{
    public const string ClientId = "bridge-client";
    public const string ClientSecret = "bridge-secret";
    public const string Sub = "7d1f1e2a-0000-4000-8000-000000000001";
    public static readonly string[] Amr = ["pwd"];
    private static readonly string[] SupportedChallengeMethods = ["S256"];
    private static readonly string[] SupportedResponseTypes = ["code"];

    private readonly WebApplication _app;
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly string _kid = Guid.NewGuid().ToString("N");
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _ecKid = Guid.NewGuid().ToString("N");
    private readonly ConcurrentDictionary<string, Grant> _grants = new();
    private readonly ConcurrentQueue<string> _authorizeRequests = new();

    private sealed record Grant(string Nonce, string Challenge, string RedirectUri, DateTimeOffset AuthTime);

    public string Issuer { get; }

    public X509Certificate2 Certificate { get; }

    public bool SignedIn { get; set; } = true;

    public bool OmitAuthTime { get; set; }

    public TimeSpan AuthTimeAge { get; set; } = TimeSpan.FromSeconds(30);

    // When set, discovery advertises only "plain" PKCE, so the bridge refuses the provider.
    public bool OmitS256 { get; set; }

    public bool OmitEmail { get; set; }

    // When set, the authorization response carries no iss parameter (RFC 9207 §2.4).
    public bool OmitIssuer { get; set; }

    // When set, the authorization response carries this iss instead of the real issuer (RFC 9207 §2.4).
    public string? ResponseIssuer { get; set; }

    // Extra claims added to the ID token, for claim mapping tests.
    public Dictionary<string, object> ExtraIdTokenClaims { get; } = new(StringComparer.Ordinal);

    // When set, the ID token carries a nonce that doesn't match the request, so the callback refuses it (OIDC Core §3.1.3.7 step 11).
    public bool WrongNonce { get; set; }

    // When set, discovery reports this issuer instead of the real one (OIDC Discovery §4.3 mismatch test).
    public string? DiscoveryIssuerOverride { get; set; }

    // Discovery advertises these ID token signing algorithms. SigningAlgorithm can differ from them, to model a provider
    // that signs with an algorithm it doesn't advertise.
    public string[] AdvertisedSigningAlgorithms { get; set; } = ["RS256"];

    public string SigningAlgorithm { get; set; } = "RS256";

    // Discovery advertises these token endpoint auth methods, and the token endpoint accepts only these (RFC 6749 §2.3.1).
    public string[] TokenEndpointAuthMethods { get; set; } = ["client_secret_basic"];

    // What the last token request sent: its Authorization header, or null when it had none, and its form fields.
    public string? LastTokenAuthorization { get; private set; }

    public IReadOnlyDictionary<string, string>? LastTokenForm { get; private set; }

    public IReadOnlyList<string> AuthorizeRequests => _authorizeRequests.ToArray();

    public static async Task<OidcProviderStub> StartAsync()
    {
        var port = FreePort();
        using var rootKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        using var self = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
        var certificate = X509CertificateLoader.LoadPkcs12(self.Export(X509ContentType.Pfx), null);

        var stub = new OidcProviderStub(port, certificate);
        await stub._app.StartAsync();
        return stub;
    }

    private OidcProviderStub(int port, X509Certificate2 certificate)
    {
        Certificate = certificate;
        Issuer = $"https://localhost:{port}";

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.ListenLocalhost(port, listen => listen.UseHttps(certificate)));
        _app = builder.Build();
        MapEndpoints();
    }

    public string CertificateThumbprint => Certificate.Thumbprint;

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _rsa.Dispose();
        _ecdsa.Dispose();
        Certificate.Dispose();
    }

    private void MapEndpoints()
    {
        _app.MapGet("/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = DiscoveryIssuerOverride ?? Issuer,
            authorization_endpoint = $"{Issuer}/authorize",
            token_endpoint = $"{Issuer}/token",
            jwks_uri = $"{Issuer}/jwks",
            response_types_supported = SupportedResponseTypes,
            id_token_signing_alg_values_supported = AdvertisedSigningAlgorithms,
            token_endpoint_auth_methods_supported = TokenEndpointAuthMethods,
            code_challenge_methods_supported = OmitS256 ? ["plain"] : SupportedChallengeMethods,
        }));

        _app.MapGet("/jwks", () =>
        {
            var parameters = _rsa.ExportParameters(false);
            var ec = _ecdsa.ExportParameters(false);
            return Results.Json(new
            {
                keys = new object[]
                {
                    new
                    {
                        kty = "RSA",
                        kid = _kid,
                        use = "sig",
                        alg = "RS256",
                        n = Base64Url(parameters.Modulus!),
                        e = Base64Url(parameters.Exponent!),
                    },
                    new
                    {
                        kty = "EC",
                        kid = _ecKid,
                        use = "sig",
                        alg = "ES256",
                        crv = "P-256",
                        x = Base64Url(ec.Q.X!),
                        y = Base64Url(ec.Q.Y!),
                    },
                },
            });
        });

        _app.MapGet("/authorize", (HttpContext context) => Authorize(context));

        _app.MapPost("/token", async Task<IResult> (HttpContext context) => await TokenAsync(context));
    }

    private IResult Authorize(HttpContext context)
    {
        var query = context.Request.Query;
        _authorizeRequests.Enqueue(context.Request.QueryString.ToString());

        var redirectUri = query["redirect_uri"].ToString();
        var state = query["state"].ToString();
        var prompt = query["prompt"].ToString();

        if (!SignedIn && prompt == "none")
        {
            return Redirect(redirectUri, WithIssuer(("error", "login_required"), ("state", state)));
        }

        var code = Base64Url(RandomNumberGenerator.GetBytes(24));
        _grants[code] = new Grant(
            Nonce: query["nonce"].ToString(),
            Challenge: query["code_challenge"].ToString(),
            RedirectUri: redirectUri,
            AuthTime: DateTimeOffset.UtcNow - AuthTimeAge);
        return Redirect(redirectUri, WithIssuer(("code", code), ("state", state)));
    }

    private (string Name, string Value)[] WithIssuer(params (string Name, string Value)[] parameters)
    {
        if (OmitIssuer)
        {
            return parameters;
        }
        return [.. parameters, ("iss", ResponseIssuer ?? Issuer)];
    }

    private async Task<IResult> TokenAsync(HttpContext context)
    {
        var form = await context.Request.ReadFormAsync();
        var authorization = context.Request.Headers.Authorization.ToString();
        LastTokenAuthorization = authorization.Length == 0 ? null : authorization;
        LastTokenForm = form.ToDictionary(field => field.Key, field => field.Value.ToString());
        if (!IsAuthenticatedClient(context, form))
        {
            return Results.Unauthorized();
        }

        var code = form["code"].ToString();
        if (!_grants.TryRemove(code, out var grant))
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        var verifier = form["code_verifier"].ToString();
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(challenge), Encoding.ASCII.GetBytes(grant.Challenge)))
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        if (form["redirect_uri"].ToString() != grant.RedirectUri)
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        var claims = new Dictionary<string, object>
        {
            ["nonce"] = WrongNonce ? "nonce-from-another-login" : grant.Nonce,
            ["email"] = "alice@example.test",
            ["preferred_username"] = "alice",
            ["roles"] = new[] { "admin", "staff" },
            ["groups"] = new[] { "payroll" },
            ["amr"] = Amr,
            ["sid"] = "session-1",
        };
        if (!OmitAuthTime)
        {
            claims["auth_time"] = grant.AuthTime.ToUnixTimeSeconds();
        }
        if (OmitEmail)
        {
            claims.Remove("email");
        }
        foreach (var (name, value) in ExtraIdTokenClaims)
        {
            claims[name] = value;
        }

        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            Subject = new ClaimsIdentity(new[] { new Claim("sub", Sub) }),
            Claims = claims,
            IssuedAt = now,
            NotBefore = now.AddSeconds(-1),
            Expires = now.AddMinutes(5),
            SigningCredentials = TokenSigningCredentials(),
        });

        return Results.Json(new
        {
            access_token = "access-" + Base64Url(RandomNumberGenerator.GetBytes(16)),
            token_type = "Bearer",
            expires_in = 300,
            id_token = token,
        });
    }

    private SigningCredentials TokenSigningCredentials() => SigningAlgorithm == "ES256"
        ? new SigningCredentials(new ECDsaSecurityKey(_ecdsa) { KeyId = _ecKid }, SecurityAlgorithms.EcdsaSha256)
        : new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = _kid }, SecurityAlgorithms.RsaSha256);

    private bool IsAuthenticatedClient(HttpContext context, IFormCollection form)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic ", StringComparison.Ordinal))
        {
            if (!TokenEndpointAuthMethods.Contains("client_secret_basic", StringComparer.Ordinal))
            {
                return false;
            }
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..]));
            var parts = decoded.Split(':', 2);
            return parts.Length == 2 && Uri.UnescapeDataString(parts[0]) == ClientId && Uri.UnescapeDataString(parts[1]) == ClientSecret;
        }

        if (!TokenEndpointAuthMethods.Contains("client_secret_post", StringComparer.Ordinal))
        {
            return false;
        }
        return form["client_id"].ToString() == ClientId && form["client_secret"].ToString() == ClientSecret;
    }

    private static IResult Redirect(string target, params (string Name, string Value)[] parameters)
    {
        var builder = new UriBuilder(target);
        var query = string.Join('&', parameters.Select(p => $"{Uri.EscapeDataString(p.Name)}={Uri.EscapeDataString(p.Value)}"));
        builder.Query = string.IsNullOrEmpty(builder.Query) ? query : builder.Query.TrimStart('?') + "&" + query;
        return Results.Redirect(builder.Uri.AbsoluteUri);
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}




