using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using ValkyrieSamlBridge.Core.Configuration;

namespace ValkyrieSamlBridge.Core.OpenIdConnect;

public sealed record AuthorizationRequest(Uri Url, string State, string Nonce, string CodeVerifier);

public sealed record ValidatedIdToken(string Subject, IReadOnlyDictionary<string, object> Claims);

// ErrorCode is the OAuth error code from an authorization response (RFC 6749 §4.1.2.1). It is never
// a token, code, or secret, so it's safe to act on.
public class OidcException(string message, string? errorCode = null, Exception? innerException = null) : Exception(message, innerException)
{
    public string? ErrorCode { get; } = errorCode;
}

// The callback's iss, state, or parameter checks (RFC 9207 §2.4, RFC 6749 §10.12) failed before any token
// request. The response may not belong to this login, so the callback doesn't answer the SP.
public sealed class OidcCallbackRejectedException(string message) : OidcException(message);

// A network or timeout failure reached the provider. The message names no URL, and the inner exception is never logged.
public sealed class OidcUnreachableException(Exception innerException)
    : OidcException("The OIDC provider could not be reached.", innerException: innerException);

// The bridge's confidential client for the OIDC provider (authorization code flow with PKCE S256).
// RFC 6749 §4.1, RFC 7636 (PKCE), RFC 9207 (iss), OIDC Core §3.1.3.7 (ID token
// validation), OIDC Discovery §4.3 (issuer match). Any failure throws OidcException, and the
// message never contains tokens, codes, or the client secret.
public sealed class OidcClient
{
    // OIDC Core §10.1 and RFC 7518 §3.1: the allow-list. "none" and HS* are never in it.
    private static readonly string[] AllowedIdTokenAlgorithms = ["RS256", "ES256"];

    private const string ClientSecretBasic = "client_secret_basic";
    private const string ClientSecretPost = "client_secret_post";

    private readonly HttpClient _http;
    private readonly OidcClientOptions _options;
    private readonly TimeProvider _time;
    private readonly TimeSpan _clockSkew;
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _configuration;
    private readonly JsonWebTokenHandler _tokenHandler = new();

    public OidcClient(HttpClient http, OidcClientOptions options, TimeProvider time, TimeSpan clockSkew)
    {
        options.Validate();
        _http = http;
        _options = options;
        _time = time;
        _clockSkew = clockSkew;

        var discoveryUrl = $"{options.Issuer.AbsoluteUri.TrimEnd('/')}/.well-known/openid-configuration";
        _configuration = new ConfigurationManager<OpenIdConnectConfiguration>(
            discoveryUrl,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(http) { RequireHttps = true });
    }

    // Fetches the discovery document and checks its issuer (OIDC Discovery §4.3).
    public async Task CheckDiscoveryAsync(CancellationToken cancellationToken) => await GetConfigurationAsync(cancellationToken);

    // The scope is set by the caller, so each login asks for only what its app's mappings need.
    // It must start with "openid" (OIDC Core §3.1.2.1).
    public async Task<AuthorizationRequest> CreateAuthorizationRequestAsync(string scope, string? prompt, CancellationToken cancellationToken)
    {
        if (!scope.Split(' ').Contains("openid", StringComparer.Ordinal))
        {
            throw new ArgumentException("The scope must include openid.", nameof(scope));
        }

        var config = await GetConfigurationAsync(cancellationToken);

        var state = RandomToken();
        var nonce = RandomToken();
        var verifier = RandomToken();
        var challenge = Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        var parameters = new List<string>
        {
            Parameter("response_type", "code"),
            Parameter("client_id", _options.ClientId),
            Parameter("redirect_uri", _options.RedirectUri.AbsoluteUri),
            Parameter("scope", scope),
            Parameter("state", state),
            Parameter("nonce", nonce),
            Parameter("code_challenge", challenge),
            Parameter("code_challenge_method", "S256"),
        };
        if (prompt is not null)
        {
            // OIDC Core §3.1.2.1: prompt=none asks for no UI, login forces re-authentication.
            parameters.Add(Parameter("prompt", prompt));
        }

        var url = new Uri($"{config.AuthorizationEndpoint}?{string.Join('&', parameters)}");
        return new AuthorizationRequest(url, state, nonce, verifier);
    }

    // callbackUri is the full URL the OIDC provider redirected the browser to. expected is the
    // request stored when the flow started. The iss and state checks run before the error check, so
    // an error response from another server is refused too (RFC 9207 §2.4).
    public async Task<ValidatedIdToken> CompleteAuthorizationAsync(
        Uri callbackUri, AuthorizationRequest expected, CancellationToken cancellationToken)
    {
        var config = await GetConfigurationAsync(cancellationToken);
        var parameters = ParseCallbackQuery(callbackUri);

        // RFC 9207 §2.4: the iss parameter must match the issuer, so a response from another
        // authorization server (mix-up) is refused. The bridge requires the parameter.
        if (!parameters.TryGetValue("iss", out var iss) || !SameIssuer(iss, config.Issuer))
        {
            throw new OidcCallbackRejectedException("The authorization response has a missing or wrong iss parameter.");
        }

        // RFC 6749 §10.12: compare state in constant time.
        if (!parameters.TryGetValue("state", out var state) ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(state), Encoding.UTF8.GetBytes(expected.State)))
        {
            throw new OidcCallbackRejectedException("The authorization response state does not match.");
        }

        if (parameters.TryGetValue("error", out var error))
        {
            throw new OidcException("The OIDC provider returned an error instead of a code.", error);
        }

        if (!parameters.TryGetValue("code", out var code) || string.IsNullOrEmpty(code))
        {
            throw new OidcException("The authorization response has no code.");
        }

        var idToken = await ExchangeCodeAsync(config, code, expected.CodeVerifier, cancellationToken);
        return await ValidateIdTokenAsync(config, idToken, expected.Nonce);
    }

    private async Task<string> ExchangeCodeAsync(
        OpenIdConnectConfiguration config, string code, string codeVerifier, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = _options.RedirectUri.AbsoluteUri,
            ["code_verifier"] = codeVerifier,
        };
        var authMethod = TokenEndpointAuthMethod(config);
        if (authMethod == ClientSecretPost)
        {
            // RFC 6749 §2.3.1: client_secret_post sends the credentials in the body. Only one method per request,
            // so no Authorization header is added below.
            form["client_id"] = _options.ClientId;
            form["client_secret"] = _options.ClientSecret;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, config.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };

        if (authMethod == ClientSecretBasic)
        {
            // RFC 6749 §2.3.1: client_secret_basic, with form-encoded credentials.
            var credentials = $"{Uri.EscapeDataString(_options.ClientId)}:{Uri.EscapeDataString(_options.ClientSecret)}";
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        }

        using var response = await SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new OidcException($"The token request failed with status {(int)response.StatusCode}.");
        }

        using var json = await ReadJsonAsync(response, cancellationToken);
        if (!json.RootElement.TryGetProperty("id_token", out var idToken) || idToken.ValueKind != JsonValueKind.String)
        {
            throw new OidcException("The token response has no ID token.");
        }

        return idToken.GetString()!;
    }

    private async Task<ValidatedIdToken> ValidateIdTokenAsync(OpenIdConnectConfiguration config, string idToken, string expectedNonce)
    {
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = config.Issuer,
            ValidateIssuer = true,
            ValidAudience = _options.ClientId,
            ValidateAudience = true,
            IssuerSigningKeys = config.SigningKeys,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = IdTokenAlgorithms(config),
            RequireSignedTokens = true,
            // Lifetime is checked below against the injected TimeProvider, because
            // TokenValidationParameters in this version reads the system clock.
            ValidateLifetime = false,
            ClockSkew = _clockSkew,
        };

        var result = await _tokenHandler.ValidateTokenAsync(idToken, parameters);
        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt)
        {
            throw new OidcException("The ID token is invalid.");
        }

        var now = _time.GetUtcNow();
        if (jwt.ValidTo == DateTime.MinValue || now > new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero) + _clockSkew)
        {
            throw new OidcException("The ID token has expired or has no expiry.");
        }
        if (jwt.ValidFrom != DateTime.MinValue && now < new DateTimeOffset(jwt.ValidFrom, TimeSpan.Zero) - _clockSkew)
        {
            throw new OidcException("The ID token is not valid yet.");
        }

        var claims = result.Claims;
        if (!claims.TryGetValue("nonce", out var nonce) || nonce is not string nonceValue ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(nonceValue), Encoding.UTF8.GetBytes(expectedNonce)))
        {
            throw new OidcException("The ID token nonce does not match.");
        }

        // OIDC Core §3.1.3.7 step 3–5: with several audiences, azp must name this client.
        var audiences = result.Claims.TryGetValue("aud", out var aud) && aud is IEnumerable<object> list ? list.Count() : 1;
        if (audiences > 1 && (!claims.TryGetValue("azp", out var azp) || azp as string != _options.ClientId))
        {
            throw new OidcException("The ID token azp does not match the client.");
        }

        if (!claims.TryGetValue("sub", out var sub) || sub is not string subject || subject.Length == 0)
        {
            throw new OidcException("The ID token has no subject.");
        }

        return new ValidatedIdToken(subject, new Dictionary<string, object>(claims));
    }

    // A network or timeout failure is a refusal, not an unhandled exception. The caller's own
    // cancellation is not, so it passes through unchanged.
    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            return await _http.SendAsync(request, cancellationToken);
        }
        catch (Exception error) when (IsNetworkFailure(error, cancellationToken))
        {
            throw new OidcUnreachableException(error);
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            return await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        }
        catch (Exception error) when (IsNetworkFailure(error, cancellationToken))
        {
            throw new OidcUnreachableException(error);
        }
    }

    private async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancellationToken)
    {
        OpenIdConnectConfiguration config;
        try
        {
            config = await _configuration.GetConfigurationAsync(cancellationToken);
        }
        catch (Exception error) when (IsNetworkFailure(error, cancellationToken))
        {
            throw new OidcUnreachableException(error);
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            // ConfigurationManager wraps the caller's cancellation. The caller gets its own cancellation back, not a refusal.
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
        if (!SameIssuer(config.Issuer, _options.Issuer.AbsoluteUri))
        {
            // OIDC Discovery §4.3: the issuer in the discovery document must equal the configured issuer.
            throw new OidcException("The discovery document issuer does not match the configured issuer.");
        }

        // These checks run on every call, including on a cached document, so every login refuses the same way.
        RequireCompliantProvider(config);
        return config;
    }

    // The provider must meet these rules, or the bridge refuses. The messages name the rule only.
    private static void RequireCompliantProvider(OpenIdConnectConfiguration config)
    {
        // RFC 6749 §4.1.1 and RFC 7636 §4.3: the authorization code flow needs the code response type.
        if (!config.ResponseTypesSupported.Contains("code", StringComparer.Ordinal))
        {
            throw new OidcException("The discovery document does not advertise the code response type.");
        }

        // RFC 7636 §4.3 and RFC 9700 §2.1.1: PKCE with S256 is required. A provider that offers only "plain" is refused.
        if (!config.CodeChallengeMethodsSupported.Contains("S256", StringComparer.Ordinal))
        {
            throw new OidcException("The discovery document does not advertise the S256 PKCE method.");
        }

        // OIDC Core §10.1 and RFC 7518 §3.1: at least one allowed ID token signing algorithm must be advertised.
        if (IdTokenAlgorithms(config).Length == 0)
        {
            throw new OidcException("The discovery document advertises no supported ID token signing algorithm.");
        }

        // OIDC Discovery §3 and RFC 6749 §2.3.1: this throws when no supported client authentication method is advertised.
        TokenEndpointAuthMethod(config);
    }

    // The allowed ID token algorithms are the allow-list intersected with what the provider advertises.
    // If the provider omits the field, the intersection is empty and the caller refuses.
    private static string[] IdTokenAlgorithms(OpenIdConnectConfiguration config) =>
        AllowedIdTokenAlgorithms.Intersect(config.IdTokenSigningAlgValuesSupported, StringComparer.Ordinal).ToArray();

    // OIDC Discovery §3: when token_endpoint_auth_methods_supported is absent, the default is client_secret_basic.
    // The parser returns an empty list for both an absent field and an empty array, so both are treated as absent.
    // An explicit [] therefore also gets client_secret_basic instead of a refusal. This is an accepted deviation.
    // Basic is preferred. Post is used only when basic isn't advertised. Any other method is refused.
    private static string TokenEndpointAuthMethod(OpenIdConnectConfiguration config)
    {
        var methods = config.TokenEndpointAuthMethodsSupported;
        if (methods.Count == 0 || methods.Contains(ClientSecretBasic, StringComparer.Ordinal))
        {
            return ClientSecretBasic;
        }
        if (methods.Contains(ClientSecretPost, StringComparer.Ordinal))
        {
            return ClientSecretPost;
        }

        throw new OidcException("The discovery document advertises no supported token endpoint authentication method.");
    }

    // The network failure can be the inner exception, because ConfigurationManager wraps the discovery fetch.
    // HttpClient reports a timeout as TaskCanceledException, so only the caller's own cancellation is excluded.
    private static bool IsNetworkFailure(Exception error, CancellationToken cancellationToken) =>
        !cancellationToken.IsCancellationRequested && HasNetworkCause(error);

    private static bool HasNetworkCause(Exception error) =>
        error is HttpRequestException or TaskCanceledException || (error.InnerException is { } inner && HasNetworkCause(inner));

    private static bool SameIssuer(string a, string b) =>
        string.Equals(a.TrimEnd('/'), b.TrimEnd('/'), StringComparison.Ordinal);

    private static Dictionary<string, string> ParseCallbackQuery(Uri callbackUri)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in callbackUri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            var name = Uri.UnescapeDataString((separator < 0 ? pair : pair[..separator]).Replace('+', ' '));
            var value = separator < 0 ? string.Empty : Uri.UnescapeDataString(pair[(separator + 1)..].Replace('+', ' '));

            // Duplicate parameters are ambiguous, so the response is refused.
            if (!result.TryAdd(name, value))
            {
                throw new OidcCallbackRejectedException("The authorization response repeats a parameter.");
            }
        }
        return result;
    }

    private static string Parameter(string name, string value) => $"{Uri.EscapeDataString(name)}={Uri.EscapeDataString(value)}";

    private static string RandomToken() => Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
