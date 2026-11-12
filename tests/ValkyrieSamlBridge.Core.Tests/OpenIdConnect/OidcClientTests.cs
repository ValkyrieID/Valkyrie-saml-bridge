using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.OpenIdConnect;

namespace ValkyrieSamlBridge.Core.Tests.OpenIdConnect;

public sealed class OidcClientTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan ClockSkew = BridgeOptions.Create(new Uri("https://sso.example.test/")).ClockSkew;

    [Fact]
    public async Task AuthorizationRequestUsesPkceS256StateAndNonce()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();

        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);

        var query = ParseQuery(request.Url.Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal(request.State, query["state"]);
        Assert.Equal(request.Nonce, query["nonce"]);
        Assert.Equal(FakeOidcProvider.RedirectUri.AbsoluteUri, query["redirect_uri"]);
        Assert.Equal(Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(request.CodeVerifier))), query["code_challenge"]);
        Assert.True(request.CodeVerifier.Length >= 43);
    }

    // OIDC Core §3.1.2.1: the openid scope is required. Without it, this isn't an OpenID Connect request.
    [Fact]
    public async Task AuthorizationRequestWithoutOpenIdIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateAuthorizationRequestAsync("profile email", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AuthorizationRequestSendsTheScopeItIsGiven()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();

        var request = await client.CreateAuthorizationRequestAsync("openid email", null, TestContext.Current.CancellationToken);

        Assert.Equal("openid email", ParseQuery(request.Url.Query)["scope"]);
    }

    [Fact]
    public async Task EachRequestGetsFreshStateNonceAndVerifier()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();

        var first = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        var second = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);

        Assert.NotEqual(first.State, second.State);
        Assert.NotEqual(first.Nonce, second.Nonce);
        Assert.NotEqual(first.CodeVerifier, second.CodeVerifier);
    }

    [Fact]
    public async Task ValidCallbackReturnsTheSubject()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);

        var result = await client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken);

        Assert.Equal(FakeOidcProvider.Subject, result.Subject);
    }

    [Fact]
    public async Task TokenRequestAuthenticatesWithClientSecretBasicAndSendsTheVerifier()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);

        await client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken);

        var tokenRequest = fake.TokenRequests.Single();
        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{FakeOidcProvider.ClientId}:{FakeOidcProvider.ClientSecret}"));
        Assert.Equal(new AuthenticationHeaderValue("Basic", expected), tokenRequest.Headers.Authorization);
        Assert.Contains($"code_verifier={request.CodeVerifier}", tokenRequest.Body);
    }

    // OIDC Discovery §3 and RFC 6749 §2.3.1: basic is preferred when advertised alongside post.
    [Fact]
    public async Task BasicAdvertisedWithPostUsesBasic()
    {
        using var fake = new FakeOidcProvider { AuthMethods = ["client_secret_post", "client_secret_basic"] };
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);

        await client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken);

        var tokenRequest = fake.TokenRequests.Single();
        Assert.Equal("Basic", tokenRequest.Headers.Authorization?.Scheme);
        Assert.DoesNotContain("client_secret=", tokenRequest.Body);
    }

    // OIDC Discovery §3 and RFC 6749 §2.3.1: post is used only when basic isn't advertised. The credentials go in
    // the body, and no Authorization header is sent, so the request uses one method only.
    [Fact]
    public async Task PostOnlyAdvertisedSendsCredentialsInTheBody()
    {
        using var fake = new FakeOidcProvider { AuthMethods = ["client_secret_post"] };
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);

        await client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken);

        var tokenRequest = fake.TokenRequests.Single();
        Assert.Null(tokenRequest.Headers.Authorization);
        Assert.Contains($"client_id={FakeOidcProvider.ClientId}", tokenRequest.Body);
        Assert.Contains($"client_secret={FakeOidcProvider.ClientSecret}", tokenRequest.Body);
        Assert.Contains($"code_verifier={request.CodeVerifier}", tokenRequest.Body);
    }

    // OIDC Discovery §3 and RFC 6749 §2.3.1: a provider that advertises neither basic nor post is refused at discovery.
    [Fact]
    public async Task ProviderWithNoSupportedClientAuthenticationIsRefused()
    {
        using var fake = new FakeOidcProvider { AuthMethods = ["private_key_jwt"] };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    // OIDC Core §3.1.2.1 and RFC 6749 §4.1.1: the provider must advertise the code response type.
    [Fact]
    public async Task DiscoveryAdvertisingCodeIsAccepted()
    {
        using var fake = new FakeOidcProvider { ResponseTypes = ["id_token", "code"] };
        var client = fake.CreateClient();

        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);

        Assert.Equal("code", ParseQuery(request.Url.Query)["response_type"]);
    }

    [Fact]
    public async Task DiscoveryWithoutCodeResponseTypeIsRefused()
    {
        using var fake = new FakeOidcProvider { ResponseTypes = ["id_token"] };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DiscoveryWithoutResponseTypesIsRefused()
    {
        using var fake = new FakeOidcProvider { ResponseTypes = null };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    // RFC 7636 §4.3 and RFC 9700 §2.1.1: S256 must be advertised. A provider that offers "plain" alone is refused.
    [Fact]
    public async Task DiscoveryAdvertisingS256IsAccepted()
    {
        using var fake = new FakeOidcProvider { ChallengeMethods = ["plain", "S256"] };
        var client = fake.CreateClient();

        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);

        Assert.Equal("S256", ParseQuery(request.Url.Query)["code_challenge_method"]);
    }

    [Fact]
    public async Task DiscoveryWithoutPkceMethodsIsRefused()
    {
        using var fake = new FakeOidcProvider { ChallengeMethods = null };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DiscoveryWithPlainPkceOnlyIsRefused()
    {
        // Attack: PKCE downgrade, where the code challenge is the verifier itself.
        using var fake = new FakeOidcProvider { ChallengeMethods = ["plain"] };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    // OIDC Core §10.1 and RFC 7518 §3.1: an ES256-only provider is accepted, and an RS256 token from it is refused.
    [Fact]
    public async Task EcdsaOnlyProviderIssuesAcceptedIdToken()
    {
        using var fake = new FakeOidcProvider { SigningAlgorithms = ["ES256"] };
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce, es256: true);

        var result = await client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken);

        Assert.Equal(FakeOidcProvider.Subject, result.Subject);
    }

    [Fact]
    public async Task RsaIdTokenIsRefusedWhenOnlyEs256IsAdvertised()
    {
        // Attack: the algorithm is narrowed to the advertised set, so an RS256 token from the same key set is refused.
        using var fake = new FakeOidcProvider { SigningAlgorithms = ["ES256"] };
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    // OIDC Core §10.1 and RFC 7518 §3.1: the intersection with the allow-list is empty, so the bridge refuses.
    [Fact]
    public async Task DiscoveryWithoutSigningAlgorithmsIsRefused()
    {
        using var fake = new FakeOidcProvider { SigningAlgorithms = null };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DiscoveryWithOnlyHmacSigningIsRefused()
    {
        // Attack: an HS256 provider. A shared secret would let anyone holding the client secret forge ID tokens.
        using var fake = new FakeOidcProvider { SigningAlgorithms = ["HS256"] };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DiscoveryWithOnlyNoneSigningIsRefused()
    {
        // Attack: unsigned ID tokens. "none" is never in the allow-list.
        using var fake = new FakeOidcProvider { SigningAlgorithms = ["none"] };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task WrongStateIsRefused()
    {
        // Attack: a response for another flow (CSRF or login injection).
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);

        await Assert.ThrowsAsync<OidcCallbackRejectedException>(() =>
            client.CompleteAuthorizationAsync(FakeOidcProvider.Callback("someone-else"), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task MissingIssIsRefused()
    {
        // RFC 9207 §2.4: the bridge requires iss, so a mix-up attempt can't go unnoticed.
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);
        var callback = new Uri($"{FakeOidcProvider.RedirectUri}?state={request.State}&code=auth-code");

        await Assert.ThrowsAsync<OidcCallbackRejectedException>(() => client.CompleteAuthorizationAsync(callback, request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task WrongIssIsRefused()
    {
        // Attack: mix-up, where the code came from a different authorization server.
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce);

        await Assert.ThrowsAsync<OidcCallbackRejectedException>(() =>
            client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State, iss: "https://evil.example.test"), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ErrorResponseIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        var callback = new Uri($"{FakeOidcProvider.RedirectUri}?iss={Uri.EscapeDataString(FakeOidcProvider.Issuer)}&state={request.State}&error=access_denied");

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(callback, request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RepeatedParametersAreRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        var callback = new Uri($"{FakeOidcProvider.Callback(request.State)}&code=second");

        await Assert.ThrowsAsync<OidcCallbackRejectedException>(() => client.CompleteAuthorizationAsync(callback, request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task MissingCodeIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        var callback = new Uri($"{FakeOidcProvider.RedirectUri}?iss={Uri.EscapeDataString(FakeOidcProvider.Issuer)}&state={request.State}");

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(callback, request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IdTokenWithAnotherNonceIsRefused()
    {
        // Attack: an ID token issued for a different login is replayed into this flow.
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token("nonce-from-another-flow");

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IdTokenExpiredBeyondClockSkewIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce, expires: Now.AddMinutes(-2));

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IdTokenExpiredWithinClockSkewIsAccepted()
    {
        // Boundary: one minute of skew is allowed, so 30 seconds past expiry still passes.
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce, expires: Now.AddSeconds(-30));

        var result = await client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken);

        Assert.Equal(FakeOidcProvider.Subject, result.Subject);
    }

    [Fact]
    public async Task IdTokenNotYetValidIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce, notBefore: Now.AddMinutes(5), expires: Now.AddMinutes(10));

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IdTokenForAnotherAudienceIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce, audience: "another-client");

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IdTokenSignedByAnotherKeyIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        using var attacker = RSA.Create(2048);
        fake.NextIdToken = fake.Token(request.Nonce, signer: attacker);

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    // HS* is excluded from the allow-list, even when the key is in the JWKS.
    [Fact]
    public async Task AnHs256SignedIdTokenIsRefused()
    {
        using var fake = new FakeOidcProvider { SigningAlgorithms = ["RS256", "ES256"] };
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        fake.NextIdToken = fake.Token(request.Nonce, hs256: true);

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task UnsignedIdTokenIsRefused()
    {
        using var fake = new FakeOidcProvider();
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);
        var header = Base64Url(Encoding.UTF8.GetBytes("""{"alg":"none","typ":"JWT"}"""));
        var payload = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["iss"] = FakeOidcProvider.Issuer,
            ["aud"] = FakeOidcProvider.ClientId,
            ["sub"] = FakeOidcProvider.Subject,
            ["nonce"] = request.Nonce,
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(),
        })));
        fake.NextIdToken = $"{header}.{payload}.";

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task FailedTokenRequestIsRefused()
    {
        using var fake = new FakeOidcProvider { TokenStatus = HttpStatusCode.BadRequest };
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<OidcException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    // A provider that can't be reached is a refusal. The HttpRequestException never escapes.
    [Fact]
    public async Task UnreachableDiscoveryIsRefusedNotThrownRaw()
    {
        var client = new OidcClient(
            new HttpClient(new StubHandler(_ => throw new HttpRequestException("The connection was refused."))),
            new OidcClientOptions(new Uri(FakeOidcProvider.Issuer), FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, FakeOidcProvider.RedirectUri),
            new FixedTime(Now), ClockSkew);

        var error = await Assert.ThrowsAsync<OidcUnreachableException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));

        var chain = new List<Exception>();
        for (var inner = error.InnerException; inner is not null; inner = inner.InnerException)
        {
            chain.Add(inner);
        }
        Assert.Contains(chain, e => e is HttpRequestException);
        Assert.Equal("The OIDC provider could not be reached.", error.Message);
    }

    [Fact]
    public async Task UnreachableTokenEndpointIsRefused()
    {
        using var fake = new FakeOidcProvider { TokenUnreachable = true };
        var client = fake.CreateClient();
        var request = await client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<OidcUnreachableException>(() => client.CompleteAuthorizationAsync(FakeOidcProvider.Callback(request.State), request, TestContext.Current.CancellationToken));
    }

    // HttpClient reports a timeout as TaskCanceledException. It's a refusal too, because the caller didn't cancel.
    [Fact]
    public async Task TimeoutIsRefusedAsUnreachable()
    {
        var client = new OidcClient(
            new HttpClient(new StubHandler(_ => throw new TaskCanceledException("The request timed out."))),
            new OidcClientOptions(new Uri(FakeOidcProvider.Issuer), FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, FakeOidcProvider.RedirectUri),
            new FixedTime(Now), ClockSkew);

        await Assert.ThrowsAsync<OidcUnreachableException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    // The caller's cancellation is not a refusal, so it passes through as the original exception.
    [Fact]
    public async Task CallerCancellationIsRethrownNotMappedToOidcException()
    {
        using var cancellation = new CancellationTokenSource();
        var client = new OidcClient(
            new HttpClient(new StubHandler(_ =>
            {
                cancellation.Cancel();
                throw new TaskCanceledException("The caller canceled.");
            })),
            new OidcClientOptions(new Uri(FakeOidcProvider.Issuer), FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, FakeOidcProvider.RedirectUri),
            new FixedTime(Now), ClockSkew);

        var error = await Record.ExceptionAsync(() => client.CreateAuthorizationRequestAsync("openid", null, cancellation.Token));

        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.IsNotType<OidcException>(error);
    }

    [Fact]
    public async Task DiscoveryDocumentWithAnotherIssuerIsRefused()
    {
        using var fake = new FakeOidcProvider { DiscoveryIssuer = "https://other.example.test" };
        var client = fake.CreateClient();

        await Assert.ThrowsAsync<OidcException>(() => client.CreateAuthorizationRequestAsync("openid", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void NonHttpsIssuerIsRefusedAtConstruction()
    {
        var options = new OidcClientOptions(new Uri("http://id.example.test"), FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, FakeOidcProvider.RedirectUri);

        Assert.Throws<InvalidOperationException>(() => new OidcClient(new HttpClient(), options, new FixedTime(Now), ClockSkew));
    }

    [Fact]
    public void NonHttpsRedirectUriIsRefusedAtConstruction()
    {
        var options = new OidcClientOptions(new Uri(FakeOidcProvider.Issuer), FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, new Uri("http://bridge.example.test/oidc/callback"));

        Assert.Throws<InvalidOperationException>(() => new OidcClient(new HttpClient(), options, new FixedTime(Now), ClockSkew));
    }

    private static Dictionary<string, string> ParseQuery(string query) =>
        query.TrimStart('?').Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FakeOidcProvider : IDisposable
    {
        public const string Issuer = "https://id.example.test";
        public const string ClientId = "saml-bridge";
        public const string ClientSecret = "client-secret-value";
        public const string Subject = "6f1c2d3e-0000-4000-8000-000000000001";
        public static readonly Uri RedirectUri = new("https://bridge.example.test/oidc/callback");
        private static readonly string[] CodeOnly = ["code"];
        private static readonly string[] PublicOnly = ["public"];
        private static readonly string[] RsaOnly = ["RS256"];
        private static readonly string[] S256Only = ["S256"];

        private readonly RSA _key = RSA.Create(2048);
        private readonly ECDsa _ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly byte[] _hmacKey = RandomNumberGenerator.GetBytes(32);
        private readonly List<HttpRequestMessage> _tokenRequests = [];
        private readonly List<string> _tokenBodies = [];

        public string? NextIdToken { get; set; }
        public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;
        public bool TokenUnreachable { get; set; }
        public string DiscoveryIssuer { get; set; } = Issuer;

        // Discovery fields. null means the field is absent from the document.
        public string[]? ResponseTypes { get; set; } = CodeOnly;
        public string[]? ChallengeMethods { get; set; } = S256Only;
        public string[]? SigningAlgorithms { get; set; } = RsaOnly;
        public string[]? AuthMethods { get; set; }

        public IEnumerable<TokenRequest> TokenRequests =>
            _tokenRequests.Zip(_tokenBodies, (request, body) => new TokenRequest(request.Headers, body));

        public OidcClient CreateClient() =>
            new(new HttpClient(new StubHandler(Route)), new OidcClientOptions(new Uri(Issuer), ClientId, ClientSecret, RedirectUri), new FixedTime(Now), ClockSkew);

        public static Uri Callback(string state, string iss = Issuer) =>
            new($"{RedirectUri}?iss={Uri.EscapeDataString(iss)}&state={Uri.EscapeDataString(state)}&code=auth-code");

        public string Token(
            string nonce,
            DateTimeOffset? expires = null,
            DateTimeOffset? notBefore = null,
            string audience = ClientId,
            RSA? signer = null,
            bool es256 = false,
            bool hs256 = false)
        {
            var key = hs256
                ? new SigningCredentials(new SymmetricSecurityKey(_hmacKey) { KeyId = "k3" }, SecurityAlgorithms.HmacSha256)
                : es256
                    ? new SigningCredentials(new ECDsaSecurityKey(_ecKey) { KeyId = "k2" }, SecurityAlgorithms.EcdsaSha256)
                    : new SigningCredentials(new RsaSecurityKey(signer ?? _key) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256);
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                Audience = audience,
                Subject = new ClaimsIdentity([new Claim("sub", Subject), new Claim("nonce", nonce)]),
                IssuedAt = Now.UtcDateTime,
                NotBefore = (notBefore ?? Now).UtcDateTime,
                Expires = (expires ?? Now.AddMinutes(5)).UtcDateTime,
                SigningCredentials = key,
            };
            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        private HttpResponseMessage Route(HttpRequestMessage request)
        {
            switch (request.RequestUri!.AbsolutePath)
            {
                case "/.well-known/openid-configuration":
                    return Json(Discovery());
                case "/.well-known/jwks":
                    var parameters = _key.ExportParameters(includePrivateParameters: false);
                    var ec = _ecKey.ExportParameters(includePrivateParameters: false);
                    return Json(new
                    {
                        keys = new object[]
                        {
                            new
                            {
                                kty = "RSA",
                                kid = "k1",
                                alg = "RS256",
                                use = "sig",
                                n = Base64Url(parameters.Modulus!),
                                e = Base64Url(parameters.Exponent!),
                            },
                            new
                            {
                                kty = "EC",
                                kid = "k2",
                                alg = "ES256",
                                use = "sig",
                                crv = "P-256",
                                x = Base64Url(ec.Q.X!),
                                y = Base64Url(ec.Q.Y!),
                            },
                            new
                            {
                                kty = "oct",
                                kid = "k3",
                                alg = "HS256",
                                use = "sig",
                                k = Base64Url(_hmacKey),
                            },
                        },
                    });
                case "/connect/token":
                    if (TokenUnreachable)
                    {
                        throw new HttpRequestException("The connection was refused.");
                    }
                    _tokenRequests.Add(request);
                    _tokenBodies.Add(request.Content!.ReadAsStringAsync().GetAwaiter().GetResult());
                    if (TokenStatus != HttpStatusCode.OK)
                    {
                        return new HttpResponseMessage(TokenStatus);
                    }
                    return Json(new { access_token = "not-used", token_type = "Bearer", id_token = NextIdToken });
                default:
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
        }

        private Dictionary<string, object> Discovery()
        {
            var document = new Dictionary<string, object>
            {
                ["issuer"] = DiscoveryIssuer,
                ["authorization_endpoint"] = $"{Issuer}/connect/authorize",
                ["token_endpoint"] = $"{Issuer}/connect/token",
                ["jwks_uri"] = $"{Issuer}/.well-known/jwks",
                ["subject_types_supported"] = PublicOnly,
            };
            if (ResponseTypes is not null)
            {
                document["response_types_supported"] = ResponseTypes;
            }
            if (ChallengeMethods is not null)
            {
                document["code_challenge_methods_supported"] = ChallengeMethods;
            }
            if (SigningAlgorithms is not null)
            {
                document["id_token_signing_alg_values_supported"] = SigningAlgorithms;
            }
            if (AuthMethods is not null)
            {
                document["token_endpoint_auth_methods_supported"] = AuthMethods;
            }
            return document;
        }

        private static HttpResponseMessage Json(object body) =>
            new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };

        public void Dispose()
        {
            _key.Dispose();
            _ecKey.Dispose();
        }
    }

    public sealed record TokenRequest(HttpRequestHeaders Headers, string Body);
}
