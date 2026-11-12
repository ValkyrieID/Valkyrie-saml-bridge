using System.Xml;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Integration.Tests;

// Discovery and token variants of the OIDC provider. Each one runs the real HTTP path, through the bridge and the stub.
public sealed class ProviderVariantTests
{
    private const string Acs = "https://payroll.example.test/saml/acs";

    // OIDC Discovery §3: id_token_signing_alg_values_supported lists the algorithms the provider signs with.
    [Fact]
    public async Task AnEs256OnlyProviderLogsTheUserIn()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s =>
        {
            s.AdvertisedSigningAlgorithms = ["ES256"];
            s.SigningAlgorithm = "ES256";
        });

        var document = await SpInitiatedSsoTests.LoginAsync(env);

        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
        var assertion = (XmlElement)document.DocumentElement!.GetElementsByTagName("Assertion", SamlNames.AssertionNs)[0]!;
        Assert.Equal(OidcProviderStub.Sub, assertion.GetElementsByTagName("NameID", SamlNames.AssertionNs)[0]!.InnerText);
    }

    // Attack: a token signed with an algorithm the provider doesn't advertise is refused at the callback (OIDC Core §3.1.3.7 step 6).
    [Fact]
    public async Task AnEs256OnlyProviderThatSignsWithRs256IsRefusedToTheValidatedAcs()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.AdvertisedSigningAlgorithms = ["ES256"]);

        var redirect = await SpInitiatedSsoTests.PostAsync(env.Bridge, SpInitiatedSsoTests.AuthnRequest("_req-rs256-on-es256"));
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, _) = await SpInitiatedSsoTests.ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusAuthnFailed, SpInitiatedSsoTests.StatusCodeOf(document));
        Assert.Empty(document.DocumentElement!.GetElementsByTagName("Assertion", SamlNames.AssertionNs));
    }

    // RFC 6749 §2.3.1: client_secret_post sends client_id and client_secret in the request body, with no Authorization header.
    [Fact]
    public async Task AProviderThatAdvertisesOnlyClientSecretPostGetsTheCredentialsInTheBody()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.TokenEndpointAuthMethods = ["client_secret_post"]);

        var document = await SpInitiatedSsoTests.LoginAsync(env);

        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
        Assert.Null(env.Stub.LastTokenAuthorization);
        Assert.Equal(OidcProviderStub.ClientId, env.Stub.LastTokenForm!["client_id"]);
        Assert.Equal(OidcProviderStub.ClientSecret, env.Stub.LastTokenForm["client_secret"]);
    }

    // RFC 6749 §2.3.1: when both are advertised, the bridge prefers client_secret_basic.
    [Fact]
    public async Task AProviderThatAdvertisesBasicAndPostGetsTheCredentialsInTheHeader()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.TokenEndpointAuthMethods = ["client_secret_basic", "client_secret_post"]);

        var document = await SpInitiatedSsoTests.LoginAsync(env);

        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
        Assert.StartsWith("Basic ", env.Stub.LastTokenAuthorization, StringComparison.Ordinal);
        Assert.False(env.Stub.LastTokenForm!.ContainsKey("client_secret"));
    }

    // A provider with no supported token auth method stops the bridge at startup.
    [Fact]
    public async Task AProviderWithNoSupportedTokenAuthMethodStopsTheBridgeAtStartup()
    {
        var error = await Assert.ThrowsAnyAsync<OidcException>(() => BridgeEnvironment.CreateAsync(configureStub: s => s.TokenEndpointAuthMethods = ["private_key_jwt"]));

        Assert.Contains("token endpoint authentication method", error.Message, StringComparison.Ordinal);
    }
}
