using System.Net;
using System.Xml;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Integration.Tests;

// IdP-initiated SSO through /idp/{slug}. The app is registered by the same CLI an admin uses.
public sealed class IdpInitiatedSsoTests
{
    private const string Acs = "https://payroll.example.test/saml/acs";
    private const string EntityId = "https://payroll.example.test/saml";

    private static Task<HttpResponseMessage> StartAsync(BridgeEnvironment env, string query = "") =>
        env.Bridge.GetAsync("/idp/" + BridgeEnvironment.AppSlug + query);

    // Runs the whole flow: start, OIDC provider sign-in, callback. Returns the auto-post result.
    private static async Task<(string Acs, XmlDocument Response, string? RelayState)> LoginAsync(BridgeEnvironment env, string query = "")
    {
        var redirect = await StartAsync(env, query);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        return await SpInitiatedSsoTests.ReadAutoPostAsync(await env.Bridge.GetAsync(callback));
    }

    [Fact]
    public async Task IdpInitiatedLoginPostsAnUnsolicitedSignedResponseToTheStoredAcs()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        var redirect = await StartAsync(env);
        Assert.Contains("prompt=none", redirect.Headers.Location!.Query, StringComparison.Ordinal);
        var (acs, document, _) = await LoginAsync(env);

        var certificate = await SpInitiatedSsoTests.BridgeCertificateAsync(env);
        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
        Assert.False(document.DocumentElement!.HasAttribute("InResponseTo"));
        Assert.Equal(Acs, document.DocumentElement.GetAttribute("Destination"));
        Assert.True(XmlSignatureVerifier.Verify(document, [certificate]), "The response signature must verify.");

        var assertion = (XmlElement)document.DocumentElement.GetElementsByTagName("Assertion", SamlNames.AssertionNs)[0]!;
        var confirmation = (XmlElement)assertion.GetElementsByTagName("SubjectConfirmationData", SamlNames.AssertionNs)[0]!;
        Assert.False(confirmation.HasAttribute("InResponseTo"));
        Assert.Equal(Acs, confirmation.GetAttribute("Recipient"));
        Assert.Equal(EntityId, assertion.GetElementsByTagName("Audience", SamlNames.AssertionNs)[0]!.InnerText);
        Assert.True(XmlSignatureVerifier.Verify(SafeXml.Parse(assertion.OuterXml), [certificate]), "The assertion signature must verify.");
    }

    [Fact]
    public async Task AllowListedRelayStateIsEchoed()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--relay-state", "/dashboard");

        var (_, _, relay) = await LoginAsync(env, "?RelayState=%2Fdashboard");

        Assert.Equal("/dashboard", relay);
    }

    // A callback refusal on an IdP-initiated login is the local page, never a SAML error to the ACS.
    [Fact]
    public async Task CallbackRefusalGetsTheLocalErrorPageNotASamlResponse()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.WrongNonce = true);

        var redirect = await StartAsync(env);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack (RFC 9207 §2.4): the provider omits iss, so the callback is refused and the local page is shown with no SAML response.
    [Fact]
    public async Task IdpLoginWhenTheProviderOmitsIssuerGetsTheLocalErrorPageNotASamlResponse()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.OmitIssuer = true);

        var redirect = await StartAsync(env);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack (RFC 9207 §2.4): the provider returns another issuer's iss. Refused the same way as a missing iss.
    [Fact]
    public async Task IdpLoginWhenTheProviderReturnsAWrongIssuerGetsTheLocalErrorPageNotASamlResponse()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.ResponseIssuer = "https://other-issuer.example.test");

        var redirect = await StartAsync(env);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // A silent sign-in that fails is retried with the sign-in page, as in SP-initiated.
    [Fact]
    public async Task SilentSignInFailsAndTheBridgeRetriesWithoutPrompt()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.SignedIn = false);

        var redirect = await StartAsync(env);
        using var stub = SpInitiatedSsoTests.StubClient(env);
        using var failure = await stub.GetAsync(redirect.Headers.Location, TestContext.Current.CancellationToken);
        var retry = await env.Bridge.GetAsync(new Uri(failure.Headers.Location!.ToString()).PathAndQuery, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, retry.StatusCode);
        Assert.DoesNotContain("prompt=", retry.Headers.Location!.Query, StringComparison.Ordinal);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, retry);
        var (_, document, _) = await SpInitiatedSsoTests.ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));
        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
    }

    // Attack: a login to an app that was never registered gets the local page, nothing to post.
    [Fact]
    public async Task IdpLoginForAnUnregisteredAppGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync(registerApp: false);

        using var response = await StartAsync(env);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack: an unknown slug and a disabled app get the same generic page, with nothing to post.
    [Fact]
    public async Task UnknownSlugGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await env.Bridge.GetAsync("/idp/no-such-app", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisabledAppGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--disable");

        using var response = await StartAsync(env);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // Attack: a slug that doesn't match the slug format is refused before any lookup.
    [Fact]
    public async Task MalformedSlugGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await env.Bridge.GetAsync("/idp/Payroll", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // A RelayState not on the allow-list is dropped, never echoed.
    [Fact]
    public async Task RelayStateNotOnTheAllowListIsDropped()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--relay-state", "/dashboard");

        var (_, document, relay) = await LoginAsync(env, "?RelayState=https%3A%2F%2Fevil.example.test");

        Assert.Null(relay);
        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
    }

    // Attack: a second RelayState parameter is malformed, so the start is refused.
    [Fact]
    public async Task RepeatedRelayStateGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--relay-state", "/dashboard");

        using var response = await StartAsync(env, "?RelayState=%2Fdashboard&RelayState=%2Fdashboard");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // Attack: an ACS in the request is ignored. The response goes only to the stored ACS.
    [Fact]
    public async Task AcsInTheRequestIsIgnored()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        var (acs, document, _) = await LoginAsync(env, "?AssertionConsumerServiceURL=https%3A%2F%2Fattacker.example.test%2Fcollect");

        Assert.Equal(Acs, acs);
        Assert.Equal(Acs, document.DocumentElement!.GetAttribute("Destination"));
    }

    // Attack: the admin disables the app while a login is in progress. The callback refuses it.
    [Fact]
    public async Task AppDisabledDuringTheLoginIsRefused()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var redirect = await StartAsync(env);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        await BridgeEnvironment.ConfigureAppAsync("--disable");

        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack: an IdP login has no request to answer, so a refusal is the local page, never a SAML error to the ACS.
    [Fact]
    public async Task MissingRequiredClaimGetsTheLocalErrorPageNotASamlResponse()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.OmitEmail = true);
        await BridgeEnvironment.ConfigureAppAsync("--attribute", "mail=email,required");

        var redirect = await StartAsync(env);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack: a pending login is single use, so the callback can't be replayed.
    [Fact]
    public async Task CallbackCannotBeReplayed()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var redirect = await StartAsync(env);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        using var first = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        using var replay = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }
}
