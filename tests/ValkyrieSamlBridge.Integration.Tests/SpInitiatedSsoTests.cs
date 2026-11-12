using System.IO.Compression;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Integration.Tests;

public sealed class SpInitiatedSsoTests
{
    private const string Acs = "https://payroll.example.test/saml/acs";
    private const string EntityId = "https://payroll.example.test/saml";

    internal static string AuthnRequest(
        string? id = null,
        string issuer = EntityId,
        string acs = Acs,
        bool forceAuthn = false,
        bool isPassive = false,
        string? requestedClass = null)
    {
        var issued = DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture);
        id ??= "_" + Guid.NewGuid().ToString("N");
        var requested = requestedClass is null ? string.Empty : $"""
            <samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>{requestedClass}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>
            """;
        return $"""
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued}" Destination="{BridgeEnvironment.PublicUrl}/saml/sso" AssertionConsumerServiceURL="{acs}" ProtocolBinding="{SamlNames.HttpPost}" ForceAuthn="{(forceAuthn ? "true" : "false")}" IsPassive="{(isPassive ? "true" : "false")}">
              <saml:Issuer>{issuer}</saml:Issuer>
              {requested}
            </samlp:AuthnRequest>
            """;
    }

    internal static async Task<HttpResponseMessage> PostAsync(HttpClient bridge, string xml, string? relayState = null)
    {
        var form = new List<KeyValuePair<string, string>> { new("SAMLRequest", Convert.ToBase64String(Encoding.UTF8.GetBytes(xml))) };
        if (relayState is not null)
        {
            form.Add(new("RelayState", relayState));
        }
        return await bridge.PostAsync("/saml/sso", new FormUrlEncodedContent(form));
    }

    private static async Task<HttpResponseMessage> GetRedirectAsync(HttpClient bridge, string xml, string relayState)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflate.Write(Encoding.UTF8.GetBytes(xml));
        }
        var query = $"SAMLRequest={Uri.EscapeDataString(Convert.ToBase64String(output.ToArray()))}&RelayState={Uri.EscapeDataString(relayState)}";
        return await bridge.GetAsync("/saml/sso?" + query);
    }

    internal static HttpClient StubClient(BridgeEnvironment env) => new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate?.Thumbprint == env.Stub.CertificateThumbprint,
    });

    // Follows the bridge's redirect to the OIDC provider and the stub's redirect back. Returns the callback path and query.
    internal static async Task<string> SignInAtOidcProviderAsync(BridgeEnvironment env, HttpResponseMessage bridgeRedirect)
    {
        Assert.True(bridgeRedirect.StatusCode == HttpStatusCode.Redirect, $"Expected a redirect to the OIDC provider, got {(int)bridgeRedirect.StatusCode}: {await bridgeRedirect.Content.ReadAsStringAsync()}");
        using var stub = StubClient(env);
        using var response = await stub.GetAsync(bridgeRedirect.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return new Uri(response.Headers.Location!.ToString()).PathAndQuery;
    }

    internal static async Task<(string Acs, XmlDocument Response, string? RelayState)> ReadAutoPostAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        var encoded = Regex.Match(html, "name=\"SAMLResponse\" value=\"([^\"]+)\"").Groups[1].Value;
        var relay = Regex.Match(html, "name=\"RelayState\" value=\"([^\"]*)\"");
        var action = Regex.Match(html, "action=\"([^\"]+)\"").Groups[1].Value;
        var xml = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        return (action, SafeXml.Parse(xml), relay.Success ? WebUtility.HtmlDecode(relay.Groups[1].Value) : null);
    }

    internal static async Task<X509Certificate2> BridgeCertificateAsync(BridgeEnvironment env)
    {
        var metadata = await env.Bridge.GetStringAsync("/saml/metadata");
        var der = Convert.FromBase64String(SafeXml.Parse(metadata).GetElementsByTagName("X509Certificate", SamlNames.DsigNs)[0]!.InnerText);
        return X509CertificateLoader.LoadCertificate(der);
    }

    internal static string StatusCodeOf(XmlDocument response)
    {
        var top = (XmlElement)response.DocumentElement!.GetElementsByTagName("StatusCode", SamlNames.ProtocolNs)[0]!;
        var nested = top.GetElementsByTagName("StatusCode", SamlNames.ProtocolNs);
        return nested.Count == 0 ? top.Attributes!["Value"]!.Value : nested[0]!.Attributes!["Value"]!.Value;
    }

    internal static async Task<XmlDocument> LoginAsync(BridgeEnvironment env)
    {
        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback));
        return document;
    }

    [Fact]
    public async Task PostBindingLoginReturnsASignedResponseForTheSubject()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var xml = AuthnRequest("_req-happy");

        var redirect = await PostAsync(env.Bridge, xml);
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        var certificate = await BridgeCertificateAsync(env);
        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));
        Assert.Equal("_req-happy", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal(Acs, document.DocumentElement.GetAttribute("Destination"));
        Assert.True(XmlSignatureVerifier.Verify(document, [certificate]), "The response signature must verify against the published certificate.");

        var assertion = (XmlElement)document.DocumentElement.GetElementsByTagName("Assertion", SamlNames.AssertionNs)[0]!;
        Assert.Equal(OidcProviderStub.Sub, assertion.GetElementsByTagName("NameID", SamlNames.AssertionNs)[0]!.InnerText);
        Assert.Equal(EntityId, assertion.GetElementsByTagName("Audience", SamlNames.AssertionNs)[0]!.InnerText);
        Assert.Equal(SamlNames.AcPassword, assertion.GetElementsByTagName("AuthnContextClassRef", SamlNames.AssertionNs)[0]!.InnerText);
        Assert.Equal(Acs, assertion.GetElementsByTagName("SubjectConfirmationData", SamlNames.AssertionNs)[0]!.Attributes!["Recipient"]!.Value);
        Assert.True(XmlSignatureVerifier.Verify(SafeXml.Parse(assertion.OuterXml), [certificate]), "The assertion signature must verify.");
    }

    // SAML Bindings 2.0 §3.5.5: the user agent POSTs the form cross-site to the responder. The antiforgery
    // middleware must not refuse it (the endpoint reads the form itself and has no RequiresValidation metadata).
    [Fact]
    public async Task CrossSitePostBindingRequestIsNotBlockedByCsrfProtection()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/saml/sso")
        {
            Content = new FormUrlEncodedContent([new KeyValuePair<string, string>("SAMLRequest", Convert.ToBase64String(Encoding.UTF8.GetBytes(AuthnRequest("_req-cross-site"))))]),
        };
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "cross-site");
        request.Headers.TryAddWithoutValidation("Origin", "https://sp.example.test");

        using var redirect = await env.Bridge.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.NotEqual(HttpStatusCode.BadRequest, redirect.StatusCode);
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));
        Assert.Equal("_req-cross-site", document.DocumentElement!.GetAttribute("InResponseTo"));
    }

    [Fact]
    public async Task RedirectBindingRequestCarriesAnAllowListedRelayState()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--relay-state", "/dashboard");

        var redirect = await GetRedirectAsync(env.Bridge, AuthnRequest(), "/dashboard");
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, _, relay) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal("/dashboard", relay);
    }

    // Success: an XML-signed Redirect request from an app that must sign is accepted and logs in (SAML Bindings §3.4.4.1).
    [Fact]
    public async Task XmlSignedRedirectRequestFromAnAppThatMustSignLogsIn()
    {
        await using var env = await BridgeEnvironment.CreateAsync(registerApp: false);
        using var certificate = await env.RegisterSigningAppAsync();
        var xml = SamlRequests.SignXml(AuthnRequest("_req-xml-redirect", issuer: BridgeEnvironment.SigningAppEntityId, acs: BridgeEnvironment.SigningAppAcs), certificate);

        var redirect = await GetRedirectAsync(env.Bridge, xml, "/dashboard");
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, relay) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(BridgeEnvironment.SigningAppAcs, acs);
        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));
        Assert.Equal("_req-xml-redirect", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Equal("/dashboard", relay);
    }

    // Attack: an XML-signed Redirect request signed with a certificate the app never confirmed. The ACS is validated,
    // so the SP gets a Requester error to it, and no login starts.
    [Fact]
    public async Task ForgedXmlSignedRedirectRequestGetsARequesterErrorAndNoLogin()
    {
        await using var env = await BridgeEnvironment.CreateAsync(registerApp: false);
        await env.RegisterSigningAppAsync();
        using var attacker = BridgeEnvironment.CreateSelfSigned();
        var xml = SamlRequests.SignXml(AuthnRequest("_req-forged-xml-redirect", issuer: BridgeEnvironment.SigningAppEntityId, acs: BridgeEnvironment.SigningAppAcs), attacker);

        using var response = await GetRedirectAsync(env.Bridge, xml, "/dashboard");
        var (acs, document, _) = await ReadAutoPostAsync(response);

        Assert.Equal(BridgeEnvironment.SigningAppAcs, acs);
        Assert.Equal(SamlNames.StatusRequester, StatusCodeOf(document));
        Assert.Empty(env.Stub.AuthorizeRequests);
    }
    [Fact]
    public async Task SpInitiatedRelayStateNotOnTheAllowListIsEchoedUnchanged()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--relay-state", "/dashboard");

        var redirect = await PostAsync(env.Bridge, AuthnRequest(), "/orders/123");
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, relay) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(Acs, acs);
        Assert.Equal("/orders/123", relay);
        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));
    }

    // Success: a RelayState of exactly the 512-character limit is echoed.
    [Fact]
    public async Task RelayStateAtTheLengthLimitIsEchoed()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var relayState = "/" + new string('a', BridgeOptions.MaxRelayStateLength - 1);

        var redirect = await PostAsync(env.Bridge, AuthnRequest(), relayState);
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, _, relay) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(relayState, relay);
    }

    // Attack: one character over the limit is refused with the local page, before any login starts.
    [Fact]
    public async Task RelayStateOneCharacterOverTheLimitGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var relayState = "/" + new string('a', BridgeOptions.MaxRelayStateLength);

        using var response = await PostAsync(env.Bridge, AuthnRequest("_req-relay-too-long"), relayState);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack: an HTML-special RelayState is encoded in the auto-post form, so it can't break out of the value attribute.
    [Fact]
    public async Task RelayStateWithHtmlIsEncodedInTheAutoPostForm()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        const string relayState = "\"><script>alert(1)</script>";

        var redirect = await PostAsync(env.Bridge, AuthnRequest(), relayState);
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);
        var html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var (_, _, relay) = await ReadAutoPostAsync(response);

        Assert.DoesNotContain(relayState, html, StringComparison.Ordinal);
        Assert.Contains("&quot;&gt;&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Equal(relayState, relay);
    }

    // Attack: a ForceAuthn+IsPassive refusal is a SAML error to the validated ACS, and it echoes the RelayState.
    [Fact]
    public async Task ForceAuthnWithIsPassiveGetsARequesterErrorWithTheRelayState()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await PostAsync(env.Bridge, AuthnRequest("_req-force-passive", forceAuthn: true, isPassive: true), "/orders/123");
        var (acs, document, relay) = await ReadAutoPostAsync(response);

        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusRequester, StatusCodeOf(document));
        Assert.Equal("/orders/123", relay);
    }

    // Attack: an AuthnFailed response after the callback echoes the RelayState to the validated ACS only.
    [Fact]
    public async Task CallbackRefusalEchoesTheRelayStateToTheValidatedAcs()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.WrongNonce = true);

        var redirect = await PostAsync(env.Bridge, AuthnRequest("_req-refused-with-relay"), "/orders/123");
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, relay) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusAuthnFailed, StatusCodeOf(document));
        Assert.Equal("/orders/123", relay);
    }

    // Attack: an error for an unregistered ACS gets the local page, so the RelayState is never posted anywhere.
    [Fact]
    public async Task ErrorForAnUnregisteredAcsDoesNotCarryTheRelayState()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await PostAsync(env.Bridge, AuthnRequest(acs: "https://attacker.example.test/collect"), "/orders/123");
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.DoesNotContain("SAMLResponse", body, StringComparison.Ordinal);
        Assert.DoesNotContain("RelayState", body, StringComparison.Ordinal);
    }

    // prompt=none first, then the sign-in page without prompt.
    [Fact]
    public async Task SilentSignInFailsAndTheBridgeRetriesWithoutPrompt()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.SignedIn = false);

        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        Assert.Contains("prompt=none", redirect.Headers.Location!.Query, StringComparison.Ordinal);

        using var stub = StubClient(env);
        using var failure = await stub.GetAsync(redirect.Headers.Location, TestContext.Current.CancellationToken);
        var retry = await env.Bridge.GetAsync(new Uri(failure.Headers.Location!.ToString()).PathAndQuery, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, retry.StatusCode);
        Assert.DoesNotContain("prompt=", retry.Headers.Location!.Query, StringComparison.Ordinal);
        var callback = await SignInAtOidcProviderAsync(env, retry);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));
        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));
    }

    [Fact]
    public async Task ForceAuthnRequestsReauthentication()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        var redirect = await PostAsync(env.Bridge, AuthnRequest(forceAuthn: true));

        Assert.Contains("prompt=login", redirect.Headers.Location!.Query, StringComparison.Ordinal);
    }

    // Attack: the provider ignored prompt=login and returned an old session. SAML Core §3.4.1.1 needs a fresh sign-in.
    [Fact]
    public async Task ForceAuthnWithAStaleSignInGetsAuthnFailed()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.AuthTimeAge = TimeSpan.FromMinutes(10));

        var redirect = await PostAsync(env.Bridge, AuthnRequest(forceAuthn: true));
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusAuthnFailed, StatusCodeOf(document));
        Assert.DoesNotContain("<saml:Assertion", document.OuterXml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ForceAuthnWithAFreshSignInSucceeds()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        var redirect = await PostAsync(env.Bridge, AuthnRequest(forceAuthn: true));
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));
    }

    // An IsPassive request never gets a login page. The SP is told NoPassive.
    [Fact]
    public async Task IsPassiveWithoutASessionGetsNoPassiveToTheAcs()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.SignedIn = false);

        var redirect = await PostAsync(env.Bridge, AuthnRequest(isPassive: true));
        using var stub = StubClient(env);
        using var failure = await stub.GetAsync(redirect.Headers.Location, TestContext.Current.CancellationToken);
        var response = await env.Bridge.GetAsync(new Uri(failure.Headers.Location!.ToString()).PathAndQuery, TestContext.Current.CancellationToken);

        var (acs, document, _) = await ReadAutoPostAsync(response);
        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusNoPassive, StatusCodeOf(document));
    }

    // SAML Core §3.3.2.2.1: when the requested AuthnContext can't be met, the SP gets NoAuthnContext.
    [Fact]
    public async Task UnsatisfiedRequestedAuthnContextGetsNoAuthnContext()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        var redirect = await PostAsync(env.Bridge, AuthnRequest(requestedClass: SamlNames.AcMobileTwoFactor));
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(SamlNames.StatusNoAuthnContext, StatusCodeOf(document));
    }

    // Attack: an AuthnRequest form far larger than any real one. It's refused by size, before it's parsed.
    [Fact]
    public async Task OversizedSsoFormIsRefusedBeforeItIsParsed()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var oversized = new string('a', BridgeOptions.MaxSsoRequestBytes + 1024);

        using var response = await env.Bridge.PostAsync("/saml/sso", new FormUrlEncodedContent([new KeyValuePair<string, string>("SAMLRequest", oversized)]), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // An app can map any valid claim name, and its ID token value is sent as the attribute.
    [Fact]
    public async Task AnArbitraryMappedClaimFromTheIdTokenIsSentAsAnAttribute()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.ExtraIdTokenClaims["cost_center"] = "42");
        var configure = await BridgeEnvironment.ConfigureAppAsync("--attribute", "cc=cost_center");
        Assert.Equal(0, configure.ExitCode);

        using var response = await SamlRequests.LoginAsync(env, "_req-arbitrary");
        var (_, document, _) = await ReadAutoPostAsync(response);

        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));
        var namespaces = new XmlNamespaceManager(document.NameTable);
        namespaces.AddNamespace("saml", SamlNames.AssertionNs);
        Assert.Equal("42", document.SelectSingleNode("//saml:Attribute[@Name='cc']/saml:AttributeValue", namespaces)?.InnerText);
    }

    // Attack: a replayed AuthnRequest is refused.
    [Fact]
    public async Task ReplayedAuthnRequestGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var xml = AuthnRequest("_req-replay");

        using var first = await PostAsync(env.Bridge, xml);
        using var replay = await PostAsync(env.Bridge, xml);

        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await replay.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack: after a login has completed, the same AuthnRequest is refused, so no second login starts from it.
    [Fact]
    public async Task ReplayOfACompletedAuthnRequestGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var xml = AuthnRequest("_req-completed-replay");
        var redirect = await PostAsync(env.Bridge, xml);
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));
        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));

        using var replay = await PostAsync(env.Bridge, xml);

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Null(replay.Headers.Location);
        Assert.DoesNotContain("SAMLResponse", await replay.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Success: the silent retry completes, and the AuthnRequest ID is still refused afterwards.
    [Fact]
    public async Task SilentRetryCompletesAndTheAuthnRequestStaysBlocked()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.SignedIn = false);
        var xml = AuthnRequest("_req-silent-then-replay");

        var redirect = await PostAsync(env.Bridge, xml);
        using var stub = StubClient(env);
        using var failure = await stub.GetAsync(redirect.Headers.Location, TestContext.Current.CancellationToken);
        var retry = await env.Bridge.GetAsync(new Uri(failure.Headers.Location!.ToString()).PathAndQuery, TestContext.Current.CancellationToken);
        var callback = await SignInAtOidcProviderAsync(env, retry);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));
        Assert.Equal(SamlNames.StatusSuccess, StatusCodeOf(document));

        using var replay = await PostAsync(env.Bridge, xml);

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await replay.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack: an unknown issuer gets nothing that could carry a response.
    [Fact]
    public async Task UnknownIssuerGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await PostAsync(env.Bridge, AuthnRequest(issuer: "https://evil.example.test"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Attack: an ACS that isn't registered gets no SAML response, and the bridge never posts to it.
    [Fact]
    public async Task UnregisteredAcsGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await PostAsync(env.Bridge, AuthnRequest(acs: "https://attacker.example.test/collect"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("attacker.example.test", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisabledAppGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--disable");

        using var response = await PostAsync(env.Bridge, AuthnRequest());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // Attack: an unsigned request for an app whose metadata requires signed requests. The ACS is validated,
    // so the refusal goes to it as a SAML error.
    [Fact]
    public async Task UnsignedRequestFromAnAppThatMustSignGetsASamlError()
    {
        await using var env = await BridgeEnvironment.CreateAsync(registerApp: false);
        await env.RegisterSigningAppAsync();

        var redirect = await PostAsync(env.Bridge, AuthnRequest(issuer: BridgeEnvironment.SigningAppEntityId, acs: BridgeEnvironment.SigningAppAcs));
        var (acs, document, _) = await ReadAutoPostAsync(redirect);

        Assert.Equal(BridgeEnvironment.SigningAppAcs, acs);
        Assert.Equal(SamlNames.StatusRequester, StatusCodeOf(document));
    }

    // Attack: a signed POST request with no Destination. SAML Bindings require Destination on a signed request, so the
    // ACS gets a Requester error and no login starts.
    [Fact]
    public async Task SignedPostRequestWithoutDestinationGetsARequesterErrorAndNoLogin()
    {
        await using var env = await BridgeEnvironment.CreateAsync(registerApp: false);
        using var certificate = await env.RegisterSigningAppAsync();
        var unsigned = AuthnRequest("_req-signed-no-destination", issuer: BridgeEnvironment.SigningAppEntityId, acs: BridgeEnvironment.SigningAppAcs)
            .Replace($"Destination=\"{BridgeEnvironment.PublicUrl}/saml/sso\" ", string.Empty, StringComparison.Ordinal);
        var xml = SamlRequests.SignXml(unsigned, certificate);

        using var response = await PostAsync(env.Bridge, xml);
        var (acs, document, _) = await ReadAutoPostAsync(response);

        Assert.Equal(BridgeEnvironment.SigningAppAcs, acs);
        Assert.Equal(SamlNames.StatusRequester, StatusCodeOf(document));
        Assert.Empty(env.Stub.AuthorizeRequests);
    }

    [Fact]
    public async Task CallbackWithoutThePendingCookieGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await env.Bridge.GetAsync("/saml/callback?code=x&state=y&iss=z", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // Attack: a callback can be used once. The second use finds the pending login gone.
    [Fact]
    public async Task CallbackCannotBeReplayed()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        using var first = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        using var replay = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    // Attack: a changed state (login CSRF or mix-up) is refused with the local page, not a SAML response.
    [Fact]
    public async Task CallbackWithWrongStateGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var tampered = Regex.Replace(callback, "state=[^&]+", "state=wrong");

        using var response = await env.Bridge.GetAsync(tampered, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // RFC 9207 §2.4: a response without iss is refused, even one that carries an error.
    [Fact]
    public async Task CallbackWithoutIssuerGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var withoutIss = Regex.Replace(callback, "&iss=[^&]+", string.Empty);

        using var response = await env.Bridge.GetAsync(withoutIss, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // RFC 9207 §2.4: a provider that omits iss from its authorization response is refused at the callback.
    // The refusal is the local page even for an SP-initiated login (OidcCallbackRejectedException), so no SAML error is sent.
    [Fact]
    public async Task ProviderThatOmitsIssuerGetsTheLocalErrorPageNotASamlResponse()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.OmitIssuer = true);
        var redirect = await PostAsync(env.Bridge, AuthnRequest("_req-no-iss-from-provider"));
        var callback = await SignInAtOidcProviderAsync(env, redirect);

        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // RFC 9207 §2.4: a provider whose iss is another issuer is refused at the callback, with the same local page
    // as a missing iss. The code reads a wrong iss as "not this login's response" and never builds a SAML error for it.
    [Fact]
    public async Task ProviderWithAWrongIssuerGetsTheLocalErrorPageNotASamlResponse()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.ResponseIssuer = "https://other-issuer.example.test");
        var redirect = await PostAsync(env.Bridge, AuthnRequest("_req-wrong-iss-from-provider"));
        var callback = await SignInAtOidcProviderAsync(env, redirect);

        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // A required claim the user doesn't have refuses the login.
    [Fact]
    public async Task MissingRequiredClaimGetsAuthnFailedWithoutAnAssertion()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.OmitEmail = true);
        await BridgeEnvironment.ConfigureAppAsync("--attribute", "mail=email,required");

        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(SamlNames.StatusAuthnFailed, StatusCodeOf(document));
        Assert.Empty(document.DocumentElement!.GetElementsByTagName("Assertion", SamlNames.AssertionNs));
    }

    // AuthnInstant comes from auth_time, so a login without it is refused.
    [Fact]
    public async Task MissingAuthTimeGetsAuthnFailed()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.OmitAuthTime = true);

        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (_, document, _) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(SamlNames.StatusAuthnFailed, StatusCodeOf(document));
    }

    [Fact]
    public async Task MetadataPublishesTheBridgeAsAnIdentityProvider()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await env.Bridge.GetAsync("/saml/metadata", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/samlmetadata+xml", response.Content.Headers.ContentType!.MediaType);
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        var document = SafeXml.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(BridgeEnvironment.PublicUrl + "/saml/metadata", document.DocumentElement!.GetAttribute("entityID"));
    }

    // A page that carries a SAML response allows only the auto-submit script (by hash), posts only to
    // the exact ACS, and can't be framed.
    [Fact]
    public async Task AutoPostPageHasAStrictContentSecurityPolicy()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        var callback = await SignInAtOidcProviderAsync(env, redirect);

        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        var csp = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Contains($"form-action {Acs}", csp, StringComparison.Ordinal);
        Assert.Contains($"script-src '{ValkyrieSamlBridge.Web.Sso.Pages.AutoSubmitScriptHash}'", csp, StringComparison.Ordinal);
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    // Regression: the error parameter used to be read before iss and state were checked. An error
    // response with a wrong state must be refused with the local page, not turned into a SAML error.
    [Fact]
    public async Task ErrorResponseWithWrongStateIsRefusedWithoutASamlResponse()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.SignedIn = false);
        var redirect = await PostAsync(env.Bridge, AuthnRequest());
        using var stub = StubClient(env);
        using var failure = await stub.GetAsync(redirect.Headers.Location, TestContext.Current.CancellationToken);
        var tampered = Regex.Replace(failure.Headers.Location!.ToString(), "state=[^&]+", "state=wrong");

        using var response = await env.Bridge.GetAsync(new Uri(tampered).PathAndQuery, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EachLoginGetsANewAssertionId()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        var first = await LoginAsync(env);
        var second = await LoginAsync(env);

        var firstId = first.GetElementsByTagName("Assertion", SamlNames.AssertionNs)[0]!.Attributes!["ID"]!.Value;
        var secondId = second.GetElementsByTagName("Assertion", SamlNames.AssertionNs)[0]!.Attributes!["ID"]!.Value;
        Assert.NotEqual(firstId, secondId);
    }

    // A disabled app refuses its requests like an unknown app. The SP gets nothing to act on.
    [Fact]
    public async Task SpInitiatedDisabledAppGetsTheLocalErrorPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await BridgeEnvironment.ConfigureAppAsync("--disable");

        using var response = await PostAsync(env.Bridge, AuthnRequest());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // A provider that doesn't advertise S256 stops the bridge at startup, so no login is ever started.
    [Fact]
    public async Task ProviderWithoutS256StopsTheBridgeAtStartup()
    {
        var error = await Assert.ThrowsAnyAsync<OidcException>(() => BridgeEnvironment.CreateAsync(configureStub: s => s.OmitS256 = true));

        Assert.Contains("S256", error.Message, StringComparison.Ordinal);
    }

    // A refusal after the callback's checks is a SAML error to the validated ACS, with InResponseTo.
    // The stub can't make only the callback's discovery fail, because discovery is cached, so the ID token's nonce is wrong.
    [Fact]
    public async Task CallbackRefusalGetsAuthnFailedToTheValidatedAcs()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.WrongNonce = true);

        var redirect = await PostAsync(env.Bridge, AuthnRequest("_req-refused-at-callback"));
        var callback = await SignInAtOidcProviderAsync(env, redirect);
        var (acs, document, relay) = await ReadAutoPostAsync(await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken));

        Assert.Equal(Acs, acs);
        Assert.Equal(SamlNames.StatusAuthnFailed, StatusCodeOf(document));
        Assert.Equal("_req-refused-at-callback", document.DocumentElement!.GetAttribute("InResponseTo"));
        Assert.Empty(document.DocumentElement.GetElementsByTagName("Assertion", SamlNames.AssertionNs));
        Assert.Null(relay);
    }

    // A provider that can't be reached stops the bridge at startup, because a bridge that can't check its provider must not serve.
    [Fact]
    public async Task UnreachableProviderStopsTheBridgeAtStartup()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        Environment.SetEnvironmentVariable(BridgeEnvironment.OidcIssuerVariable, "https://localhost:1");

        Assert.Throws<OidcUnreachableException>(() => env.RestartBridge());
    }
}


