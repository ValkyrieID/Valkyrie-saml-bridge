using ValkyrieSamlBridge.Core.Apps;

namespace ValkyrieSamlBridge.Core.Tests.Apps;

public sealed class AppRegistrationTests
{
    private static AppRegistration WithAcs(params AppAcsEndpoint[] endpoints) => new(
        Slug: "payroll",
        EntityId: "https://payroll.example.test/saml",
        Enabled: true,
        AuthnRequestsSigned: false,
        AcsEndpoints: endpoints,
        ConfirmedSigningCertificates: [],
        NameId: null,
        Attributes: [],
        RelayStates: []);

    // An unsolicited response goes to the endpoint marked default.
    [Fact]
    public void TheEndpointMarkedDefaultIsUsed()
    {
        var app = WithAcs(new AppAcsEndpoint("https://a.example.test/acs", 1, IsDefault: false), new AppAcsEndpoint("https://b.example.test/acs", 2, IsDefault: true));

        Assert.Equal("https://b.example.test/acs", app.DefaultAcs!.Location);
    }

    [Fact]
    public void WithoutADefaultTheLowestIndexIsUsed()
    {
        var app = WithAcs(new AppAcsEndpoint("https://b.example.test/acs", 5, IsDefault: false), new AppAcsEndpoint("https://a.example.test/acs", 2, IsDefault: false));

        Assert.Equal("https://a.example.test/acs", app.DefaultAcs!.Location);
    }

    // Attack surface: an app with no ACS has nowhere to send an unsolicited response, so there is no default.
    [Fact]
    public void AnAppWithNoEndpointHasNoDefault()
    {
        Assert.Null(WithAcs().DefaultAcs);
    }
}
