using Microsoft.AspNetCore.Mvc.Testing;
using ValkyrieSamlBridge.Core.Security;

namespace ValkyrieSamlBridge.Integration.Tests;

public sealed class BridgeWebFactory : WebApplicationFactory<Program>
{
    private readonly TempDatabase _database = new();

    public BridgeWebFactory()
    {
        Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, MasterKey.GenerateBase64());
        Environment.SetEnvironmentVariable("SAMLBRIDGE_PUBLIC_URL", "https://sso.example.test");
        Environment.SetEnvironmentVariable("SAMLBRIDGE_OIDC_ISSUER", "https://localhost:1");
        Environment.SetEnvironmentVariable("SAMLBRIDGE_OIDC_CLIENT_ID", "bridge-client");
        Environment.SetEnvironmentVariable("SAMLBRIDGE_OIDC_CLIENT_SECRET", "bridge-secret");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _database.Dispose();
        }
    }
}

public sealed class HealthEndpointTests
{
    [Fact]
    public async Task HealthzReturnsOk()
    {
        await using var env = await BridgeEnvironment.CreateAsync(registerApp: false);

        var response = await env.Bridge.GetAsync("/healthz", TestContext.Current.CancellationToken);

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("/healthz")]
    [InlineData("/does-not-exist")]
    public async Task EveryResponseHasTheCacheAndCorpHeaders(string path)
    {
        // Scan finding (ZAP 10049): 404 pages were cacheable. SAML responses and login redirects must not be cached either.
        await using var env = await BridgeEnvironment.CreateAsync(registerApp: false);

        var response = await env.Bridge.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.True(response.Headers.CacheControl?.NoStore);
        // Scan finding (ZAP 90004): the metadata document had no Cross-Origin-Resource-Policy header.
        Assert.Equal("same-origin", response.Headers.GetValues("Cross-Origin-Resource-Policy").Single());
    }

    [Fact]
    public void HostRefusesToStartWithoutTheMasterKey()
    {
        var original = Environment.GetEnvironmentVariable(MasterKey.EnvironmentVariable);
        Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, null);
        try
        {
            using var withoutKey = new BridgeWebFactory();
            Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, null);

            Assert.ThrowsAny<InvalidOperationException>(() => withoutKey.CreateClient());
        }
        finally
        {
            Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, original);
        }
    }
}
