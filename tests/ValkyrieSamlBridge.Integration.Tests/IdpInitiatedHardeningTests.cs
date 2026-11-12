using System.Net;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Integration.Tests;

public sealed class IdpInitiatedHardeningTests
{
    private static async Task<HttpResponseMessage> CompleteIdpAsync(BridgeEnvironment env)
    {
        var redirect = await env.Bridge.GetAsync("/idp/" + BridgeEnvironment.AppSlug);
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, redirect);
        return await env.Bridge.GetAsync(callback);
    }

    // AuthnInstant comes from auth_time. An IdP-initiated login without it has no request to answer,
    // so the refusal is the local page and nothing is posted to the ACS.
    [Fact]
    public async Task IdpLoginWithoutAuthTimeGetsTheLocalPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.OmitAuthTime = true);

        using var response = await CompleteIdpAsync(env);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RefusedIdpLoginGetsTheLocalPage()
    {
        await using var env = await BridgeEnvironment.CreateAsync(configureStub: s => s.OmitAuthTime = true);

        using var response = await CompleteIdpAsync(env);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
