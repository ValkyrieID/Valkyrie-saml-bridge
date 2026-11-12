using System.Net;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Integration.Tests;

// Several apps in one instance: each app's audience, recipient, flags, and scopes are its own.
public sealed class MultiAppTests
{
    // The first app is payroll (registered by BridgeEnvironment); this adds a second one.
    private static async Task<BridgeEnvironment> CreateWithTwoAppsAsync()
    {
        var env = await BridgeEnvironment.CreateAsync();
        await env.AddAppAsync("crm", SamlRequests.CrmEntity, SamlRequests.CrmAcs);
        return env;
    }

    [Fact]
    public async Task EachAppGetsAnAssertionForItsOwnAudienceAndRecipient()
    {
        await using var env = await CreateWithTwoAppsAsync();

        using var crm = await SamlRequests.LoginAsync(env, "_req-crm", SamlRequests.CrmEntity, SamlRequests.CrmAcs);
        var (crmAcs, crmDocument, _) = await SpInitiatedSsoTests.ReadAutoPostAsync(crm);
        using var payroll = await SamlRequests.LoginAsync(env, "_req-payroll");
        var (payrollAcs, payrollDocument, _) = await SpInitiatedSsoTests.ReadAutoPostAsync(payroll);

        Assert.Equal(SamlRequests.CrmAcs, crmAcs);
        Assert.Equal(SamlRequests.CrmEntity, crmDocument.GetElementsByTagName("Audience", SamlNames.AssertionNs)[0]!.InnerText);
        Assert.Equal(SamlRequests.CrmAcs, crmDocument.GetElementsByTagName("SubjectConfirmationData", SamlNames.AssertionNs)[0]!.Attributes!["Recipient"]!.Value);
        Assert.Equal(SamlRequests.PayrollAcs, payrollAcs);
        Assert.Equal(SamlRequests.PayrollEntity, payrollDocument.GetElementsByTagName("Audience", SamlNames.AssertionNs)[0]!.InnerText);
    }

    // Attack: a valid entity ID paired with another app's ACS. The ACS must belong to the requesting app, so nothing is sent.
    [Theory]
    [InlineData(SamlRequests.CrmEntity, SamlRequests.PayrollAcs)]
    [InlineData(SamlRequests.PayrollEntity, SamlRequests.CrmAcs)]
    public async Task AnAcsOfAnotherAppIsRefusedWithTheLocalPage(string issuer, string acs)
    {
        await using var env = await CreateWithTwoAppsAsync();

        using var response = await SamlRequests.StartAsync(env, "_req-cross", issuer, acs);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
        Assert.DoesNotContain("saml/acs", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Disabling one app stops only that app.
    [Fact]
    public async Task DisablingOneAppLeavesTheOtherWorking()
    {
        await using var env = await CreateWithTwoAppsAsync();
        await Cli.RunAsync("apps", "set", "crm", "--disable");

        using var crm = await SamlRequests.StartAsync(env, "_req-off", SamlRequests.CrmEntity, SamlRequests.CrmAcs);
        using var payroll = await SamlRequests.LoginAsync(env, "_req-on");
        var (_, document, _) = await SpInitiatedSsoTests.ReadAutoPostAsync(payroll);

        Assert.Equal(HttpStatusCode.BadRequest, crm.StatusCode);
        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
    }

    // Each app's SSO is switched on or off on its own, so a disabled app refuses the start URL and the other app still works.
    [Fact]
    public async Task IdpStartIsRefusedOnlyForTheDisabledApp()
    {
        await using var env = await CreateWithTwoAppsAsync();
        await BridgeEnvironment.ConfigureAppAsync("--disable");

        using var crm = await env.Bridge.GetAsync("/idp/crm", TestContext.Current.CancellationToken);
        using var payroll = await env.Bridge.GetAsync("/idp/payroll", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, crm.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, payroll.StatusCode);
    }

    // Each app asks the OIDC provider only for its own mapped scopes. Another app's mapping never widens a request.
    [Fact]
    public async Task EachAppRequestsOnlyItsOwnScopes()
    {
        await using var env = await CreateWithTwoAppsAsync();
        await Cli.RunAsync("apps", "set", "crm", "--attribute", "mail=email");

        await SamlRequests.LoginAsync(env, "_req-scope-crm", SamlRequests.CrmEntity, SamlRequests.CrmAcs);
        var crmScope = env.Stub.AuthorizeRequests[^1];
        await SamlRequests.LoginAsync(env, "_req-scope-payroll");
        var payrollScope = env.Stub.AuthorizeRequests[^1];

        Assert.Contains("scope=openid%20email&", crmScope, StringComparison.Ordinal);
        Assert.Contains("scope=openid&", payrollScope, StringComparison.Ordinal);
        Assert.DoesNotContain("email", payrollScope, StringComparison.Ordinal);
    }

    // An admin's configured scope list is what the bridge requests, for that app only.
    [Fact]
    public async Task AConfiguredScopeIsSentToOidcProviderForItsAppOnly()
    {
        await using var env = await CreateWithTwoAppsAsync();
        await Cli.RunAsync("apps", "set", "crm", "--attribute", "roles=roles", "--scope", "roles");

        await SamlRequests.LoginAsync(env, "_req-roles-crm", SamlRequests.CrmEntity, SamlRequests.CrmAcs);
        var crmScope = env.Stub.AuthorizeRequests[^1];
        await SamlRequests.LoginAsync(env, "_req-roles-payroll");
        var payrollScope = env.Stub.AuthorizeRequests[^1];

        Assert.Contains("scope=openid%20roles&", crmScope, StringComparison.Ordinal);
        Assert.Contains("scope=openid&", payrollScope, StringComparison.Ordinal);
    }
}
