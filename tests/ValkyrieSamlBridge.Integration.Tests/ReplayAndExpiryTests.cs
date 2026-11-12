using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Integration.Tests;

// Expiry and time-window checks over HTTP. The clock is BridgeEnvironment.Clock.
public sealed class ReplayAndExpiryTests
{
    private static readonly BridgeOptions Options = BridgeOptions.Create(new Uri(BridgeEnvironment.PublicUrl));

    // The assertion is valid from the moment it's issued for two minutes.
    [Fact]
    public async Task AssertionValidityIsTwoMinutesFromIssue()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        using var response = await SamlRequests.LoginAsync(env, "_req-window");
        var (_, document, _) = await SpInitiatedSsoTests.ReadAutoPostAsync(response);

        var notBefore = DateTimeOffset.Parse(SamlRequests.AssertionAttribute(document, "Conditions", "NotBefore"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        var notOnOrAfter = DateTimeOffset.Parse(SamlRequests.AssertionAttribute(document, "Conditions", "NotOnOrAfter"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        Assert.Equal(TimeSpan.FromMinutes(2), notOnOrAfter - notBefore);
        Assert.Equal(env.Clock.GetUtcNow(), notBefore, TimeSpan.FromSeconds(1));
    }

    // A pending login older than its lifetime is refused, even though the code and state are valid.
    [Fact]
    public async Task PendingLoginPastItsLifetimeIsRefused()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var start = await SamlRequests.StartAsync(env, "_req-late");
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, start);

        env.Clock.Advance(Options.PendingLoginLifetime + TimeSpan.FromSeconds(1));
        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // An AuthnRequest older than the window gets a SAML error to its validated ACS.
    [Fact]
    public async Task AuthnRequestOlderThanTheWindowGetsASamlErrorToTheAcs()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var old = env.Clock.GetUtcNow() - BridgeOptions.AuthnRequestMaxAge - Options.ClockSkew - TimeSpan.FromSeconds(1);

        using var response = await SamlRequests.PostAsync(env.Bridge, SamlRequests.AuthnRequest("_req-old", old));
        var (acs, document, _) = await SpInitiatedSsoTests.ReadAutoPostAsync(response);

        Assert.Equal(SamlRequests.PayrollAcs, acs);
        Assert.Equal(SamlNames.StatusRequester, SpInitiatedSsoTests.StatusCodeOf(document));
    }

    // The window's edge is inclusive: a request exactly at the boundary is accepted.
    [Fact]
    public async Task AuthnRequestExactlyAtTheWindowEdgeIsAcceptedOverHttp()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var edge = env.Clock.GetUtcNow() - BridgeOptions.AuthnRequestMaxAge - Options.ClockSkew;

        using var response = await SamlRequests.PostAsync(env.Bridge, SamlRequests.AuthnRequest("_req-edge", edge));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    // An expired pending login is purged, whether or not it was consumed. A live one stays.
    [Fact]
    public async Task PurgeRemovesExpiredPendingLoginsAndKeepsLiveOnes()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var now = env.Clock.GetUtcNow();
        await using var db = env.Database.OpenDbContext();
        var store = new PendingLoginStore(db, env.Clock);
        Assert.True(await store.PutAsync(NewPendingLogin("expired", "_req-purge-expired", now - TimeSpan.FromSeconds(1)), TestContext.Current.CancellationToken));
        Assert.True(await store.PutAsync(NewPendingLogin("live", "_req-purge-live", now + Options.PendingLoginLifetime), TestContext.Current.CancellationToken));

        var purged = await store.PurgeExpiredAsync(TestContext.Current.CancellationToken);

        await using var check = env.Database.OpenDbContext();
        Assert.Equal(1, purged);
        Assert.Equal(["live"], await check.PendingLogins.Select(p => p.Id).ToArrayAsync(TestContext.Current.CancellationToken));
    }

    // Attack: a login past its expiry can't be taken, even though its row is still in the table, and a live one can.
    [Fact]
    public async Task ExpiredPendingLoginCannotBeTakenButALiveOneCan()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var now = env.Clock.GetUtcNow();
        await using var seed = env.Database.OpenDbContext();
        var store = new PendingLoginStore(seed, env.Clock);
        Assert.True(await store.PutAsync(NewPendingLogin("taken-late", "_req-take-late", now - TimeSpan.FromSeconds(1)), TestContext.Current.CancellationToken));
        Assert.True(await store.PutAsync(NewPendingLogin("taken-live", "_req-take-live", now + Options.PendingLoginLifetime), TestContext.Current.CancellationToken));

        await using var db = env.Database.OpenDbContext();
        var taker = new PendingLoginStore(db, env.Clock);

        Assert.Null(await taker.TakeAsync("taken-late", TestContext.Current.CancellationToken));
        Assert.NotNull(await taker.TakeAsync("taken-live", TestContext.Current.CancellationToken));
    }

    // Attack: a consumed login can't be taken again, and two concurrent takes produce one login.
    [Fact]
    public async Task ConsumedPendingLoginCannotBeTakenAgain()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var login = NewPendingLogin("race", "_req-take-race", env.Clock.GetUtcNow() + Options.PendingLoginLifetime);
        await using (var seed = env.Database.OpenDbContext())
        {
            Assert.True(await new PendingLoginStore(seed, env.Clock).PutAsync(login, TestContext.Current.CancellationToken));
        }

        await using var first = env.Database.OpenDbContext();
        await using var second = env.Database.OpenDbContext();
        var takes = await Task.WhenAll(
            new PendingLoginStore(first, env.Clock).TakeAsync(login.Id, TestContext.Current.CancellationToken),
            new PendingLoginStore(second, env.Clock).TakeAsync(login.Id, TestContext.Current.CancellationToken));
        await using var third = env.Database.OpenDbContext();
        var again = await new PendingLoginStore(third, env.Clock).TakeAsync(login.Id, TestContext.Current.CancellationToken);

        Assert.Equal(1, takes.Count(t => t is not null));
        Assert.Null(again);
    }

    private static PendingLogin NewPendingLogin(string id, string requestId, DateTimeOffset expiresAt) => new()
    {
        Id = id,
        AppEntityId = BridgeEnvironment.PublicUrl,
        AcsUrl = "https://payroll.example.test/saml/acs",
        RequestId = requestId,
        OidcState = "state-" + id,
        Nonce = "nonce-" + id,
        CodeVerifier = "verifier-" + id,
        CreatedAt = expiresAt - Options.PendingLoginLifetime,
        ExpiresAtUnixMs = expiresAt.ToUnixTimeMilliseconds(),
    };
}
