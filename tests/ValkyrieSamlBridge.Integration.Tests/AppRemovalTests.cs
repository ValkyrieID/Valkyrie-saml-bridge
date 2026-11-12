using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Integration.Tests;

public sealed class AppRemovalCliTests : IDisposable
{
    private readonly TempDatabase _database = new();
    private readonly string _directory = Directory.CreateTempSubdirectory("saml-bridge-tests").FullName;

    public void Dispose()
    {
        _database.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task DisableTurnsTheAppOff()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);
        await Cli.RunAsync("apps", "set", "payroll", "--nameid-claim", "sub", "--nameid-format", "persistent", "--enable");

        var disable = await Cli.RunAsync("apps", "disable", "payroll");
        await Cli.RunAsync("apps", "set", "payroll", "--enable");
        var setDisable = await Cli.RunAsync("apps", "set", "payroll", "--disable");

        Assert.Equal(0, disable.ExitCode);
        Assert.Equal(0, setDisable.ExitCode);
        var show = await Cli.RunAsync("apps", "show", "payroll");
        Assert.Contains("Enabled: False", show.Output);
    }

    [Fact]
    public async Task RemoveDeletesTheAppAndItsSettings()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "set", "payroll", "--attribute", "mail=email", "--relay-state", "/dashboard");

        var remove = await Cli.RunAsync("apps", "remove", "payroll");

        Assert.Equal(0, remove.ExitCode);
        Assert.Contains("Removed 'payroll'", remove.Output);
        Assert.Equal(0, await _database.CountAppsAsync());
        await using var db = _database.OpenDbContext();
        Assert.Equal(0, await db.Set<SamlAppEndpoint>().CountAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await db.Set<SamlAppCertificate>().CountAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await db.Set<SamlAppClaimMapping>().CountAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await db.Set<SamlAppRelayState>().CountAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DisableAndRemoveOfAnUnknownSlugFailWithoutChangingAnything()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var disable = await Cli.RunAsync("apps", "disable", "missing");
        var remove = await Cli.RunAsync("apps", "remove", "missing");

        Assert.Equal(1, disable.ExitCode);
        Assert.Equal(1, remove.ExitCode);
        Assert.Contains("No app with that slug", disable.Error);
        Assert.Contains("No app with that slug", remove.Error);
        Assert.Equal(1, await _database.CountAppsAsync());
    }

    // Attack: a slug that differs only by letter case or surrounding whitespace must not match the stored app.
    [Theory]
    [InlineData("PAYROLL")]
    [InlineData("Payroll")]
    [InlineData(" payroll")]
    [InlineData("payroll ")]
    [InlineData("payroll\t")]
    public async Task DisableAndRemoveDoNotMatchADifferentSpellingOfTheSlug(string slug)
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var disable = await Cli.RunAsync("apps", "disable", slug);
        var remove = await Cli.RunAsync("apps", "remove", slug);

        Assert.Equal(1, disable.ExitCode);
        Assert.Equal(1, remove.ExitCode);
        Assert.Equal(1, await _database.CountAppsAsync());
    }

    [Fact]
    public async Task RemovedSlugAndEntityIdCanBeAddedAgain()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);
        var remove = await Cli.RunAsync("apps", "remove", "payroll");

        var add = await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        var confirm = await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);

        Assert.Equal(0, remove.ExitCode);
        Assert.Equal(0, add.ExitCode);
        Assert.Equal(0, confirm.ExitCode);
        Assert.Equal(1, await _database.CountAppsAsync());
    }
}

public sealed class AppRemovalSsoTests
{
    // Attack: an SP login started before the removal. The callback must be refused, and its pending row is gone.
    [Fact]
    public async Task CallbackForALoginStartedBeforeTheAppWasRemovedIsRefused()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var start = await SamlRequests.StartAsync(env, "_pending-before-remove");
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, start);
        await using (var before = env.Database.OpenDbContext())
        {
            Assert.Equal(1, await before.PendingLogins.CountAsync(TestContext.Current.CancellationToken));
        }

        var remove = await Cli.RunAsync("apps", "remove", BridgeEnvironment.AppSlug);

        Assert.Equal(0, remove.ExitCode);
        await using (var after = env.Database.OpenDbContext())
        {
            Assert.Equal(0, await after.PendingLogins.CountAsync(p => p.AppEntityId == SamlRequests.PayrollEntity, TestContext.Current.CancellationToken));
        }
        using var response = await env.Bridge.GetAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("SAMLResponse", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    // Success: the app logs in again after it is removed and re-added.
    [Fact]
    public async Task FreshAssertionIdIsAcceptedAfterTheAppIsReAdded()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        using var first = await SamlRequests.LoginAsync(env, "_req-one");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var remove = await Cli.RunAsync("apps", "remove", BridgeEnvironment.AppSlug);
        await env.AddAppAsync(BridgeEnvironment.AppSlug, SamlRequests.PayrollEntity, SamlRequests.PayrollAcs);
        using var second = await SamlRequests.LoginAsync(env, "_req-two");

        Assert.Equal(0, remove.ExitCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }
}
