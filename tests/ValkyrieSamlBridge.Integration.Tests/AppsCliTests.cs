using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Integration.Tests;

public sealed class AppsCliTests : IDisposable
{
    private readonly TempDatabase _database = new();
    private readonly string _directory = Directory.CreateTempSubdirectory("saml-bridge-tests").FullName;

    public void Dispose()
    {
        _database.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task AddThenConfirmWithTheExactFingerprintSucceeds()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);

        var add = await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        var confirm = await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);

        Assert.Equal(0, add.ExitCode);
        Assert.Contains(fingerprint, add.Output.Replace(":", string.Empty));
        Assert.Equal(0, confirm.ExitCode);
        var show = await Cli.RunAsync("apps", "show", "payroll");
        Assert.Contains("(confirmed", show.Output);
    }

    [Fact]
    public async Task ConfirmWithAWrongFingerprintConfirmsNothing()
    {
        // Attack: a typo or a substituted certificate. The confirmation must match exactly.
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var confirm = await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", new string('0', 64));

        Assert.Equal(1, confirm.ExitCode);
        var show = await Cli.RunAsync("apps", "show", "payroll");
        Assert.DoesNotContain("(confirmed", show.Output);
        Assert.Contains("not confirmed", show.Output);
    }

    [Fact]
    public async Task DuplicateSlugIsRefused()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        var (otherPath, _) = MetadataFiles.WriteValid(_directory, "other.xml", "https://other.example.test/saml");

        var result = await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", otherPath);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("already exists", result.Error);
    }

    [Fact]
    public async Task DuplicateEntityIdIsRefused()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var result = await Cli.RunAsync("apps", "add", "--slug", "payroll-copy", "--metadata", path);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("entity ID is already registered", result.Error);
    }

    [Theory]
    [InlineData("Payroll")]
    [InlineData("-payroll")]
    [InlineData("pay/roll")]
    public async Task InvalidSlugIsRefused(string slug)
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);

        var result = await Cli.RunAsync("apps", "add", "--slug", slug, "--metadata", path);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(0, await _database.CountAppsAsync());
    }

    [Theory]
    [InlineData("1st")]
    [InlineData("dept-code")]
    [InlineData("dept.code")]
    public async Task AnInvalidClaimNameIsRefusedAndNothingIsSaved(string claim)
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var result = await Cli.RunAsync("apps", "set", "payroll", "--attribute", $"mail={claim}");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("valid claim name", result.Error);
        await using var db = _database.OpenDbContext();
        Assert.Empty((await db.Apps.Include(a => a.Attributes).SingleAsync(TestContext.Current.CancellationToken)).Attributes);
    }

    [Fact]
    public async Task AnArbitraryValidClaimNameIsAcceptedAtAppsSet()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var result = await Cli.RunAsync("apps", "set", "payroll", "--attribute", "cc=cost_center");

        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task MetadataWithADoctypeIsRefusedAndNothingIsStored()
    {
        // Attack: XML external entity injection.
        var path = MetadataFiles.WriteWithDoctype(_directory);

        var result = await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(0, await _database.CountAppsAsync());
    }

    [Fact]
    public async Task ShowingAnUnknownAppFails()
    {
        var result = await Cli.RunAsync("apps", "show", "missing");

        Assert.Equal(1, result.ExitCode);
    }

    // An app is enabled only when a response can be built for it. A certificate the admin hasn't confirmed can't sign responses.
    [Fact]
    public async Task EnablingNeedsConfirmedCertificatesFirst()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "set", "payroll", "--nameid-claim", "sub", "--nameid-format", "persistent");

        var unconfirmed = await Cli.RunAsync("apps", "set", "payroll", "--enable");
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);
        var confirmed = await Cli.RunAsync("apps", "set", "payroll", "--enable");

        Assert.Equal(1, unconfirmed.ExitCode);
        Assert.Contains("confirmed", unconfirmed.Error);
        Assert.Equal(0, confirmed.ExitCode);
    }

    [Fact]
    public async Task EnablingNeedsNameIdFirst()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);

        var result = await Cli.RunAsync("apps", "set", "payroll", "--enable");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("nameid-claim", result.Error);
        var show = await Cli.RunAsync("apps", "show", "payroll");
        Assert.Contains("Enabled: False", show.Output);
    }

    // The metadata parser already refuses an app without an ACS, so this state is reached only by editing the database.
    [Fact]
    public async Task EnablingNeedsAnAcsEndpointFirst()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);
        await Cli.RunAsync("apps", "set", "payroll", "--nameid-claim", "sub", "--nameid-format", "persistent");
        await using (var db = _database.OpenDbContext())
        {
            await db.Set<SamlAppEndpoint>().ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        }

        var result = await Cli.RunAsync("apps", "set", "payroll", "--enable");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("AssertionConsumerService", result.Error);
        var show = await Cli.RunAsync("apps", "show", "payroll");
        Assert.Contains("Enabled: False", show.Output);
    }

    [Fact]
    public async Task EnablingAReadyAppIsAllowedAndDisablingIsAlwaysAllowed()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);
        await Cli.RunAsync("apps", "set", "payroll", "--nameid-claim", "sub", "--nameid-format", "persistent");

        var on = await Cli.RunAsync("apps", "set", "payroll", "--enable");
        var shownOn = await Cli.RunAsync("apps", "show", "payroll");
        var off = await Cli.RunAsync("apps", "set", "payroll", "--disable");
        var shownOff = await Cli.RunAsync("apps", "show", "payroll");

        Assert.Equal(0, on.ExitCode);
        Assert.Contains("Enabled: True", shownOn.Output);
        Assert.Equal(0, off.ExitCode);
        Assert.Contains("Enabled: False", shownOff.Output);
    }

    [Fact]
    public async Task DisablingAnEnabledAppThatIsNoLongerReadyIsAllowed()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);
        await Cli.RunAsync("apps", "set", "payroll", "--nameid-claim", "sub", "--nameid-format", "persistent", "--enable");
        await using (var db = _database.OpenDbContext())
        {
            await db.Set<SamlAppEndpoint>().ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        }

        var result = await Cli.RunAsync("apps", "set", "payroll", "--disable");

        Assert.Equal(0, result.ExitCode);
    }

    // Attack: two attributes that differ only in case would make the app's attribute list ambiguous.
    [Fact]
    public async Task AttributeNamesMustBeUniqueIgnoringCase()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var result = await Cli.RunAsync("apps", "set", "payroll", "--attribute", "mail=email", "--attribute", "MAIL=given_name");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("unique", result.Error);
        var show = await Cli.RunAsync("apps", "show", "payroll");
        Assert.Equal(0, show.ExitCode);
    }

    // Many attributes are accepted: the list has no fixed cap.
    [Fact]
    public async Task ManyAttributesAreAccepted()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        var attributes = Enumerable.Range(0, 40).SelectMany(i => new[] { "--attribute", $"a{i}=email" });

        var arguments = new List<string> { "apps", "set", "payroll" };
        arguments.AddRange(attributes);
        var result = await Cli.RunAsync(arguments.ToArray());

        Assert.Equal(0, result.ExitCode);
        await using var db = _database.OpenDbContext();
        Assert.Equal(40, (await db.Apps.Include(a => a.Attributes).SingleAsync(TestContext.Current.CancellationToken)).Attributes.Count);
    }

    // Attack: a repeated attribute name, in another case, is refused even among many attributes, and nothing is saved.
    [Fact]
    public async Task DuplicateAttributeNamesAreRefusedAmongManyAndNothingIsSaved()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        var attributes = Enumerable.Range(0, 40).SelectMany(i => new[] { "--attribute", $"a{i}=email" }).Append("--attribute").Append("A0=email");

        var arguments = new List<string> { "apps", "set", "payroll" };
        arguments.AddRange(attributes);
        var result = await Cli.RunAsync(arguments.ToArray());

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("unique", result.Error);
        await using var db = _database.OpenDbContext();
        Assert.Empty((await db.Apps.Include(a => a.Attributes).SingleAsync(TestContext.Current.CancellationToken)).Attributes);
    }

    // Regression: an unrelated change must not clear the attribute list or RelayState values.
    [Fact]
    public async Task ChangingOnlyTheEnabledFlagKeepsAttributesAndRelayStates()
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "confirm", "payroll", "--fingerprint", fingerprint);
        await Cli.RunAsync("apps", "set", "payroll", "--nameid-claim", "sub", "--nameid-format", "persistent", "--attribute", "mail=email", "--relay-state", "/dashboard");

        var result = await Cli.RunAsync("apps", "set", "payroll", "--enable");

        Assert.Equal(0, result.ExitCode);
        await using var db = _database.OpenDbContext();
        var app = await db.Apps.Include(a => a.Attributes).Include(a => a.RelayStates).SingleAsync(TestContext.Current.CancellationToken);
        Assert.Single(app.Attributes);
        Assert.Single(app.RelayStates);
    }

    [Fact]
    public async Task RolesMappingWithTheRolesScopeIsAccepted()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var result = await Cli.RunAsync("apps", "set", "payroll", "--attribute", "roles=roles", "--scope", "roles");

        Assert.Equal(0, result.ExitCode);
        var show = await Cli.RunAsync("apps", "show", "payroll");
        Assert.Contains("Scopes: roles", show.Output);
    }

    [Fact]
    public async Task DefaultScopesReturnsTheAppToTheDefaultList()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);
        await Cli.RunAsync("apps", "set", "payroll", "--scope", "roles");

        var reset = await Cli.RunAsync("apps", "set", "payroll", "--default-scopes");
        var show = await Cli.RunAsync("apps", "show", "payroll");

        Assert.Equal(0, reset.ExitCode);
        Assert.Contains("Scopes: default", show.Output);
    }

    [Fact]
    public async Task DefaultScopesCannotBeCombinedWithScope()
    {
        var (path, _) = MetadataFiles.WriteValid(_directory);
        await Cli.RunAsync("apps", "add", "--slug", "payroll", "--metadata", path);

        var result = await Cli.RunAsync("apps", "set", "payroll", "--default-scopes", "--scope", "roles");

        Assert.Equal(1, result.ExitCode);
    }
}
