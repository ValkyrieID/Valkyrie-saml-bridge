using System.Diagnostics;
using System.Text.Json;
using ValkyrieSamlBridge.Core.OpenIdConnect;
using ValkyrieSamlBridge.Core.Security;

namespace ValkyrieSamlBridge.Integration.Tests;

// The web host validates the OIDC issuer and public URL settings when it starts. An invalid setting
// must stop the host before it serves a request. Settings come from environment variables only, so these tests run the
// real host as a process. WebApplicationFactory can't prove this, because its configuration callbacks don't reach the host's builder.
public sealed class StartupConfigurationTests
{
    private const string ZeroKeyValue = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    public static TheoryData<string, string, string> RequiredSettings => new()
    {
        { "SAMLBRIDGE_PUBLIC_URL", "https://sso.example.test", "SAMLBRIDGE_PUBLIC_URL must be set" },
        { "SAMLBRIDGE_OIDC_ISSUER", "https://valkyrie.example.test", "SAMLBRIDGE_OIDC_ISSUER must be set" },
        { "SAMLBRIDGE_OIDC_CLIENT_ID", "bridge-client", "The OIDC client id and secret must be set." },
        { "SAMLBRIDGE_OIDC_CLIENT_SECRET", OidcProviderStub.ClientSecret, "The OIDC client id and secret must be set." },
        { MasterKey.EnvironmentVariable, ZeroKeyValue, "SAMLBRIDGE_MASTER_KEY is not set." },
    };

    [Theory]
    [MemberData(nameof(RequiredSettings))]
    public async Task ValueOnlyInAppSettingsDoesNotStartTheHost(string variable, string value, string expected)
    {
        // Attack: a copy in appsettings.json in the working directory must not be read. The variable is unset, so the host must refuse.
        using var directory = new WorkDirectory();
        await File.WriteAllTextAsync(Path.Combine(directory.Path, "appsettings.json"), JsonSerializer.Serialize(new Dictionary<string, string> { [variable] = value }), TestContext.Current.CancellationToken);
        var environment = ValidEnvironment(directory.Path);
        environment[variable] = null;

        var run = await RunHostAsync(directory.Path, environment);

        Assert.NotNull(run.ExitCode);
        Assert.NotEqual(0, run.ExitCode);
        Assert.Contains(expected, run.Output);
        AssertNoSecrets(run.Output, value, environment[MasterKey.EnvironmentVariable]);
    }

    [Theory]
    [MemberData(nameof(RequiredSettings))]
    public async Task ValueOnlyOnTheCommandLineDoesNotStartTheHost(string variable, string value, string expected)
    {
        // Attack: a --NAME=value argument must not be read. The variable is unset, so the host must refuse.
        using var directory = new WorkDirectory();
        var environment = ValidEnvironment(directory.Path);
        environment[variable] = null;

        var run = await RunHostAsync(directory.Path, environment, $"--{variable}={value}");

        Assert.NotNull(run.ExitCode);
        Assert.NotEqual(0, run.ExitCode);
        Assert.Contains(expected, run.Output);
        AssertNoSecrets(run.Output, value, environment[MasterKey.EnvironmentVariable]);
    }

    [Fact]
    public async Task EnvironmentSettingsAreReadAndTheProviderIsCheckedAtStartup()
    {
        // The host reads its settings from the environment. With the provider unreachable, it stops at the provider check,
        // and the message names the provider, not a missing setting.
        using var directory = new WorkDirectory();
        var environment = ValidEnvironment(directory.Path);

        var run = await RunHostAsync(directory.Path, environment);

        Assert.NotEqual(0, run.ExitCode);
        Assert.Contains("could not be reached", run.Output, StringComparison.Ordinal);
        AssertNoSecrets(run.Output, environment[MasterKey.EnvironmentVariable]);
    }

    [Theory]
    [InlineData("SAMLBRIDGE_OIDC_ISSUER", "http://localhost:1")]
    [InlineData("SAMLBRIDGE_OIDC_ISSUER", "")]
    [InlineData("SAMLBRIDGE_OIDC_CLIENT_ID", "")]
    [InlineData("SAMLBRIDGE_OIDC_CLIENT_SECRET", "")]
    [InlineData("SAMLBRIDGE_PUBLIC_URL", "http://sso.example.test")]
    public void InvalidOidcOrPublicUrlStopsTheHost(string variable, string value)
    {
        using var factory = new BridgeWebFactory();
        var original = Environment.GetEnvironmentVariable(variable);
        Environment.SetEnvironmentVariable(variable, value);
        try
        {
            Assert.Throws<InvalidOperationException>(() => factory.CreateClient());
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, original);
        }
    }

    // Attack: discovery names a different issuer. The host must refuse to start, not wait for the first login to fail.
    [Fact]
    public async Task ProviderWithAWrongDiscoveryIssuerStopsTheHost()
    {
        await Assert.ThrowsAnyAsync<OidcException>(() => BridgeEnvironment.CreateAsync(configureStub: s => s.DiscoveryIssuerOverride = "https://other-issuer.example.test"));
    }

    private static Dictionary<string, string?> ValidEnvironment(string directory) => new()
    {
        [MasterKey.EnvironmentVariable] = MasterKey.GenerateBase64(),
        ["SAMLBRIDGE_PUBLIC_URL"] = "https://sso.example.test",
        ["SAMLBRIDGE_OIDC_ISSUER"] = "https://valkyrie.example.test",
        ["SAMLBRIDGE_OIDC_CLIENT_ID"] = "bridge-client",
        ["SAMLBRIDGE_OIDC_CLIENT_SECRET"] = OidcProviderStub.ClientSecret,
        ["SAMLBRIDGE_DATABASE"] = Path.Combine(directory, "saml-bridge.db"),
        ["ASPNETCORE_URLS"] = null,
    };

    private static void AssertNoSecrets(string output, params string?[] values)
    {
        Assert.DoesNotContain(OidcProviderStub.ClientSecret, output);
        foreach (var value in values.Where(value => !string.IsNullOrEmpty(value)))
        {
            Assert.DoesNotContain(value!, output);
        }
    }

    private static async Task<HostRun> RunHostAsync(string workDirectory, Dictionary<string, string?> environment, params string[] arguments)
    {
        using var process = StartHost(workDirectory, environment, arguments);
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            // The host is still running, so it accepted the settings. The test fails on the null exit code.
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            return new HostRun(null, await stdout + await stderr);
        }
        return new HostRun(process.ExitCode, await stdout + await stderr);
    }

    private static Process StartHost(string workDirectory, Dictionary<string, string?> environment, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            WorkingDirectory = workDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        startInfo.ArgumentList.Add(typeof(Program).Assembly.Location);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        foreach (var (name, value) in environment)
        {
            if (value is null)
            {
                startInfo.Environment.Remove(name);
            }
            else
            {
                startInfo.Environment[name] = value;
            }
        }
        return Process.Start(startInfo) ?? throw new InvalidOperationException("The host process did not start.");
    }

    private sealed record HostRun(int? ExitCode, string Output);

    // A temporary working directory that is deleted when the test ends. The host creates no file in it in the negative tests.
    private sealed class WorkDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("saml-bridge-startup").FullName;

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
