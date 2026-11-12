using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Security;

namespace ValkyrieSamlBridge.Integration.Tests;

public sealed class BridgeFactory(string oidcThumbprint, FakeTimeProvider clock, Action<IServiceCollection>? configureServices) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.ConfigureTestServices(services =>
        {
            // Tests move this clock to check expiry and skew boundaries.
            services.AddSingleton<TimeProvider>(clock);
            configureServices?.Invoke(services);

            // The OIDC provider stub uses a self-signed certificate. Only the bridge's outgoing client trusts
            // it, and only by thumbprint.
            services.AddHttpClient("oidc").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate?.Thumbprint == oidcThumbprint,
            });
        });
    }
}

// One bridge, one OIDC provider stub, and (optionally) one registered app, each fresh for a test.
// Environment variables are process-wide, so the tests in this assembly run serially (TestHost.cs).
public sealed class BridgeEnvironment : IAsyncDisposable
{
    public const string PublicUrl = "https://sso.example.test";
    public const string AppSlug = "payroll";
    public const string OidcIssuerVariable = "SAMLBRIDGE_OIDC_ISSUER";

    private readonly TempDatabase _database;
    private readonly string _directory;
    private readonly Action<IServiceCollection>? _configureServices;
    private BridgeFactory _factory;

    private BridgeEnvironment(OidcProviderStub stub, TempDatabase database, string directory, BridgeFactory factory, HttpClient bridge, FakeTimeProvider clock, Action<IServiceCollection>? configureServices)
    {
        Stub = stub;
        _database = database;
        _directory = directory;
        _factory = factory;
        Bridge = bridge;
        Clock = clock;
        _configureServices = configureServices;
    }

    public OidcProviderStub Stub { get; }

    // Talks to the bridge at its public origin, so cookies marked Secure are sent back to it.
    public HttpClient Bridge { get; private set; }

    public FakeTimeProvider Clock { get; }

    public TempDatabase Database => _database;

    // Starts a new bridge host over the same database, as a process restart does. The new host loads the signing keys
    // again, so it signs with the active key in the database. The old host keeps running until it's disposed here.
    // A startup failure (for example, two active keys) is thrown from here.
    public void RestartBridge()
    {
        Bridge.Dispose();
        _factory.Dispose();
        _factory = new BridgeFactory(Stub.CertificateThumbprint, Clock, _configureServices);
        Bridge = CreateBridgeClient(_factory);
    }

    private static HttpClient CreateBridgeClient(BridgeFactory factory) => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = true,
        BaseAddress = new Uri(PublicUrl),
    });

    public static async Task<BridgeEnvironment> CreateAsync(bool registerApp = true, Action<OidcProviderStub>? configureStub = null, Action<IServiceCollection>? configureServices = null)
    {
        var stub = await OidcProviderStub.StartAsync();
        configureStub?.Invoke(stub);

        var database = new TempDatabase();
        var directory = Path.Combine(Path.GetTempPath(), "saml-bridge-sso-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, MasterKey.GenerateBase64());
        Environment.SetEnvironmentVariable("SAMLBRIDGE_PUBLIC_URL", PublicUrl);
        Environment.SetEnvironmentVariable(OidcIssuerVariable, stub.Issuer);
        Environment.SetEnvironmentVariable("SAMLBRIDGE_OIDC_CLIENT_ID", OidcProviderStub.ClientId);
        Environment.SetEnvironmentVariable("SAMLBRIDGE_OIDC_CLIENT_SECRET", OidcProviderStub.ClientSecret);

        if (registerApp)
        {
            await RegisterAppAsync(directory);
        }

        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        var factory = new BridgeFactory(stub.CertificateThumbprint, clock, configureServices);
        var bridge = CreateBridgeClient(factory);
        return new BridgeEnvironment(stub, database, directory, factory, bridge, clock, configureServices);
    }

    // Registers another app through the same CLI an admin uses. Its signing certificate is confirmed and its NameID is set.
    public async Task AddAppAsync(string slug, string entityId, string acs)
    {
        var (path, fingerprint) = MetadataFiles.WriteValid(_directory, slug + ".xml", entityId, acs);
        var add = await Cli.RunAsync("apps", "add", "--slug", slug, "--metadata", path);
        if (add.ExitCode != 0)
        {
            throw new InvalidOperationException("apps add failed: " + add.Error);
        }
        await Cli.RunAsync("apps", "confirm", slug, "--fingerprint", fingerprint);
        var set = await Cli.RunAsync("apps", "set", slug, "--nameid-claim", "sub", "--nameid-format", "persistent", "--enable");
        if (set.ExitCode != 0)
        {
            throw new InvalidOperationException("apps set failed: " + set.Error);
        }
    }

    // The app is registered through the same CLI an admin uses.
    private static async Task RegisterAppAsync(string directory)
    {
        var (metadataPath, fingerprint) = MetadataFiles.WriteValid(directory);
        var add = await Cli.RunAsync("apps", "add", "--slug", AppSlug, "--metadata", metadataPath);
        if (add.ExitCode != 0)
        {
            throw new InvalidOperationException("apps add failed: " + add.Error);
        }
        await Cli.RunAsync("apps", "confirm", AppSlug, "--fingerprint", fingerprint);
        var set = await Cli.RunAsync("apps", "set", AppSlug, "--nameid-claim", "sub", "--nameid-format", "persistent", "--enable");
        if (set.ExitCode != 0)
        {
            throw new InvalidOperationException("apps set failed: " + set.Error);
        }
    }

    // Lets a test change the app's settings through the CLI, then the bridge reads them on the next request.
    public static Task<CliResult> ConfigureAppAsync(params string[] arguments) =>
        Cli.RunAsync(new[] { "apps", "set", AppSlug }.Concat(arguments).ToArray());

    public const string SigningAppEntityId = "https://signed.example.test/saml";
    public const string SigningAppAcs = "https://signed.example.test/acs";

    // A second app whose metadata says AuthnRequestsSigned="true".
    public async Task<System.Security.Cryptography.X509Certificates.X509Certificate2> RegisterSigningAppAsync()
    {
        var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(
            CreateSelfSigned().Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx), null);
        var der = certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
        var xml = $"""
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{SigningAppEntityId}">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true">
                <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{Convert.ToBase64String(der)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SigningAppAcs}" index="1" isDefault="true"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>
            """;
        var path = Path.Combine(_directory, "signed.xml");
        await File.WriteAllTextAsync(path, xml);
        var fingerprint = ValkyrieSamlBridge.Core.Metadata.MetadataParser.Fingerprint(der);

        var add = await Cli.RunAsync("apps", "add", "--slug", "signed", "--metadata", path);
        if (add.ExitCode != 0)
        {
            throw new InvalidOperationException("apps add failed: " + add.Error);
        }
        await Cli.RunAsync("apps", "confirm", "signed", "--fingerprint", fingerprint);
        await Cli.RunAsync("apps", "set", "signed", "--nameid-claim", "sub", "--nameid-format", "persistent", "--enable");
        return certificate;
    }

    internal static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateSelfSigned()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=signed.example.test", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    public async ValueTask DisposeAsync()
    {
        Bridge.Dispose();
        _factory.Dispose();
        await Stub.DisposeAsync();
        _database.Dispose();
        Environment.SetEnvironmentVariable(OidcIssuerVariable, null);
        Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, null);
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}




