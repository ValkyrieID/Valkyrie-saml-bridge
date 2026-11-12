using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Web.Cli;
using ValkyrieSamlBridge.Core.Metadata;
using ValkyrieSamlBridge.Data;

[assembly: Xunit.v3.ParallelizationAttribute(MaxThreads = 1)]

namespace ValkyrieSamlBridge.Integration.Tests;

// Owns a temporary SQLite file and points the CLI at it through SAMLBRIDGE_DATABASE.
// Tests run serially because the environment variable is process-wide.
public sealed class TempDatabase : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"saml-bridge-test-{Guid.NewGuid():N}.db");

    public TempDatabase() => Environment.SetEnvironmentVariable(CliApp.DatabaseVariable, Path);

    public BridgeDbContext OpenDbContext() =>
        new(new DbContextOptionsBuilder<BridgeDbContext>().UseSqlite(new SqliteConnectionStringBuilder { DataSource = Path }.ToString()).Options);

    // A refused request can stop before the database file is created, so a missing file means no apps.
    public async Task<int> CountAppsAsync()
    {
        if (!File.Exists(Path))
        {
            return 0;
        }

        await using var db = OpenDbContext();
        return await db.Apps.CountAsync(TestContext.Current.CancellationToken);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(CliApp.DatabaseVariable, null);
        SqliteConnection.ClearAllPools();
        if (File.Exists(Path))
        {
            File.Delete(Path);
        }
    }
}

public sealed record CliResult(int ExitCode, string Output, string Error);

public static class Cli
{
    private static readonly SemaphoreSlim ConsoleLock = new(1, 1);

    // Captures console output so the CLI's messages can be asserted.
    public static async Task<CliResult> RunAsync(params string[] args)
    {
        await ConsoleLock.WaitAsync();
        var originalOut = Console.Out;
        var originalError = Console.Error;
        var output = new StringWriter();
        var error = new StringWriter();
        try
        {
            Console.SetOut(output);
            Console.SetError(error);
            var exitCode = await CliApp.RunAsync(args);
            return new CliResult(exitCode, output.ToString(), error.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
            ConsoleLock.Release();
        }
    }
}

public static class MetadataFiles
{
    public const string EntityId = "https://payroll.example.test/saml";

    public static (string Path, string Fingerprint) WriteValid(string directory, string fileName = "payroll.xml", string entityId = EntityId, string acs = "https://payroll.example.test/saml/acs")
    {
        var (der, fingerprint) = MakeCertificate();
        var xml = $"""
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{entityId}">
              <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{Convert.ToBase64String(der)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="1" isDefault="true"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>
            """;
        var path = System.IO.Path.Combine(directory, fileName);
        File.WriteAllText(path, xml);
        return (path, fingerprint);
    }

    public static string WriteWithDoctype(string directory)
    {
        var path = System.IO.Path.Combine(directory, "xxe.xml");
        File.WriteAllText(path, """
            <?xml version="1.0"?>
            <!DOCTYPE md:EntityDescriptor [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://x.example.test"/>
            """);
        return path;
    }

    private static (byte[] Der, string Fingerprint) MakeCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=payroll.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return (certificate.RawData, MetadataParser.Fingerprint(certificate.RawData));
    }
}
