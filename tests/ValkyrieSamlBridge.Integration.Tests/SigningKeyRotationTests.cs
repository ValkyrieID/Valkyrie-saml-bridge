using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Core.Security;
using ValkyrieSamlBridge.Data;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Integration.Tests;

// `keys rotate` and `keys retire`, and the metadata and signing that follow a restart. The running bridge
// keeps the key it loaded at startup, so each test that needs the new key restarts the bridge first.
public sealed class SigningKeyRotationTests
{
    [Fact]
    public async Task RotateKeepsTheOldKeyInactiveAndAddsAnActiveOne()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var before = (await ReadKeysAsync(env)).Single();

        var result = await Cli.RunAsync("keys", "rotate");

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        Assert.Contains("Restart the bridge now", result.Output);
        var rows = await ReadKeysAsync(env);
        Assert.Equal(2, rows.Count);
        var old = rows.Single(k => k.KeyId == before.KeyId);
        var created = rows.Single(k => k.KeyId != before.KeyId);
        Assert.False(old.Active);
        Assert.True(created.Active);
    }

    [Fact]
    public async Task AfterRestartMetadataPublishesTheNewCertificateFirstAndTheOldOneAfterIt()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var oldCertificate = (await PublishedAsync(env)).Single();
        Assert.Single(await PublishedAsync(env));

        await Cli.RunAsync("keys", "rotate");
        env.RestartBridge();

        var published = await PublishedAsync(env);
        var created = (await ReadKeysAsync(env)).Single(k => k.Active);
        Assert.Equal(2, published.Length);
        Assert.Equal(created.CertificateDer, published[0].RawData);
        Assert.Equal(oldCertificate.RawData, published[1].RawData);
    }

    [Fact]
    public async Task BeforeRestartTheRunningBridgeStillSignsWithTheOldKey()
    {
        // The restart requirement: rotate doesn't hot-reload, so the running bridge keeps the old key.
        await using var env = await BridgeEnvironment.CreateAsync();
        var oldCertificate = (await PublishedAsync(env)).Single();

        await Cli.RunAsync("keys", "rotate");
        var document = await SpInitiatedSsoTests.LoginAsync(env);

        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
        Assert.True(XmlSignatureVerifier.Verify(document, [oldCertificate]));
    }

    [Fact]
    public async Task AfterRestartAResponseIsSignedWithTheNewKeyAndTheOldCertificateDoesNotVerify()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var oldCertificate = (await PublishedAsync(env)).Single();

        await Cli.RunAsync("keys", "rotate");
        env.RestartBridge();
        var newCertificate = (await PublishedAsync(env))[0];
        var document = await SpInitiatedSsoTests.LoginAsync(env);

        Assert.Equal(SamlNames.StatusSuccess, SpInitiatedSsoTests.StatusCodeOf(document));
        Assert.True(XmlSignatureVerifier.Verify(document, [newCertificate]), "The response must verify against the new certificate.");
        Assert.False(XmlSignatureVerifier.Verify(document, [oldCertificate]), "The old certificate must not verify the new signature.");
    }

    [Fact]
    public async Task RetireDeletesOnlyTheInactiveKeyAndPublishesOneCertificateAfterRestart()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var old = (await ReadKeysAsync(env)).Single();
        await Cli.RunAsync("keys", "rotate");
        var created = (await ReadKeysAsync(env)).Single(k => k.Active);

        var result = await Cli.RunAsync("keys", "retire");
        env.RestartBridge();

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        Assert.Contains($"Retired 1 inactive signing key(s): {old.KeyId}.", result.Output);
        var rows = await ReadKeysAsync(env);
        var remaining = Assert.Single(rows);
        Assert.Equal(created.KeyId, remaining.KeyId);
        Assert.True(remaining.Active);
        var published = Assert.Single(await PublishedAsync(env));
        Assert.Equal(created.CertificateDer, published.RawData);
    }

    [Fact]
    public async Task RetireWithoutAnInactiveKeyIsRefusedAndChangesNothing()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        var before = await ReadKeysAsync(env);

        var result = await Cli.RunAsync("keys", "retire");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("There is no inactive signing key to retire. Nothing was changed.", result.Error);
        Assert.Equal(before.Select(k => k.KeyId), (await ReadKeysAsync(env)).Select(k => k.KeyId));
    }

    [Fact]
    public async Task RetireNeverDeletesTheActiveKey()
    {
        // Attack: retire with the active key as the only key, then retire again after a rotation has already been retired.
        await using var env = await BridgeEnvironment.CreateAsync();
        var only = (await ReadKeysAsync(env)).Single();

        var refused = await Cli.RunAsync("keys", "retire");

        Assert.Equal(1, refused.ExitCode);
        Assert.Equal(only.KeyId, (await ReadKeysAsync(env)).Single().KeyId);

        await Cli.RunAsync("keys", "rotate");
        var created = (await ReadKeysAsync(env)).Single(k => k.Active);
        Assert.Equal(0, (await Cli.RunAsync("keys", "retire")).ExitCode);

        var again = await Cli.RunAsync("keys", "retire");

        Assert.Equal(1, again.ExitCode);
        var remaining = Assert.Single(await ReadKeysAsync(env));
        Assert.Equal(created.KeyId, remaining.KeyId);
        Assert.True(remaining.Active);
    }

    [Fact]
    public async Task RotateWithoutAnActiveKeyIsRefusedAndCreatesNoRow()
    {
        // Attack: the only stored key is inactive. Rotation would have nothing to rotate from, so it's refused (fail closed).
        await using var env = await BridgeEnvironment.CreateAsync();
        await SetActiveAsync(env, active: false);

        var result = await Cli.RunAsync("keys", "rotate");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("There is no active signing key to rotate from. Nothing was changed.", result.Error);
        var rows = await ReadKeysAsync(env);
        Assert.Single(rows);
        Assert.False(rows[0].Active);
    }

    [Fact]
    public async Task RotateWithNoKeyRowsIsRefusedAndCreatesNoRow()
    {
        await using var env = await BridgeEnvironment.CreateAsync();
        await using (var db = env.Database.OpenDbContext())
        {
            db.SigningKeys.RemoveRange(await db.SigningKeys.ToListAsync(TestContext.Current.CancellationToken));
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var result = await Cli.RunAsync("keys", "rotate");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("There is no active signing key to rotate from.", result.Error);
        Assert.Empty(await ReadKeysAsync(env));
    }

    [Fact]
    public async Task KeysCommandsNeverCreateTheDatabase()
    {
        // The database is opened, not created, so a typo in the path can't leave an empty file behind.
        using var database = new TempDatabase();
        var masterKey = MasterKey.GenerateBase64();
        var originalKey = Environment.GetEnvironmentVariable(MasterKey.EnvironmentVariable);
        var originalUrl = Environment.GetEnvironmentVariable(BridgeSettings.PublicUrlVariable);
        Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, masterKey);
        Environment.SetEnvironmentVariable(BridgeSettings.PublicUrlVariable, BridgeEnvironment.PublicUrl);
        try
        {
            var rotate = await Cli.RunAsync("keys", "rotate");
            var retire = await Cli.RunAsync("keys", "retire");

            Assert.Equal(1, rotate.ExitCode);
            Assert.Contains("The database file does not exist.", rotate.Error);
            Assert.Equal(1, retire.ExitCode);
            Assert.False(File.Exists(database.Path));
        }
        finally
        {
            Environment.SetEnvironmentVariable(MasterKey.EnvironmentVariable, originalKey);
            Environment.SetEnvironmentVariable(BridgeSettings.PublicUrlVariable, originalUrl);
        }
    }

    [Fact]
    public async Task TwoActiveKeysStopTheBridgeFromStarting()
    {
        // Attack: two rows marked active. The bridge can't tell which key to sign with, so it refuses to start.
        await using var env = await BridgeEnvironment.CreateAsync();
        await AddActiveKeyAsync(env);

        var error = Assert.ThrowsAny<Exception>(() => env.RestartBridge());

        Assert.Contains("There are 2 active signing keys, but exactly one is required.", error.ToString());
    }

    [Fact]
    public async Task StoredKeysWithNoActiveKeyStopTheBridgeWithoutCreatingOne()
    {
        // Attack: the keys exist but none is active. The bridge must not quietly create a new key in that state.
        await using var env = await BridgeEnvironment.CreateAsync();
        await SetActiveAsync(env, active: false);

        var error = Assert.ThrowsAny<Exception>(() => env.RestartBridge());

        Assert.Contains("There is no active signing key, but keys are stored.", error.ToString());
        var rows = await ReadKeysAsync(env);
        Assert.Single(rows);
        Assert.False(rows[0].Active);
    }

    [Fact]
    public async Task KeyMaterialIsEncryptedAndNeverPrinted()
    {
        await using var env = await BridgeEnvironment.CreateAsync();

        var result = await Cli.RunAsync("keys", "rotate");

        var created = (await ReadKeysAsync(env)).Single(k => k.Active);
        using var masterKey = MasterKey.FromBase64(Environment.GetEnvironmentVariable(MasterKey.EnvironmentVariable));
        var pkcs8 = masterKey.Decrypt(created.EncryptedPrivateKey, SigningKeyStore.Context);
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8, out _);
        using var certificate = X509CertificateLoader.LoadCertificate(created.CertificateDer);
        Assert.Equal(certificate.GetRSAPublicKey()!.ExportSubjectPublicKeyInfo(), rsa.ExportSubjectPublicKeyInfo());

        Assert.Equal(-1, created.EncryptedPrivateKey.AsSpan().IndexOf(pkcs8));
        SqliteConnection.ClearAllPools();
        Assert.Equal(-1, (await File.ReadAllBytesAsync(env.Database.Path, TestContext.Current.CancellationToken)).AsSpan().IndexOf(pkcs8));
        var plaintext = Convert.ToBase64String(pkcs8);
        Assert.DoesNotContain(plaintext, result.Output);
        Assert.DoesNotContain(plaintext, result.Error);
    }

    private static async Task<List<SigningKey>> ReadKeysAsync(BridgeEnvironment env)
    {
        await using var db = env.Database.OpenDbContext();
        return await db.SigningKeys.AsNoTracking().OrderBy(k => k.Id).ToListAsync();
    }

    private static async Task SetActiveAsync(BridgeEnvironment env, bool active)
    {
        await using var db = env.Database.OpenDbContext();
        var key = await db.SigningKeys.SingleAsync();
        key.Active = active;
        await db.SaveChangesAsync();
    }

    // Inserts a second active key directly, the way a bad restore or a race between two admins could leave the table.
    private static async Task AddActiveKeyAsync(BridgeEnvironment env)
    {
        using var masterKey = MasterKey.FromBase64(Environment.GetEnvironmentVariable(MasterKey.EnvironmentVariable));
        var (privateKey, certificate) = SigningCertificate.Create(TimeProvider.System, "rogue.example.test");
        await using var db = env.Database.OpenDbContext();
        db.SigningKeys.Add(new SigningKey
        {
            KeyId = "rogue",
            CreatedAt = DateTimeOffset.UtcNow,
            Active = true,
            EncryptedPrivateKey = masterKey.Encrypt(privateKey, SigningKeyStore.Context),
            CertificateDer = certificate,
        });
        await db.SaveChangesAsync();
    }

    private static async Task<X509Certificate2[]> PublishedAsync(BridgeEnvironment env)
    {
        var metadata = SafeXml.Parse(await env.Bridge.GetStringAsync("/saml/metadata"));
        return metadata.GetElementsByTagName("X509Certificate", SamlNames.DsigNs).Cast<XmlNode>()
            .Select(node => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(node.InnerText)))
            .ToArray();
    }
}
