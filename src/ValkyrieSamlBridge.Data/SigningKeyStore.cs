using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Core.Security;
using ValkyrieSamlBridge.Data.Entities;

namespace ValkyrieSamlBridge.Data;

public sealed class SigningKeyException(string message) : Exception(message);

// The keys the bridge loaded. Active signs. Published lists every stored certificate in DER, the active one first,
// then the inactive ones by CreatedAt. Only the active key's private key is decrypted.
public sealed record SigningKeySet(X509Certificate2 Active, IReadOnlyList<byte[]> Published);

// The key `keys rotate` created: its ID and its public certificate, which is what SPs need.
public sealed record RotatedSigningKey(string KeyId, byte[] CertificateDer);

// Loads, creates, rotates, and retires the bridge signing keys. The private key of each key
// is stored encrypted with the master key, under a context label that no other secret uses.
public sealed class SigningKeyStore(BridgeDbContext db, MasterKey masterKey, TimeProvider time)
{
    public const string Context = "signing-key";

    // Returns null when no key has ever been created. Throws when the stored keys don't have exactly one active key.
    public async Task<SigningKeySet?> FindAsync(CancellationToken cancellationToken)
    {
        var rows = await db.SigningKeys.AsNoTracking().OrderBy(k => k.Id).ToListAsync(cancellationToken);
        return rows.Count == 0 ? null : Resolve(rows);
    }

    public async Task<SigningKeySet> LoadOrCreateAsync(string commonName, CancellationToken cancellationToken)
    {
        var existing = await FindAsync(cancellationToken);
        if (existing is not null)
        {
            return existing;
        }

        var (privateKey, certificate) = SigningCertificate.Create(time, commonName);
        var row = new SigningKey
        {
            KeyId = NewKeyId(),
            CreatedAt = time.GetUtcNow(),
            Active = true,
            EncryptedPrivateKey = masterKey.Encrypt(privateKey, Context),
            CertificateDer = certificate,
        };
        db.SigningKeys.Add(row);
        await db.SaveChangesAsync(cancellationToken);

        return Load(row, [row]);
    }

    // `keys rotate`. Creates a new active key and makes the previous one inactive. The old row stays, so its
    // certificate is still published until `keys retire`. Refuses unless exactly one key is active (fail closed).
    // The running bridge keeps the key it loaded at startup; the new key signs after a restart.
    public async Task<RotatedSigningKey> RotateAsync(string commonName, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.SigningKeys.OrderBy(k => k.Id).ToListAsync(cancellationToken);
        var active = RequireSingleActive(rows, "rotate from");

        var (privateKey, certificate) = SigningCertificate.Create(time, commonName);
        active.Active = false;
        var row = new SigningKey
        {
            KeyId = NewKeyId(),
            CreatedAt = time.GetUtcNow(),
            Active = true,
            EncryptedPrivateKey = masterKey.Encrypt(privateKey, Context),
            CertificateDer = certificate,
        };
        db.SigningKeys.Add(row);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new RotatedSigningKey(row.KeyId, certificate);
    }

    // `keys retire`. Deletes every inactive key. The active key is never deleted, and the command refuses
    // when there is nothing inactive to delete, so a repeated retire changes nothing.
    public async Task<IReadOnlyList<string>> RetireInactiveAsync(CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var rows = await db.SigningKeys.OrderBy(k => k.Id).ToListAsync(cancellationToken);
        RequireSingleActive(rows, "retire with");

        var inactive = rows.Where(k => !k.Active).ToList();
        if (inactive.Count == 0)
        {
            throw new SigningKeyException("There is no inactive signing key to retire. Nothing was changed.");
        }

        db.SigningKeys.RemoveRange(inactive);
        var retired = inactive.Select(k => k.KeyId).ToList();
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return retired;
    }

    private static SigningKey RequireSingleActive(List<SigningKey> rows, string action)
    {
        var active = rows.Where(k => k.Active).ToList();
        if (active.Count == 1)
        {
            return active[0];
        }

        throw new SigningKeyException(active.Count == 0
            ? $"There is no active signing key to {action}. Nothing was changed."
            : $"There are {active.Count} active signing keys, but exactly one is required. Nothing was changed.");
    }

    // Startup needs exactly one active key. Anything else is refused, not repaired.
    private SigningKeySet Resolve(List<SigningKey> rows)
    {
        var active = rows.Where(k => k.Active).ToList();
        if (active.Count != 1)
        {
            throw new SigningKeyException(active.Count == 0
                ? "There is no active signing key, but keys are stored. The bridge refuses to start. Restore the active key or ask for help before creating a new one."
                : $"There are {active.Count} active signing keys, but exactly one is required. The bridge refuses to start.");
        }

        return Load(active[0], rows);
    }

    private SigningKeySet Load(SigningKey active, List<SigningKey> rows)
    {
        var published = new List<byte[]> { active.CertificateDer };
        published.AddRange(rows.Where(k => !k.Active).OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).Select(k => k.CertificateDer));
        var privateKeyBytes = masterKey.Decrypt(active.EncryptedPrivateKey, Context);
        return new SigningKeySet(SigningCertificate.Load(privateKeyBytes, active.CertificateDer), published);
    }

    private static string NewKeyId() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
}
