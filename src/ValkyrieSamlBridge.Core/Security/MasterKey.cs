using System.Security.Cryptography;
using System.Text;

namespace ValkyrieSamlBridge.Core.Security;

// Encrypts secrets at rest (signing key, OIDC client secret) with AES-256-GCM.
// The context label is bound as associated data, so a ciphertext for one purpose can't be
// decrypted as another. Output layout: nonce (12) | tag (16) | ciphertext.
public sealed class MasterKey : IDisposable
{
    public const string EnvironmentVariable = "SAMLBRIDGE_MASTER_KEY";

    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;

    private MasterKey(byte[] key) => _key = key;

    public static MasterKey FromBase64(string? base64)
    {
        if (string.IsNullOrWhiteSpace(base64))
        {
            throw new InvalidOperationException($"{EnvironmentVariable} is not set. The bridge refuses to start without a master key.");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64.Trim());
        }
        catch (FormatException)
        {
            throw new InvalidOperationException($"{EnvironmentVariable} must be base64.");
        }

        if (key.Length != KeySize)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidOperationException($"{EnvironmentVariable} must decode to exactly {KeySize} bytes.");
        }

        return new MasterKey(key);
    }

    public static MasterKey FromEnvironment() => FromBase64(Environment.GetEnvironmentVariable(EnvironmentVariable));

    public static string GenerateBase64() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeySize));

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, string context)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(context));

        var output = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(output, 0);
        tag.CopyTo(output, NonceSize);
        ciphertext.CopyTo(output, NonceSize + TagSize);
        return output;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> sealedData, string context)
    {
        if (sealedData.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Sealed data is too short.");
        }

        var nonce = sealedData[..NonceSize];
        var tag = sealedData[NonceSize..(NonceSize + TagSize)];
        var ciphertext = sealedData[(NonceSize + TagSize)..];
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(context));
        return plaintext;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
