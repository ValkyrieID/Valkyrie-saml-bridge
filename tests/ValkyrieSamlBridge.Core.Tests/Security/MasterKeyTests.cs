using System.Security.Cryptography;
using ValkyrieSamlBridge.Core.Security;

namespace ValkyrieSamlBridge.Core.Tests.Security;

public sealed class MasterKeyTests
{
    [Fact]
    public void MissingKeyRefusesToStart()
    {
        Assert.Throws<InvalidOperationException>(() => MasterKey.FromBase64(null));
        Assert.Throws<InvalidOperationException>(() => MasterKey.FromBase64("   "));
    }

    [Fact]
    public void KeyThatIsNot32BytesIsRefused()
    {
        var shortKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        Assert.Throws<InvalidOperationException>(() => MasterKey.FromBase64(shortKey));
    }

    [Fact]
    public void KeyThatIsNotBase64IsRefused()
    {
        Assert.Throws<InvalidOperationException>(() => MasterKey.FromBase64("not base64!"));
    }

    [Fact]
    public void EncryptThenDecryptReturnsThePlaintext()
    {
        using var key = MasterKey.FromBase64(MasterKey.GenerateBase64());
        var plaintext = "signing key bytes"u8.ToArray();

        var sealedData = key.Encrypt(plaintext, "signing-key");

        Assert.Equal(plaintext, key.Decrypt(sealedData, "signing-key"));
    }

    [Fact]
    public void CiphertextForOnePurposeDoesNotDecryptForAnother()
    {
        using var key = MasterKey.FromBase64(MasterKey.GenerateBase64());
        var sealedData = key.Encrypt("secret"u8, "client-secret");

        Assert.Throws<AuthenticationTagMismatchException>(() => key.Decrypt(sealedData, "signing-key"));
    }

    [Fact]
    public void TamperedCiphertextIsRejected()
    {
        using var key = MasterKey.FromBase64(MasterKey.GenerateBase64());
        var sealedData = key.Encrypt("secret"u8, "signing-key");
        sealedData[^1] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() => key.Decrypt(sealedData, "signing-key"));
    }

    [Fact]
    public void EachEncryptionUsesAFreshNonce()
    {
        using var key = MasterKey.FromBase64(MasterKey.GenerateBase64());

        var first = key.Encrypt("same"u8, "signing-key");
        var second = key.Encrypt("same"u8, "signing-key");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void TruncatedDataIsRejected()
    {
        using var key = MasterKey.FromBase64(MasterKey.GenerateBase64());

        Assert.Throws<CryptographicException>(() => key.Decrypt(new byte[10], "signing-key"));
    }
}
