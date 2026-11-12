namespace ValkyrieSamlBridge.Core.Saml;

// Signature and digest allow-list (RSA-SHA256 only, no SHA-1, no ECDSA).
// Every signature the bridge verifies is checked here first.
public static class AlgorithmPolicy
{
    public const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public const string Sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256";
    public const string ExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public const string Enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    private static readonly HashSet<string> SignatureMethods = new(StringComparer.Ordinal) { RsaSha256 };
    private static readonly HashSet<string> DigestMethods = new(StringComparer.Ordinal) { Sha256Digest };

    public static bool IsAllowedSignatureMethod(string? algorithm) => algorithm is not null && SignatureMethods.Contains(algorithm);

    public static bool IsAllowedDigestMethod(string? algorithm) => algorithm is not null && DigestMethods.Contains(algorithm);
}
