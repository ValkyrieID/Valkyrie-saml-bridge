using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Core.Tests.Saml;

// Shared helpers for SAML tests: a fixed clock, a key pair, and small builders for AuthnRequests.
public sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

public static class SamlTestData
{
    public static readonly DateTimeOffset Now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
    public const string AppEntityId = "https://payroll.example.test/saml";
    public const string AcsLocation = "https://payroll.example.test/saml/acs";
    public const string OtherAcsLocation = "https://payroll.example.test/saml/other";
    public const string PublicUrl = "https://sso.example.test";

    public static readonly BridgeOptions Options = BridgeOptions.Create(new Uri(PublicUrl));

    public static X509Certificate2 CreateCertificate(string name = "bridge")
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }

    public static string AuthnRequestXml(
        string id = "_req-1",
        DateTimeOffset? issueInstant = null,
        string issuer = AppEntityId,
        string? destination = null,
        string? acs = AcsLocation,
        string? binding = SamlNames.HttpPost,
        string? extra = null)
    {
        var issued = (issueInstant ?? Now).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture);
        var attributes = $"ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{issued}\" "
            + (destination is null ? string.Empty : $"Destination=\"{destination}\" ")
            + (acs is null ? string.Empty : $"AssertionConsumerServiceURL=\"{acs}\" ")
            + (binding is null ? string.Empty : $"ProtocolBinding=\"{binding}\" ");
        return $"""
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" {attributes}>
              <saml:Issuer>{issuer}</saml:Issuer>
              {extra}
            </samlp:AuthnRequest>
            """;
    }

    public static AppRegistration Registration(
        X509Certificate2? certificate = null,
        bool enabled = true,
        bool signatureRequired = false,
        IEnumerable<string>? relayStates = null,
        IEnumerable<AttributeSetting>? attributes = null,
        NameIdSetting? nameId = null,
        string? requestedScopes = null) => new(
            Slug: "payroll",
            EntityId: AppEntityId,
            Enabled: enabled,
            AuthnRequestsSigned: signatureRequired,
            AcsEndpoints:
            [
                new AppAcsEndpoint(AcsLocation, 1, IsDefault: true),
                new AppAcsEndpoint(OtherAcsLocation, 2, IsDefault: false),
            ],
            ConfirmedSigningCertificates: certificate is null ? [] : [certificate.Export(X509ContentType.Cert)],
            NameId: nameId ?? new NameIdSetting("sub", SamlNames.NameIdPersistent),
            Attributes: attributes?.ToList() ?? [],
            RelayStates: relayStates?.ToList() ?? [],
            RequestedScopes: requestedScopes);

    public static XmlDocument Parse(string xml) => SafeXml.Parse(xml);

    // Signs the root element with an enveloped signature, placed after Issuer, as a test-side signer.
    public static void SignRoot(XmlDocument document, X509Certificate2 certificate, string signatureMethod = AlgorithmPolicy.RsaSha256, string digestMethod = AlgorithmPolicy.Sha256Digest)
    {
        var root = document.DocumentElement!;
        var signature = new SamlSignedXml(document) { SigningKey = certificate.GetRSAPrivateKey() };
        signature.SignedInfo!.CanonicalizationMethod = AlgorithmPolicy.ExcC14N;
        signature.SignedInfo.SignatureMethod = signatureMethod;
        var reference = new Reference("#" + root.GetAttribute("ID")) { DigestMethod = digestMethod };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signature.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signature.KeyInfo = keyInfo;
        signature.ComputeSignature();

        var issuer = root.GetElementsByTagName("Issuer", SamlNames.AssertionNs)[0]!;
        root.InsertAfter(document.ImportNode(signature.GetXml(), true), issuer);
    }
}




