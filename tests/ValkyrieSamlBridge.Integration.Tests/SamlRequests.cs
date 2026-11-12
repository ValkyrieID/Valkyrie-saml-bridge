using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Integration.Tests;

// Builds AuthnRequests and posts them the way an SP does (HTTP-POST binding).
internal static class SamlRequests
{
    public const string PayrollEntity = "https://payroll.example.test/saml";
    public const string PayrollAcs = "https://payroll.example.test/saml/acs";
    public const string CrmEntity = "https://crm.example.test/saml";
    public const string CrmAcs = "https://crm.example.test/saml/acs";

    public static string AuthnRequest(string id, DateTimeOffset issued, string issuer = PayrollEntity, string acs = PayrollAcs) =>
        $"""
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture)}" Destination="{BridgeEnvironment.PublicUrl}/saml/sso" AssertionConsumerServiceURL="{acs}" ProtocolBinding="{SamlNames.HttpPost}">
          <saml:Issuer>{issuer}</saml:Issuer>
        </samlp:AuthnRequest>
        """;

    public static Task<HttpResponseMessage> PostAsync(HttpClient bridge, string xml) =>
        bridge.PostAsync("/saml/sso", new FormUrlEncodedContent([new KeyValuePair<string, string>("SAMLRequest", Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)))]));

    // Sends an AuthnRequest issued now by the test clock.
    public static Task<HttpResponseMessage> StartAsync(BridgeEnvironment env, string id, string issuer = PayrollEntity, string acs = PayrollAcs) =>
        PostAsync(env.Bridge, AuthnRequest(id, env.Clock.GetUtcNow(), issuer, acs));

    // Follows the bridge redirect to the OIDC provider, signs in, and returns the callback's response.
    public static async Task<HttpResponseMessage> CompleteAsync(BridgeEnvironment env, HttpResponseMessage start)
    {
        var callback = await SpInitiatedSsoTests.SignInAtOidcProviderAsync(env, start);
        return await env.Bridge.GetAsync(callback);
    }

    public static async Task<HttpResponseMessage> LoginAsync(BridgeEnvironment env, string id, string issuer = PayrollEntity, string acs = PayrollAcs) =>
        await CompleteAsync(env, await StartAsync(env, id, issuer, acs));

    public static string AssertionAttribute(XmlDocument response, string element, string attribute) =>
        ((XmlElement)response.DocumentElement!.GetElementsByTagName(element, SamlNames.AssertionNs)[0]!).GetAttribute(attribute);

    // Signs the root with an enveloped RSA-SHA256 signature after Issuer, as an SP does for an XML-signed AuthnRequest.
    public static string SignXml(string xml, X509Certificate2 certificate)
    {
        var document = SafeXml.Parse(xml);
        var root = document.DocumentElement!;
        var signature = new SamlSignedXml(document) { SigningKey = certificate.GetRSAPrivateKey() };
        signature.SignedInfo!.CanonicalizationMethod = AlgorithmPolicy.ExcC14N;
        signature.SignedInfo.SignatureMethod = AlgorithmPolicy.RsaSha256;
        var reference = new Reference("#" + root.GetAttribute("ID")) { DigestMethod = AlgorithmPolicy.Sha256Digest };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signature.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signature.KeyInfo = keyInfo;
        signature.ComputeSignature();

        var issuer = root.GetElementsByTagName("Issuer", SamlNames.AssertionNs)[0]!;
        root.InsertAfter(document.ImportNode(signature.GetXml(), true), issuer);
        return document.OuterXml;
    }
}
