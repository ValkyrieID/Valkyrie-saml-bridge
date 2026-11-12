using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace ValkyrieSamlBridge.Core.Saml;

public sealed class SamlException(string message) : Exception(message);

// Strict XML parsing for SAML messages: no DTD, no external entities, and a size cap.
public static class SafeXml
{
    public const int MaxBytes = 256 * 1024;

    public static XmlDocument Parse(string xml, int maxBytes = MaxBytes)
    {
        if (xml.Length > maxBytes)
        {
            throw new SamlException("The SAML message is too large.");
        }

        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = maxBytes,
            });
            var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            document.Load(reader);
            return document;
        }
        catch (XmlException)
        {
            throw new SamlException("The SAML message is not well-formed XML, or it contains a DTD.");
        }
    }
}

// SignedXml resolves "#id" references through the Id attribute only. SAML uses ID (SAML Core §1.3.4),
// so this override resolves ID. Two elements with the same ID are ambiguous, and resolve to nothing.
public sealed class SamlSignedXml(XmlDocument document) : SignedXml(document)
{
    public override XmlElement? GetIdElement(XmlDocument? document, string idValue)
    {
        var root = document?.DocumentElement;
        if (root is null || string.IsNullOrEmpty(idValue))
        {
            return null;
        }

        var matches = new List<XmlElement>();
        if (root.GetAttribute("ID") == idValue)
        {
            matches.Add(root);
        }
        foreach (XmlElement element in root.GetElementsByTagName("*"))
        {
            if (element.GetAttribute("ID") == idValue)
            {
                matches.Add(element);
            }
        }
        return matches.Count == 1 ? matches[0] : null;
    }
}

// Verifies an enveloped XML signature on the root element. It guards against signature wrapping:
// The signature must be the only one in the document, a direct child of the root, reference the
// root's ID, and use allow-listed algorithms. The root is the element that gets used afterwards.
public static class XmlSignatureVerifier
{
    public static bool Verify(XmlDocument document, IEnumerable<X509Certificate2> certificates)
    {
        var root = document.DocumentElement;
        if (root is null || string.IsNullOrEmpty(root.GetAttribute("ID")))
        {
            return false;
        }

        var directSignatures = root.ChildNodes.OfType<XmlElement>()
            .Where(e => e.LocalName == "Signature" && e.NamespaceURI == SamlNames.DsigNs)
            .ToList();
        if (directSignatures.Count != 1)
        {
            return false;
        }

        // A signature elsewhere is only allowed inside an Assertion, which has its own signature and check.
        var signature = directSignatures[0];
        foreach (XmlElement other in document.GetElementsByTagName("Signature", SamlNames.DsigNs))
        {
            if (other != signature && !InsideAssertion(other, root))
            {
                return false;
            }
        }

        var ns = new XmlNamespaceManager(document.NameTable);
        ns.AddNamespace("ds", SamlNames.DsigNs);

        var signedInfo = signature.SelectSingleNode("ds:SignedInfo", ns) as XmlElement;
        if (signedInfo is null ||
            signedInfo.SelectSingleNode("ds:CanonicalizationMethod/@Algorithm", ns)?.Value != AlgorithmPolicy.ExcC14N ||
            !AlgorithmPolicy.IsAllowedSignatureMethod(signedInfo.SelectSingleNode("ds:SignatureMethod/@Algorithm", ns)?.Value))
        {
            return false;
        }

        var references = signedInfo.SelectNodes("ds:Reference", ns);
        if (references is null || references.Count != 1 || references[0] is not XmlElement reference)
        {
            return false;
        }
        if (reference.GetAttribute("URI") != "#" + root.GetAttribute("ID") ||
            !AlgorithmPolicy.IsAllowedDigestMethod(reference.SelectSingleNode("ds:DigestMethod/@Algorithm", ns)?.Value))
        {
            return false;
        }

        var transforms = reference.SelectNodes("ds:Transforms/ds:Transform/@Algorithm", ns);
        var allowedTransforms = transforms is not null &&
            transforms.Cast<XmlNode>().All(t => t.Value is AlgorithmPolicy.Enveloped or AlgorithmPolicy.ExcC14N);
        if (!allowedTransforms)
        {
            return false;
        }

        try
        {
            var signed = new SamlSignedXml(document);
            signed.LoadXml(signature);
            return certificates.Any(certificate => signed.CheckSignature(certificate, verifySignatureOnly: true));
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool InsideAssertion(XmlNode node, XmlElement root)
    {
        for (var current = node.ParentNode; current is not null && current != root; current = current.ParentNode)
        {
            if (current is XmlElement { LocalName: "Assertion" } element && element.NamespaceURI == SamlNames.AssertionNs)
            {
                return true;
            }
        }
        return false;
    }
}

// Verifies an HTTP-Redirect binding signature over the raw query string (SAML Bindings §3.4.4.1).
// The signed input is the query as received, so the values are never decoded and re-encoded first.
public static class RedirectSignature
{
    public static bool Verify(string rawQuery, IEnumerable<X509Certificate2> certificates)
    {
        var parameters = ParseRaw(rawQuery);
        if (parameters is null)
        {
            return false;
        }

        var message = parameters.TryGetValue("SAMLRequest", out var request) ? request : parameters.GetValueOrDefault("SAMLResponse");
        if (message.Name is null ||
            !parameters.TryGetValue("SigAlg", out var sigAlg) ||
            !parameters.TryGetValue("Signature", out var signature))
        {
            return false;
        }

        var algorithm = Uri.UnescapeDataString(sigAlg.Raw);
        if (algorithm != AlgorithmPolicy.RsaSha256)
        {
            return false;
        }

        var signedInput = new StringBuilder();
        signedInput.Append(message.Name).Append('=').Append(message.Raw);
        if (parameters.TryGetValue("RelayState", out var relay))
        {
            signedInput.Append("&RelayState=").Append(relay.Raw);
        }
        signedInput.Append("&SigAlg=").Append(sigAlg.Raw);

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(Uri.UnescapeDataString(signature.Raw));
        }
        catch (FormatException)
        {
            return false;
        }

        var data = Encoding.UTF8.GetBytes(signedInput.ToString());
        return certificates.Any(certificate => certificate.GetRSAPublicKey() is { } key &&
            key.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    public static bool IsPresent(string rawQuery) => ParseRaw(rawQuery)?.ContainsKey("Signature") ?? true;

    // Returns null when a parameter repeats, because a repeated name is ambiguous.
    private static Dictionary<string, RawValue>? ParseRaw(string rawQuery)
    {
        var query = rawQuery.TrimStart('?');
        var result = new Dictionary<string, RawValue>(StringComparer.Ordinal);
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            if (separator <= 0)
            {
                return null;
            }
            var name = pair[..separator];
            if (!result.TryAdd(name, new RawValue(name, pair[(separator + 1)..])))
            {
                return null;
            }
        }
        return result;
    }

    private readonly record struct RawValue(string Name, string Raw);
}
