using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Core.Metadata;

public sealed record AcsEndpoint(string Location, int Index, bool IsDefault);

public sealed record SpMetadata(
    string EntityId,
    IReadOnlyList<AcsEndpoint> AcsEndpoints,
    IReadOnlyList<byte[]> SigningCertificates,
    bool AuthnRequestsSigned,
    bool WantAssertionsSigned,
    IReadOnlyList<string> NameIdFormats,
    IReadOnlyList<string> RequestedAttributes);

public sealed class MetadataException(string message) : Exception(message);

// Parses SAML 2.0 SP metadata (OASIS SAML Metadata §2.4). The parser is strict: DTDs and
// external entities are refused, and size and nesting are capped. Anything it doesn't
// understand fails the parse rather than being skipped. Metadata signatures are not verified.
public static class MetadataParser
{
    public const int MaxBytes = 1024 * 1024;
    public const int MaxDepth = 32;

    private const string Md = SamlNames.MetadataNs;
    private const string Ds = SamlNames.DsigNs;
    private const string Protocol = SamlNames.ProtocolNs;
    private const string HttpPost = SamlNames.HttpPost;

    // Characters an ACS location may use. The location is placed in the auto-post page's Content-Security-Policy,
    // where ; , ' and spaces would change the policy, so they are refused here.
    private static readonly Regex SafeAcsLocation = new("^https://[A-Za-z0-9\\-._~:/?#\\[\\]@!$&()*+=%]+\\z", RegexOptions.CultureInvariant);

    public static SpMetadata Parse(string xml)
    {
        if (xml.Length > MaxBytes)
        {
            throw new MetadataException("Metadata is too large.");
        }

        XmlDocument document;
        try
        {
            document = SafeXml.Parse(xml, MaxBytes);
        }
        catch (SamlException)
        {
            throw new MetadataException("Metadata is not well-formed XML, or it contains a DTD.");
        }

        XDocument xDocument;
        try
        {
            xDocument = XDocument.Load(new XmlNodeReader(document), LoadOptions.None);
        }
        catch (XmlException)
        {
            throw new MetadataException("Metadata is not well-formed XML, or it contains a DTD.");
        }

        if (xDocument.Descendants().Any(e => e.Ancestors().Count() > MaxDepth))
        {
            throw new MetadataException("Metadata is nested too deeply.");
        }

        var root = xDocument.Root;
        if (root is null || root.Name != XName.Get("EntityDescriptor", Md))
        {
            throw new MetadataException("Metadata root must be a single md:EntityDescriptor.");
        }

        var entityId = root.Attribute("entityID")?.Value;
        if (string.IsNullOrWhiteSpace(entityId) || entityId.Length > 2048)
        {
            throw new MetadataException("EntityDescriptor needs a non-empty entityID of at most 2048 characters.");
        }

        var sso = root.Elements(XName.Get("SPSSODescriptor", Md)).ToList();
        if (sso.Count != 1)
        {
            throw new MetadataException("Metadata must contain exactly one SPSSODescriptor.");
        }
        var spDescriptor = sso[0];

        var protocols = (spDescriptor.Attribute("protocolSupportEnumeration")?.Value ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (!protocols.Contains(Protocol))
        {
            throw new MetadataException("SPSSODescriptor must support the SAML 2.0 protocol.");
        }

        var acs = spDescriptor.Elements(XName.Get("AssertionConsumerService", Md))
            .Where(e => e.Attribute("Binding")?.Value == HttpPost)
            .Select(e => new AcsEndpoint(
                Location: RequireHttps(e.Attribute("Location")?.Value),
                Index: int.TryParse(e.Attribute("index")?.Value, out var i) ? i : throw new MetadataException("ACS index is missing or invalid."),
                IsDefault: e.Attribute("isDefault")?.Value is "true" or "1"))
            .ToList();
        if (acs.Count == 0)
        {
            throw new MetadataException("Metadata needs at least one HTTP-POST AssertionConsumerService.");
        }
        if (acs.Select(a => a.Index).Distinct().Count() != acs.Count)
        {
            throw new MetadataException("ACS indexes must be unique.");
        }

        var certificates = spDescriptor.Elements(XName.Get("KeyDescriptor", Md))
            .Where(k => k.Attribute("use")?.Value == "signing")
            .SelectMany(k => k.Descendants(XName.Get("X509Certificate", Ds)))
            .Select(c => Convert.FromBase64String(string.Concat(c.Value.Where(ch => !char.IsWhiteSpace(ch)))))
            .ToList();
        if (certificates.Count == 0)
        {
            throw new MetadataException("Metadata needs at least one signing certificate (KeyDescriptor use=\"signing\").");
        }

        var nameIdFormats = spDescriptor.Elements(XName.Get("NameIDFormat", Md)).Select(e => e.Value.Trim()).ToList();
        var attributes = spDescriptor.Descendants(XName.Get("RequestedAttribute", Md))
            .Select(e => e.Attribute("Name")?.Value ?? throw new MetadataException("RequestedAttribute needs a Name."))
            .ToList();

        return new SpMetadata(
            EntityId: entityId,
            AcsEndpoints: acs,
            SigningCertificates: certificates,
            AuthnRequestsSigned: spDescriptor.Attribute("AuthnRequestsSigned")?.Value is "true" or "1",
            WantAssertionsSigned: spDescriptor.Attribute("WantAssertionsSigned")?.Value is "true" or "1",
            NameIdFormats: nameIdFormats,
            RequestedAttributes: attributes);
    }

    public static string Fingerprint(byte[] certificateDer) =>
        Convert.ToHexString(SHA256.HashData(certificateDer));

    public static string NormalizeFingerprint(string value) =>
        new string(value.Where(c => !char.IsWhiteSpace(c) && c != ':').ToArray()).ToUpperInvariant();

    private static string RequireHttps(string? location)
    {
        if (location is null || !SafeAcsLocation.IsMatch(location) || !Uri.TryCreate(location, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new MetadataException("ACS locations must be absolute https URLs.");
        }
        return uri.AbsoluteUri;
    }
}
