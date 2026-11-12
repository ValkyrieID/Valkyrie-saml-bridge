using System.Xml.Linq;
using ValkyrieSamlBridge.Core.Configuration;

namespace ValkyrieSamlBridge.Core.Saml;

// The bridge's IdP metadata (SAML Metadata §2.2). Every certificate is a signing KeyDescriptor, so an SP
// can trust the new certificate before the old one is retired. The first certificate is the active one.
public static class IdpMetadata
{
    public static string Build(BridgeOptions options, IEnumerable<byte[]> certificatesDer)
    {
        XNamespace md = SamlNames.MetadataNs;
        XNamespace ds = SamlNames.DsigNs;

        var descriptor = new XElement(md + "IDPSSODescriptor",
            new XAttribute("protocolSupportEnumeration", SamlNames.ProtocolNs),
            new XAttribute("WantAuthnRequestsSigned", "false"),
            certificatesDer.Select(der => new XElement(md + "KeyDescriptor",
                new XAttribute("use", "signing"),
                new XElement(ds + "KeyInfo",
                    new XElement(ds + "X509Data",
                        new XElement(ds + "X509Certificate", Convert.ToBase64String(der)))))),
            SamlNames.SupportedNameIdFormats.Select(format => new XElement(md + "NameIDFormat", format)),
            new XElement(md + "SingleSignOnService",
                new XAttribute("Binding", SamlNames.HttpRedirect),
                new XAttribute("Location", options.SsoUrl)),
            new XElement(md + "SingleSignOnService",
                new XAttribute("Binding", SamlNames.HttpPost),
                new XAttribute("Location", options.SsoUrl)));

        var entity = new XElement(md + "EntityDescriptor",
            new XAttribute("entityID", options.EntityId),
            descriptor);

        return new XDocument(new XDeclaration("1.0", "utf-8", null), entity).ToString(SaveOptions.DisableFormatting);
    }
}
