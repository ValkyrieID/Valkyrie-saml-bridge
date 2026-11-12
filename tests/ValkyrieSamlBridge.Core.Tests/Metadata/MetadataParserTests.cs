using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ValkyrieSamlBridge.Core.Metadata;

namespace ValkyrieSamlBridge.Core.Tests.Metadata;

public sealed class MetadataParserTests
{
    private static readonly string Certificate = MakeCertificate();

    private const string Valid = """
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://payroll.example.test/saml">
          <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo><ds:X509Data><ds:X509Certificate>CERT</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
            </md:KeyDescriptor>
            <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://payroll.example.test/saml/acs" index="1" isDefault="true"/>
            <md:AttributeConsumingService index="1"><md:RequestedAttribute Name="mail"/></md:AttributeConsumingService>
          </md:SPSSODescriptor>
        </md:EntityDescriptor>
        """;

    [Fact]
    public void ValidMetadataIsRead()
    {
        var metadata = MetadataParser.Parse(Valid.Replace("CERT", Certificate));

        Assert.Equal("https://payroll.example.test/saml", metadata.EntityId);
        var acs = Assert.Single(metadata.AcsEndpoints);
        Assert.Equal("https://payroll.example.test/saml/acs", acs.Location);
        Assert.True(acs.IsDefault);
        Assert.Single(metadata.SigningCertificates);
        Assert.True(metadata.AuthnRequestsSigned);
        Assert.True(metadata.WantAssertionsSigned);
        Assert.Equal(["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"], metadata.NameIdFormats);
        Assert.Equal(["mail"], metadata.RequestedAttributes);
    }

    [Fact]
    public void FingerprintIsTheSha256OfTheCertificateDer()
    {
        var der = Convert.FromBase64String(Certificate);

        var fingerprint = MetadataParser.Fingerprint(der);

        Assert.Equal(64, fingerprint.Length);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(der)), fingerprint);
    }

    // Attack: an ACS location with characters that would change the auto-post page's Content-Security-Policy.
    [Theory]
    [InlineData("https://payroll.example.test/saml/acs;script-src 'unsafe-inline'")]
    [InlineData("https://payroll.example.test/saml/acs'")]
    [InlineData("https://payroll.example.test/saml/ac s")]
    [InlineData("https://payroll.example.test/saml/acs\"")]
    public void AcsLocationWithPolicyCharactersIsRefused(string location)
    {
        var xml = Valid.Replace("CERT", Certificate).Replace("https://payroll.example.test/saml/acs", location);

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void DocumentTypeDeclarationIsRefused()
    {
        // Attack: an external entity that would read a local file or call out to a server.
        var xml = """
            <?xml version="1.0"?>
            <!DOCTYPE md:EntityDescriptor [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
            """ + Valid.Replace("CERT", Certificate);

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void NonHttpsAssertionConsumerLocationIsRefused()
    {
        var xml = Valid.Replace("CERT", Certificate).Replace("https://payroll.example.test/saml/acs", "http://payroll.example.test/saml/acs");

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void OnlyHttpPostEndpointsAreUsedAndAtLeastOneIsRequired()
    {
        var xml = Valid.Replace("CERT", Certificate).Replace(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void MetadataWithoutASigningCertificateIsRefused()
    {
        var xml = Valid.Replace("CERT", Certificate).Replace("use=\"signing\"", "use=\"encryption\"");

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void TwoSPDescriptorsAreRefused()
    {
        var xml = Valid.Replace("CERT", Certificate).Replace(
            "</md:EntityDescriptor>",
            "<md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/></md:EntityDescriptor>");

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void ProtocolSupportMustIncludeSaml2()
    {
        var xml = Valid.Replace("CERT", Certificate).Replace("urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:1.1:protocol");

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void WrongRootElementIsRefused()
    {
        Assert.Throws<MetadataException>(() => MetadataParser.Parse("<root/>"));
    }

    [Fact]
    public void OversizedMetadataIsRefused()
    {
        var xml = new string('a', MetadataParser.MaxBytes + 1);

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void DeeplyNestedMetadataIsRefused()
    {
        var nested = string.Concat(Enumerable.Repeat("<x>", 40)) + string.Concat(Enumerable.Repeat("</x>", 40));
        var xml = Valid.Replace("CERT", Certificate).Replace("</md:EntityDescriptor>", $"<md:Extensions>{nested}</md:Extensions></md:EntityDescriptor>");

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    [Fact]
    public void DuplicateAcsIndexesAreRefused()
    {
        var xml = Valid.Replace("CERT", Certificate).Replace(
            "index=\"1\" isDefault=\"true\"/>",
            "index=\"1\" isDefault=\"true\"/><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://payroll.example.test/other\" index=\"1\"/>");

        Assert.Throws<MetadataException>(() => MetadataParser.Parse(xml));
    }

    private static string MakeCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=payroll.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return Convert.ToBase64String(certificate.RawData);
    }
}
