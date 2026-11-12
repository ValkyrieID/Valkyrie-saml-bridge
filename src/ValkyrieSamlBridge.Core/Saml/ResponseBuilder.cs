using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using ValkyrieSamlBridge.Core.Configuration;

namespace ValkyrieSamlBridge.Core.Saml;

public sealed record AssertionContent(
    string NameId,
    string NameIdFormat,
    IReadOnlyList<SamlAttributeData> Attributes,
    string AuthnContextClass,
    DateTimeOffset AuthnInstant,
    string? InResponseTo,
    string Audience,
    string AcsUrl);

public sealed record BuiltResponse(string Xml, string? AssertionId);

// Every time comes from the injected TimeProvider and is
// passed explicitly to the assertion, so the library never reads the system clock.
public sealed class ResponseBuilder(X509Certificate2 signingCertificate, BridgeOptions options, TimeProvider time)
{
    // 128 random bits from RandomNumberGenerator. The leading letter makes the value a valid xs:ID (SAML Core §1.3.4).
    private static string NewId() => "a" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    public BuiltResponse BuildAuthnResponse(AssertionContent content)
    {
        var now = time.GetUtcNow();
        var (assertionXml, assertionId) = BuildSignedAssertion(content, now);
        var xml = BuildSignedResponse(content.AcsUrl, content.InResponseTo, SamlNames.StatusSuccess, assertionXml, now);
        return new BuiltResponse(xml, assertionId);
    }

    public BuiltResponse BuildErrorResponse(string topLevelStatus, string? secondLevelStatus, string acsUrl, string? inResponseTo)
    {
        var now = time.GetUtcNow();
        var xml = BuildSignedResponse(acsUrl, inResponseTo, topLevelStatus, assertionXml: null, now, secondLevel: secondLevelStatus);
        return new BuiltResponse(xml, null);
    }

    private (string Xml, string Id) BuildSignedAssertion(AssertionContent content, DateTimeOffset now)
    {
        var expires = now + options.AssertionLifetime;
        var id = NewId();
        var assertion = new Saml2Assertion(new Saml2NameIdentifier(options.EntityId))
        {
            Id = new Saml2Id(id),
            IssueInstant = now.UtcDateTime,
            SigningCredentials = new SigningCredentials(new X509SecurityKey(signingCertificate), AlgorithmPolicy.RsaSha256, AlgorithmPolicy.Sha256Digest),
        };

        assertion.Subject = new Saml2Subject(new Saml2NameIdentifier(content.NameId, new Uri(content.NameIdFormat)));
        var confirmationData = new Saml2SubjectConfirmationData
        {
            NotOnOrAfter = expires.UtcDateTime,
            Recipient = new Uri(content.AcsUrl),
        };
        if (content.InResponseTo is not null)
        {
            confirmationData.InResponseTo = new Saml2Id(content.InResponseTo);
        }
        assertion.Subject.SubjectConfirmations.Add(new Saml2SubjectConfirmation(new Uri(SamlNames.BearerMethod), confirmationData));

        assertion.Conditions = new Saml2Conditions
        {
            NotBefore = now.UtcDateTime,
            NotOnOrAfter = expires.UtcDateTime,
        };
        assertion.Conditions.AudienceRestrictions.Add(new Saml2AudienceRestriction(content.Audience));

        assertion.Statements.Add(new Saml2AuthenticationStatement(
            new Saml2AuthenticationContext(new Uri(content.AuthnContextClass)),
            content.AuthnInstant.UtcDateTime));

        if (content.Attributes.Count > 0)
        {
            var statement = new Saml2AttributeStatement(content.Attributes.Select(a =>
            {
                var attribute = new Saml2Attribute(a.Name) { NameFormat = new Uri(SamlNames.BasicNameFormat) };
                foreach (var value in a.Values)
                {
                    attribute.Values.Add(value);
                }
                return attribute;
            }));
            assertion.Statements.Add(statement);
        }

        var handler = new Saml2SecurityTokenHandler();
        return (handler.WriteToken(new Saml2SecurityToken(assertion)), id);
    }

    private string BuildSignedResponse(string acsUrl, string? inResponseTo, string statusCode, string? assertionXml, DateTimeOffset now, string? secondLevel = null)
    {
        var id = NewId();
        var document = new XmlDocument { PreserveWhitespace = true };
        var response = document.CreateElement("samlp", "Response", SamlNames.ProtocolNs);
        response.SetAttribute("ID", id);
        response.SetAttribute("Version", "2.0");
        response.SetAttribute("IssueInstant", Format(now));
        response.SetAttribute("Destination", acsUrl);
        if (inResponseTo is not null)
        {
            response.SetAttribute("InResponseTo", inResponseTo);
        }
        document.AppendChild(response);

        var issuer = document.CreateElement("saml", "Issuer", SamlNames.AssertionNs);
        issuer.InnerText = options.EntityId;
        response.AppendChild(issuer);

        var status = document.CreateElement("samlp", "Status", SamlNames.ProtocolNs);
        var top = document.CreateElement("samlp", "StatusCode", SamlNames.ProtocolNs);
        top.SetAttribute("Value", statusCode);
        status.AppendChild(top);
        if (secondLevel is not null)
        {
            var nested = document.CreateElement("samlp", "StatusCode", SamlNames.ProtocolNs);
            nested.SetAttribute("Value", secondLevel);
            top.AppendChild(nested);
        }
        response.AppendChild(status);

        if (assertionXml is not null)
        {
            var assertionDocument = new XmlDocument { PreserveWhitespace = true };
            assertionDocument.LoadXml(assertionXml);
            response.AppendChild(document.ImportNode(assertionDocument.DocumentElement!, deep: true));
        }

        SignElement(document, response, issuer);
        return document.OuterXml;
    }

    // The signature goes right after Issuer (SAML Core §5.4.2 element order) and covers the whole Response.
    private void SignElement(XmlDocument document, XmlElement response, XmlElement issuer)
    {
        using var rsa = signingCertificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("The signing certificate has no private key.");

        var signed = new SamlSignedXml(document) { SigningKey = rsa };
        var signedInfo = signed.SignedInfo ?? throw new InvalidOperationException("SignedXml has no SignedInfo.");
        signedInfo.CanonicalizationMethod = AlgorithmPolicy.ExcC14N;
        signedInfo.SignatureMethod = AlgorithmPolicy.RsaSha256;

        var reference = new Reference("#" + response.GetAttribute("ID")) { DigestMethod = AlgorithmPolicy.Sha256Digest };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signed.AddReference(reference);

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(signingCertificate));
        signed.KeyInfo = keyInfo;
        signed.ComputeSignature();

        response.InsertAfter(document.ImportNode(signed.GetXml(), deep: true), issuer);
    }

    private static string Format(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
}

