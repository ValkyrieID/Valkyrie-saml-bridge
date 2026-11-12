using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Saml;
using ValkyrieSamlBridge.Core.Security;

namespace ValkyrieSamlBridge.Core.Tests.Saml;

public sealed class ResponseBuilderTests : IDisposable
{
    private readonly X509Certificate2 _certificate = SamlTestData.CreateCertificate("sso");
    private readonly FixedTime _time = new(SamlTestData.Now);

    public void Dispose() => _certificate.Dispose();

    private ResponseBuilder Builder() => new(_certificate, SamlTestData.Options, _time);

    private static AssertionContent Content(IReadOnlyList<SamlAttributeData>? attributes = null, string? inResponseTo = "_req-1") => new(
        NameId: "7d1f1e2a-0000-4000-8000-000000000001",
        NameIdFormat: SamlNames.NameIdPersistent,
        Attributes: attributes ?? [],
        AuthnContextClass: SamlNames.AcPassword,
        AuthnInstant: SamlTestData.Now.AddMinutes(-1),
        InResponseTo: inResponseTo,
        Audience: SamlTestData.AppEntityId,
        AcsUrl: SamlTestData.AcsLocation);

    [Fact]
    public void AssertionCarriesTheExpectedFieldsAndExplicitTimes()
    {
        var built = Builder().BuildAuthnResponse(Content());
        var xml = SafeXml.Parse(built.Xml);
        var assertion = Assertion(xml);

        Assert.Equal(SamlTestData.Options.EntityId, Text(assertion, "Issuer"));
        Assert.Equal(SamlNames.BearerMethod, assertion.GetElementsByTagName("SubjectConfirmation", SamlNames.AssertionNs)[0]!.Attributes!["Method"]!.Value);

        var confirmation = assertion.GetElementsByTagName("SubjectConfirmationData", SamlNames.AssertionNs)[0]!;
        Assert.Equal(SamlTestData.AcsLocation, confirmation.Attributes!["Recipient"]!.Value);
        Assert.Equal("_req-1", confirmation.Attributes["InResponseTo"]!.Value);
        Assert.Equal(Iso(SamlTestData.Now + SamlTestData.Options.AssertionLifetime), confirmation.Attributes["NotOnOrAfter"]!.Value);

        var conditions = assertion.GetElementsByTagName("Conditions", SamlNames.AssertionNs)[0]!;
        Assert.Equal(Iso(SamlTestData.Now), conditions.Attributes!["NotBefore"]!.Value);
        Assert.Equal(Iso(SamlTestData.Now + SamlTestData.Options.AssertionLifetime), conditions.Attributes["NotOnOrAfter"]!.Value);
        Assert.Equal(SamlTestData.AppEntityId, Text(assertion, "Audience"));

        var authn = assertion.GetElementsByTagName("AuthnStatement", SamlNames.AssertionNs)[0]!;
        Assert.Equal(Iso(SamlTestData.Now - TimeSpan.FromMinutes(1)), authn.Attributes!["AuthnInstant"]!.Value);
        Assert.Equal(SamlNames.AcPassword, Text(assertion, "AuthnContextClassRef"));
    }

    // The library must not read the system clock. The fixed clock is far from real time, so this fails if it does.
    [Fact]
    public void TimesComeFromTheInjectedClockNotTheSystemClock()
    {
        var built = Builder().BuildAuthnResponse(Content());

        var assertion = Assertion(SafeXml.Parse(built.Xml));
        Assert.Equal(Iso(SamlTestData.Now), assertion.Attributes!["IssueInstant"]!.Value);
    }

    // Without attributes, the AttributeStatement is omitted (valid SAML; ITfoxtec couldn't do this).
    [Fact]
    public void AssertionWithoutAttributesHasNoAttributeStatement()
    {
        var built = Builder().BuildAuthnResponse(Content());

        Assert.Empty(SafeXml.Parse(built.Xml).GetElementsByTagName("AttributeStatement", SamlNames.AssertionNs));
    }

    [Fact]
    public void AttributesAreWrittenWithMultipleValues()
    {
        var attributes = new List<SamlAttributeData> { new("mail", ["a@example.test"]), new("groups", ["admins", "staff"]) };

        var built = Builder().BuildAuthnResponse(Content(attributes));
        var values = SafeXml.Parse(built.Xml).GetElementsByTagName("AttributeValue", SamlNames.AssertionNs);

        Assert.Equal(3, values.Count);
    }

    [Fact]
    public void ResponseAndAssertionAreBothSignedWithRsaSha256()
    {
        var built = Builder().BuildAuthnResponse(Content());
        var document = SafeXml.Parse(built.Xml);

        Assert.Equal(AlgorithmPolicy.RsaSha256, SignatureMethod(document.DocumentElement!));
        Assert.Equal(AlgorithmPolicy.RsaSha256, SignatureMethod(Assertion(document)));
        Assert.True(XmlSignatureVerifier.Verify(document, [_certificate]));
        Assert.True(XmlSignatureVerifier.Verify(SafeXml.Parse(AssertionAsDocument(document)), [_certificate]));
    }

    [Fact]
    public void ResponseSignatureFailsForAnotherCertificate()
    {
        using var other = SamlTestData.CreateCertificate("other");
        var document = SafeXml.Parse(Builder().BuildAuthnResponse(Content()).Xml);

        Assert.False(XmlSignatureVerifier.Verify(document, [other]));
    }

    [Fact]
    public void ResponseCarriesDestinationInResponseToAndStatus()
    {
        var root = SafeXml.Parse(Builder().BuildAuthnResponse(Content()).Xml).DocumentElement!;

        Assert.Equal(SamlTestData.AcsLocation, root.GetAttribute("Destination"));
        Assert.Equal("_req-1", root.GetAttribute("InResponseTo"));
        Assert.Equal(SamlNames.StatusSuccess, root.GetElementsByTagName("StatusCode", SamlNames.ProtocolNs)[0]!.Attributes!["Value"]!.Value);
    }

    [Fact]
    public void AssertionIdsAreUniqueAcrossLogins()
    {
        var builder = Builder();

        var first = builder.BuildAuthnResponse(Content()).AssertionId;
        var second = builder.BuildAuthnResponse(Content()).AssertionId;

        Assert.NotNull(first);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void ErrorResponseHasNoAssertionAndUsesTheStatusCodes()
    {
        var built = Builder().BuildErrorResponse(SamlNames.StatusResponder, SamlNames.StatusNoPassive, SamlTestData.AcsLocation, "_req-1");
        var root = SafeXml.Parse(built.Xml).DocumentElement!;

        Assert.Null(built.AssertionId);
        Assert.Empty(root.GetElementsByTagName("Assertion", SamlNames.AssertionNs));
        var top = root.GetElementsByTagName("StatusCode", SamlNames.ProtocolNs)[0]!;
        Assert.Equal(SamlNames.StatusResponder, top.Attributes!["Value"]!.Value);
        Assert.Equal(SamlNames.StatusNoPassive, top.FirstChild!.Attributes!["Value"]!.Value);
    }

    private static XmlElement Assertion(XmlDocument document) =>
        (XmlElement)document.DocumentElement!.GetElementsByTagName("Assertion", SamlNames.AssertionNs)[0]!;

    private static string AssertionAsDocument(XmlDocument document)
    {
        var copy = new XmlDocument { PreserveWhitespace = true };
        copy.AppendChild(copy.ImportNode(Assertion(document), true));
        return copy.OuterXml;
    }

    private static string Text(XmlElement scope, string localName) =>
        scope.GetElementsByTagName(localName, localName == "Audience" ? SamlNames.AssertionNs : SamlNames.AssertionNs)[0]!.InnerText;

    private static string SignatureMethod(XmlElement scope) =>
        scope.GetElementsByTagName("SignatureMethod", SamlNames.DsigNs)[0]!.Attributes!["Algorithm"]!.Value;

    private static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture);
}

public sealed class ClaimMappingTests
{
    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> IdToken = new Dictionary<string, IReadOnlyList<string>>
    {
        ["sub"] = ["7d1f1e2a-0000-4000-8000-000000000001"],
        ["email"] = ["alice@example.test"],
        ["groups"] = ["admins", "staff"],
    };

    [Fact]
    public void NameIdAndRequiredAttributesAreMapped()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("mail", "email", Required: true)]);

        var identity = ClaimMapper.Map(app, IdToken);

        Assert.Equal("7d1f1e2a-0000-4000-8000-000000000001", identity.NameId);
        Assert.Equal("mail", identity.Attributes[0].Name);
        Assert.Equal(["alice@example.test"], identity.Attributes[0].Values);
    }

    [Fact]
    public void MultiValuedClaimsBecomeMultipleValues()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("groups", "groups", Required: false)]);

        var identity = ClaimMapper.Map(app, IdToken);

        Assert.Equal(["admins", "staff"], identity.Attributes[0].Values);
    }

    [Fact]
    public void MissingRequiredAttributeRefusesTheLogin()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("title", "name", Required: true)]);

        Assert.Throws<SamlException>(() => ClaimMapper.Map(app, IdToken));
    }

    [Fact]
    public void MissingOptionalAttributeIsOmittedNotSentEmpty()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("title", "name", Required: false)]);

        var identity = ClaimMapper.Map(app, IdToken);

        Assert.Empty(identity.Attributes);
    }

    [Fact]
    public void MissingNameIdRefusesTheLogin()
    {
        var app = SamlTestData.Registration(nameId: new NameIdSetting("preferred_username", SamlNames.NameIdUnspecified));

        Assert.Throws<SamlException>(() => ClaimMapper.Map(app, IdToken));
    }

    [Fact]
    public void AppWithoutANameIdClaimRefusesTheLogin()
    {
        var app = SamlTestData.Registration() with { NameId = null };

        Assert.Throws<SamlException>(() => ClaimMapper.Map(app, IdToken));
    }

    // Attack: a multi-valued NameID would give the SP an ambiguous identity.
    [Fact]
    public void MultiValuedNameIdRefusesTheLogin()
    {
        var app = SamlTestData.Registration(nameId: new NameIdSetting("groups", SamlNames.NameIdUnspecified));

        Assert.Throws<SamlException>(() => ClaimMapper.Map(app, IdToken));
    }

    // Attack: a mapped name that breaks the claim name rule is refused, even when the ID token has a value for it.
    [Fact]
    public void ClaimNameThatBreaksTheRuleIsRefused()
    {
        var app = SamlTestData.Registration(attributes: [new AttributeSetting("x", "tenant-id", Required: false)]);

        Assert.Throws<SamlException>(() => ClaimMapper.Map(app, IdToken));
    }

    [Theory]
    [InlineData("pwd", SamlNames.AcPassword)]
    [InlineData("pwd mfa", SamlNames.AcPassword)]
    [InlineData("pwd otp mfa", SamlNames.AcMobileTwoFactor)]
    [InlineData("pwd passkey", SamlNames.AcUnspecified)]
    [InlineData("", SamlNames.AcUnspecified)]
    public void AmrMapsToAuthnContext(string amr, string expected) =>
        Assert.Equal(expected, AuthnContextMapper.FromAmr(amr.Split(' ', StringSplitOptions.RemoveEmptyEntries)));

    [Fact]
    public void RequestedClassesAreSatisfiedOnlyWhenListed()
    {
        Assert.True(AuthnContextMapper.Satisfies([], SamlNames.AcPassword));
        Assert.True(AuthnContextMapper.Satisfies([SamlNames.AcPassword], SamlNames.AcPassword));
        Assert.False(AuthnContextMapper.Satisfies([SamlNames.AcMobileTwoFactor], SamlNames.AcPassword));
    }
}

public sealed class BridgeOptionsTests
{
    [Theory]
    [InlineData("http://sso.example.test")]
    [InlineData("https://sso.example.test/path")]
    [InlineData("https://sso.example.test/?x=1")]
    public void PublicUrlMustBeAnHttpsOrigin(string url)
    {
        var options = BridgeOptions.Create(new Uri(url));

        Assert.Throws<InvalidOperationException>(() => options.Validate());
    }

    [Fact]
    public void EndpointsAreBuiltFromThePublicUrlOnly()
    {
        var options = BridgeOptions.Create(new Uri("https://sso.example.test/"));

        Assert.Equal("https://sso.example.test/saml/metadata", options.EntityId);
        Assert.Equal("https://sso.example.test/saml/sso", options.SsoUrl);
        Assert.Equal("https://sso.example.test/saml/callback", options.CallbackUrl);
    }
}

public sealed class IdpMetadataTests
{
    [Fact]
    public void MetadataPublishesTheEntityEndpointsAndCertificate()
    {
        using var certificate = SamlTestData.CreateCertificate("sso");
        var der = certificate.Export(X509ContentType.Cert);

        var xml = IdpMetadata.Build(SamlTestData.Options, [der]);
        var document = SafeXml.Parse(xml);

        var entity = document.DocumentElement!;
        Assert.Equal(SamlTestData.Options.EntityId, entity.GetAttribute("entityID"));
        Assert.Equal(SamlTestData.Options.SsoUrl, document.GetElementsByTagName("SingleSignOnService", SamlNames.MetadataNs)[0]!.Attributes!["Location"]!.Value);
        Assert.Equal(2, document.GetElementsByTagName("SingleSignOnService", SamlNames.MetadataNs).Count);
        Assert.Equal(Convert.ToBase64String(der), document.GetElementsByTagName("X509Certificate", SamlNames.DsigNs)[0]!.InnerText);
    }
}

public sealed class SigningCertificateTests
{
    [Fact]
    public void GeneratedKeyIsRsa2048AndRoundTripsThroughPkcs8()
    {
        var time = new FixedTime(SamlTestData.Now);
        var (privateKey, der) = SigningCertificate.Create(time, "sso.example.test");

        using var loaded = SigningCertificate.Load(privateKey, der);

        Assert.Equal(SigningCertificate.KeySize, loaded.GetRSAPublicKey()?.KeySize);
        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(SamlTestData.Now.AddMinutes(-5).UtcDateTime.Date, loaded.NotBefore.Date);
    }

    [Fact]
    public void CertificateIsValidFiveYears()
    {
        var (_, der) = SigningCertificate.Create(new FixedTime(SamlTestData.Now), "sso.example.test");

        using var certificate = X509CertificateLoader.LoadCertificate(der);
        Assert.Equal(SamlTestData.Now + SigningCertificate.Lifetime, certificate.NotAfter.ToUniversalTime(), TimeSpan.FromDays(1));
    }
}

public sealed class MasterKeyEncryptionForSigningKeyTests
{
    [Fact]
    public void SigningKeyCannotBeDecryptedWithAnotherContext()
    {
        using var master = MasterKey.FromBase64(MasterKey.GenerateBase64());
        var (privateKey, _) = SigningCertificate.Create(new FixedTime(SamlTestData.Now), "sso.example.test");
        var sealedKey = master.Encrypt(privateKey, "signing-key");

        Assert.ThrowsAny<CryptographicException>(() => master.Decrypt(sealedKey, "client-secret"));
    }
}

