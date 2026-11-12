using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Configuration;
using ValkyrieSamlBridge.Core.Saml;

namespace ValkyrieSamlBridge.Core.Tests.Saml;

public sealed class AuthnRequestValidationTests
{
    private static readonly DateTimeOffset Now = SamlTestData.Now;

    private static ValidatedAuthnRequest Validate(string xml, AppRegistration? app, string? relayState = null, string? rawRedirect = null)
    {
        var document = SafeXml.Parse(xml);
        var message = AuthnRequestParser.Parse(document);
        return AuthnRequestValidator.Validate(message, document, rawRedirect, app, relayState, SamlTestData.Options, Now);
    }

    private static SamlRequestException Refused(string xml, AppRegistration? app)
    {
        var error = Assert.Throws<SamlRequestException>(() => Validate(xml, app));
        return error;
    }

    [Fact]
    public void ValidRequestIsAcceptedWithItsDefaultAcs()
    {
        var result = Validate(SamlTestData.AuthnRequestXml(destination: SamlTestData.Options.SsoUrl), SamlTestData.Registration());

        Assert.Equal(SamlTestData.AcsLocation, result.AcsUrl);
        Assert.Equal("_req-1", result.Request.Id);
    }

    [Fact]
    public void UnknownIssuerIsRefusedWithoutAnAcs()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(issuer: "https://evil.example.test"), SamlTestData.Registration());

        Assert.Null(error.AcsUrl);
    }

    [Fact]
    public void NoAppIsRefusedWithoutAnAcs()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(), null);

        Assert.Null(error.AcsUrl);
    }

    [Fact]
    public void DisabledAppIsRefused()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(), SamlTestData.Registration(enabled: false));

        Assert.Null(error.AcsUrl);
    }

    [Fact]
    public void AcsThatIsNotRegisteredIsRefusedWithoutAnAcs()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(acs: "https://payroll.example.test/saml/acs/extra"), SamlTestData.Registration());

        Assert.Null(error.AcsUrl);
    }

    [Fact]
    public void AcsPrefixMatchIsRefused()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(acs: SamlTestData.AcsLocation + "%2F..%2Fx"), SamlTestData.Registration());

        Assert.Null(error.AcsUrl);
    }

    [Fact]
    public void AcsIndexSelectsTheRegisteredEndpoint()
    {
        var xml = SamlTestData.AuthnRequestXml(acs: null, extra: null).Replace("ProtocolBinding=", "AssertionConsumerServiceIndex=\"2\" ProtocolBinding=");

        var result = Validate(xml, SamlTestData.Registration());

        Assert.Equal(SamlTestData.OtherAcsLocation, result.AcsUrl);
    }

    [Fact]
    public void AcsUrlAndIndexThatDisagreeAreRefused()
    {
        var xml = SamlTestData.AuthnRequestXml(acs: SamlTestData.AcsLocation).Replace("ProtocolBinding=", "AssertionConsumerServiceIndex=\"2\" ProtocolBinding=");

        var error = Refused(xml, SamlTestData.Registration());

        Assert.Null(error.AcsUrl);
    }

    [Fact]
    public void WrongDestinationIsRefusedAfterTheAcsIsValidated()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(destination: "https://sso.example.test/other"), SamlTestData.Registration());

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    [Fact]
    public void ArtifactBindingIsRefused()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"), SamlTestData.Registration());

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    [Fact]
    public void RequestOlderThanTheWindowIsRefused()
    {
        var old = Now - BridgeOptions.AuthnRequestMaxAge - SamlTestData.Options.ClockSkew - TimeSpan.FromSeconds(1);

        var error = Refused(SamlTestData.AuthnRequestXml(issueInstant: old), SamlTestData.Registration());

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    [Fact]
    public void RequestExactlyAtTheClockSkewBoundaryIsAccepted()
    {
        var edge = Now - BridgeOptions.AuthnRequestMaxAge - SamlTestData.Options.ClockSkew;

        var result = Validate(SamlTestData.AuthnRequestXml(issueInstant: edge), SamlTestData.Registration());

        Assert.Equal("_req-1", result.Request.Id);
    }

    [Fact]
    public void RequestFromTheFutureBeyondTheSkewIsRefused()
    {
        var future = Now + SamlTestData.Options.ClockSkew + TimeSpan.FromSeconds(1);

        var error = Refused(SamlTestData.AuthnRequestXml(issueInstant: future), SamlTestData.Registration());

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    [Fact]
    public void UnsignedRequestIsRefusedWhenTheAppMustSign()
    {
        var error = Refused(SamlTestData.AuthnRequestXml(), SamlTestData.Registration(signatureRequired: true));

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    [Fact]
    public void SignedRequestFromAConfirmedCertificateIsAccepted()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml(destination: SamlTestData.Options.SsoUrl));
        SamlTestData.SignRoot(document, certificate);

        var message = AuthnRequestParser.Parse(document);
        var result = AuthnRequestValidator.Validate(message, document, null, SamlTestData.Registration(certificate), null, SamlTestData.Options, Now);

        Assert.Equal("_req-1", result.Request.Id);
    }

    // Attack: a signed POST request with no Destination is refused after the ACS is validated, so the SP gets a SAML error.
    [Fact]
    public void SignedRequestWithoutDestinationIsRefusedAfterTheAcsIsValidated()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, certificate);

        var message = AuthnRequestParser.Parse(document);
        var error = Assert.Throws<SamlRequestException>(() =>
            AuthnRequestValidator.Validate(message, document, null, SamlTestData.Registration(certificate), null, SamlTestData.Options, Now));

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    // Success: an unsigned request with no Destination is still accepted when the app doesn't require signing.
    [Fact]
    public void UnsignedRequestWithoutDestinationIsAcceptedWhenSigningIsNotRequired()
    {
        var result = Validate(SamlTestData.AuthnRequestXml(), SamlTestData.Registration());

        Assert.Equal("_req-1", result.Request.Id);
    }

    // Attack: the signature is valid, but for a certificate the admin never confirmed.
    [Fact]
    public void SignatureFromAnUnconfirmedCertificateIsRefused()
    {
        using var attacker = SamlTestData.CreateCertificate("attacker");
        using var confirmed = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, attacker);

        var message = AuthnRequestParser.Parse(document);
        var error = Assert.Throws<SamlRequestException>(() =>
            AuthnRequestValidator.Validate(message, document, null, SamlTestData.Registration(confirmed), null, SamlTestData.Options, Now));

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    // Attack: the signature covers a different element, and the message is changed after signing.
    [Fact]
    public void TamperedSignedRequestIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, certificate);
        document.DocumentElement!.GetElementsByTagName("Issuer", SamlNames.AssertionNs)[0]!.InnerText = SamlTestData.AppEntityId + "-tampered";

        var message = AuthnRequestParser.Parse(document);
        Assert.Throws<SamlRequestException>(() =>
            AuthnRequestValidator.Validate(message, document, null, SamlTestData.Registration(certificate), null, SamlTestData.Options, Now));
    }

    // Attack: SHA-1 signatures are refused even when the key is trusted.
    [Fact]
    public void Sha1SignatureIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, certificate, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2000/09/xmldsig#sha1");

        var message = AuthnRequestParser.Parse(document);
        var error = Assert.Throws<SamlRequestException>(() =>
            AuthnRequestValidator.Validate(message, document, null, SamlTestData.Registration(certificate), null, SamlTestData.Options, Now));

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    // Attack: signature wrapping. A copy of the signed element is moved so the signature covers the
    // element the bridge doesn't read (the verified element must be the one used).
    [Fact]
    public void SignatureWrappingIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, certificate);
        var root = document.DocumentElement!;
        var signature = root.GetElementsByTagName("Signature", SamlNames.DsigNs)[0]!;
        var wrapper = document.CreateElement("Wrapper");
        wrapper.AppendChild(signature.CloneNode(true));
        root.AppendChild(wrapper);
        root.RemoveChild(signature);

        Assert.Throws<SamlRequestException>(() =>
            AuthnRequestValidator.Validate(AuthnRequestParser.Parse(document), document, null, SamlTestData.Registration(certificate), null, SamlTestData.Options, Now));
    }

    // Success: an XML signature on a Redirect request is verified the same way as on a POST request.
    [Fact]
    public void RedirectRequestWithAnXmlSignatureIsAcceptedWhenSigningIsRequired()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml(destination: SamlTestData.Options.SsoUrl));
        SamlTestData.SignRoot(document, certificate);

        var result = ValidateRedirect(document, "?SAMLRequest=abc", SamlTestData.Registration(certificate, signatureRequired: true));

        Assert.Equal("_req-1", result.Request.Id);
    }

    // Success: a query signature alone still satisfies a Redirect request that must be signed.
    [Fact]
    public void RedirectRequestWithAValidQuerySignatureIsAccepted()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml(destination: SamlTestData.Options.SsoUrl));
        var raw = RedirectSignatureTests.SignedRedirectQuery(certificate, "SAMLRequest=abc", "rsa-sha256");

        var result = ValidateRedirect(document, raw, SamlTestData.Registration(certificate, signatureRequired: true));

        Assert.Equal("_req-1", result.Request.Id);
    }

    // Success: both signatures are present and both verify.
    [Fact]
    public void RedirectRequestWithBothSignaturesValidIsAccepted()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml(destination: SamlTestData.Options.SsoUrl));
        SamlTestData.SignRoot(document, certificate);
        var raw = RedirectSignatureTests.SignedRedirectQuery(certificate, "SAMLRequest=abc", "rsa-sha256");

        var result = ValidateRedirect(document, raw, SamlTestData.Registration(certificate, signatureRequired: true));

        Assert.Equal("_req-1", result.Request.Id);
    }

    // Attack: a Redirect request with no signature of either kind is refused when the app must sign.
    [Fact]
    public void UnsignedRedirectRequestIsRefusedWhenTheAppMustSign()
    {
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());

        var error = Assert.Throws<SamlRequestException>(() =>
            ValidateRedirect(document, "?SAMLRequest=abc", SamlTestData.Registration(signatureRequired: true)));

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    // Attack: the XML signature is valid, but for a certificate the admin never confirmed.
    [Fact]
    public void RedirectXmlSignatureFromAnUnconfirmedCertificateIsRefused()
    {
        using var attacker = SamlTestData.CreateCertificate("attacker");
        using var confirmed = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, attacker);

        var error = Assert.Throws<SamlRequestException>(() =>
            ValidateRedirect(document, "?SAMLRequest=abc", SamlTestData.Registration(confirmed, signatureRequired: true)));

        Assert.Equal(SamlTestData.AcsLocation, error.AcsUrl);
    }

    // Attack: the XML signature is signed for the root, then the ACS is changed. The signature no longer verifies.
    [Fact]
    public void RedirectXmlSignedRequestWithAChangedAcsIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, certificate);
        document.DocumentElement!.SetAttribute("AssertionConsumerServiceURL", SamlTestData.OtherAcsLocation);

        Assert.Throws<SamlRequestException>(() =>
            ValidateRedirect(document, "?SAMLRequest=abc", SamlTestData.Registration(certificate, signatureRequired: true)));
    }

    // Attack: a valid query signature doesn't cover for a forged XML signature.
    [Fact]
    public void ValidQuerySignatureDoesNotCoverAForgedXmlSignature()
    {
        using var confirmed = SamlTestData.CreateCertificate("payroll");
        using var attacker = SamlTestData.CreateCertificate("attacker");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, attacker);
        var raw = RedirectSignatureTests.SignedRedirectQuery(confirmed, "SAMLRequest=abc", "rsa-sha256");

        Assert.Throws<SamlRequestException>(() =>
            ValidateRedirect(document, raw, SamlTestData.Registration(confirmed, signatureRequired: true)));
    }

    // Attack: a valid XML signature doesn't cover for a forged query signature.
    [Fact]
    public void ValidXmlSignatureDoesNotCoverAForgedQuerySignature()
    {
        using var confirmed = SamlTestData.CreateCertificate("payroll");
        using var attacker = SamlTestData.CreateCertificate("attacker");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, confirmed);
        var raw = RedirectSignatureTests.SignedRedirectQuery(attacker, "SAMLRequest=abc", "rsa-sha256");

        Assert.Throws<SamlRequestException>(() =>
            ValidateRedirect(document, raw, SamlTestData.Registration(confirmed, signatureRequired: true)));
    }

    // Attack: SHA-1 is refused for an XML signature on a Redirect request too.
    [Fact]
    public void Sha1XmlSignatureOnARedirectRequestIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml());
        SamlTestData.SignRoot(document, certificate, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2000/09/xmldsig#sha1");

        Assert.Throws<SamlRequestException>(() =>
            ValidateRedirect(document, "?SAMLRequest=abc", SamlTestData.Registration(certificate, signatureRequired: true)));
    }

    private static ValidatedAuthnRequest ValidateRedirect(XmlDocument document, string rawQuery, AppRegistration app) =>
        AuthnRequestValidator.Validate(AuthnRequestParser.Parse(document), document, rawQuery, app, null, SamlTestData.Options, Now);

    [Fact]
    public void RelayStateOnTheAllowListIsKept()
    {
        var result = Validate(SamlTestData.AuthnRequestXml(), SamlTestData.Registration(relayStates: ["/home"]), relayState: "/home");

        Assert.Equal("/home", result.RelayState);
    }

    // The SP's RelayState is echoed unchanged, even when it's not on the app's allow-list.
    [Fact]
    public void RelayStateNotOnTheAllowListIsEchoedUnchanged()
    {
        var result = Validate(SamlTestData.AuthnRequestXml(), SamlTestData.Registration(relayStates: ["/home"]), relayState: "/orders/123");

        Assert.Equal("/orders/123", result.RelayState);
    }

    [Fact]
    public void RelayStateIsNotMatchedAgainstTheAllowList()
    {
        var result = Validate(SamlTestData.AuthnRequestXml(), SamlTestData.Registration(relayStates: ["/home"]), relayState: "/home/../admin");

        Assert.Equal("/home/../admin", result.RelayState);
    }
}

public sealed class AuthnRequestParserTests
{
    [Fact]
    public void DoctypeIsRefused()
    {
        var xml = "<!DOCTYPE x [ <!ENTITY e SYSTEM \"file:///etc/passwd\"> ]>" + SamlTestData.AuthnRequestXml();

        Assert.Throws<SamlException>(() => SafeXml.Parse(xml));
    }

    [Fact]
    public void ExternalEntityIsRefused()
    {
        var xml = "<!DOCTYPE samlp:AuthnRequest [ <!ENTITY x SYSTEM \"http://169.254.169.254/\"> ]><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">&x;</samlp:AuthnRequest>";

        Assert.Throws<SamlException>(() => SafeXml.Parse(xml));
    }

    [Fact]
    public void OversizedMessageIsRefused()
    {
        var xml = new string('a', SafeXml.MaxBytes + 1);

        Assert.Throws<SamlException>(() => SafeXml.Parse(xml));
    }

    [Fact]
    public void WrongRootElementIsRefused()
    {
        var document = SafeXml.Parse("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_a\" Version=\"2.0\" IssueInstant=\"2026-11-10T12:00:00Z\"/>");

        Assert.Throws<SamlRequestException>(() => AuthnRequestParser.Parse(document));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1starts-with-digit")]
    [InlineData("_has space")]
    public void InvalidIdIsRefused(string id)
    {
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml(id: id));

        Assert.Throws<SamlRequestException>(() => AuthnRequestParser.Parse(document));
    }

    [Fact]
    public void UnsupportedChildElementIsRefused()
    {
        var document = SafeXml.Parse(SamlTestData.AuthnRequestXml(extra: "<samlp:Scoping xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>"));

        Assert.Throws<SamlRequestException>(() => AuthnRequestParser.Parse(document));
    }

    [Fact]
    public void ParsesRequestedContextAndFlags()
    {
        var extra = """
            <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Comparison="exact">
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </samlp:RequestedAuthnContext>
            """;
        var xml = SamlTestData.AuthnRequestXml(extra: extra).Replace("ProtocolBinding=", "ForceAuthn=\"true\" ProtocolBinding=");

        var message = AuthnRequestParser.Parse(SafeXml.Parse(xml));

        Assert.True(message.ForceAuthn);
        Assert.False(message.IsPassive);
        Assert.Equal("exact", message.RequestedComparison);
        Assert.Equal([SamlNames.AcPassword], message.RequestedContextClasses);
    }

    [Fact]
    public void InvalidBooleanIsRefused()
    {
        var xml = SamlTestData.AuthnRequestXml().Replace("ProtocolBinding=", "IsPassive=\"yes\" ProtocolBinding=");

        Assert.Throws<SamlRequestException>(() => AuthnRequestParser.Parse(SafeXml.Parse(xml)));
    }

    [Fact]
    public void RedirectInflateRejectsAnOversizedExpansion()
    {
        var big = new string('a', SafeXml.MaxBytes + 4096);
        using var output = new MemoryStream();
        using (var deflate = new System.IO.Compression.DeflateStream(output, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
        {
            var bytes = Encoding.UTF8.GetBytes(big);
            deflate.Write(bytes);
        }

        Assert.Throws<SamlException>(() => SamlMessageEncoding.InflateRedirect(Convert.ToBase64String(output.ToArray())));
    }
}

public sealed class AlgorithmPolicyTests
{
    [Fact]
    public void RsaSha256IsAllowed() => Assert.True(AlgorithmPolicy.IsAllowedSignatureMethod(AlgorithmPolicy.RsaSha256));

    // Attack: a stronger RSA or an ECDSA signature method is refused too. Only RSA-SHA256 is allowed.
    [Theory]
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")]
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")]
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")]
    public void OtherSignatureMethodsAreRefused(string algorithm) => Assert.False(AlgorithmPolicy.IsAllowedSignatureMethod(algorithm));

    [Theory]
    [InlineData("http://www.w3.org/2000/09/xmldsig#rsa-sha1")]
    [InlineData("http://www.w3.org/2000/09/xmldsig#dsa-sha1")]
    [InlineData("RS256")]
    [InlineData("")]
    public void Sha1AndUnknownSignatureAlgorithmsAreRefused(string algorithm) =>
        Assert.False(AlgorithmPolicy.IsAllowedSignatureMethod(algorithm));

    [Fact]
    public void Sha1DigestIsRefused() => Assert.False(AlgorithmPolicy.IsAllowedDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1"));
}

public sealed class RedirectSignatureTests
{
    [Fact]
    public void ValidRedirectSignatureIsAccepted()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var raw = SignedRedirectQuery(certificate, "SAMLRequest=abc%2Bdef&RelayState=%2Fhome", "rsa-sha256");

        Assert.True(RedirectSignature.Verify(raw, [certificate]));
    }

    // Attack: changing the message after it was signed.
    [Fact]
    public void ChangedRedirectMessageIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var raw = SignedRedirectQuery(certificate, "SAMLRequest=abc%2Bdef", "rsa-sha256");

        Assert.False(RedirectSignature.Verify(raw.Replace("abc", "xyz"), [certificate]));
    }

    [Fact]
    public void Sha1RedirectSignatureIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var raw = SignedRedirectQuery(certificate, "SAMLRequest=abc", "rsa-sha1");

        Assert.False(RedirectSignature.Verify(raw, [certificate]));
    }

    [Fact]
    public void RepeatedParameterIsRefused()
    {
        using var certificate = SamlTestData.CreateCertificate("payroll");
        var raw = SignedRedirectQuery(certificate, "SAMLRequest=abc", "rsa-sha256") + "&SAMLRequest=other";

        Assert.False(RedirectSignature.Verify(raw, [certificate]));
    }

    internal static string SignedRedirectQuery(X509Certificate2 certificate, string message, string sigAlgName)
    {
        var sigAlg = sigAlgName == "rsa-sha1"
            ? "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
            : AlgorithmPolicy.RsaSha256;
        var hash = sigAlgName == "rsa-sha1" ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
        var signedInput = $"{message}&SigAlg={Uri.EscapeDataString(sigAlg)}";
        var signature = certificate.GetRSAPrivateKey()?.SignData(Encoding.UTF8.GetBytes(signedInput), hash, RSASignaturePadding.Pkcs1)
            ?? throw new InvalidOperationException("The test certificate has no private key.");
        return $"?{signedInput}&Signature={Uri.EscapeDataString(Convert.ToBase64String(signature))}";
    }
}




