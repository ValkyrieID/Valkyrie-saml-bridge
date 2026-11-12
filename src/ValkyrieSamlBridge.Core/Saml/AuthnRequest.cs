using System.Globalization;
using System.Xml;
using ValkyrieSamlBridge.Core.Apps;
using ValkyrieSamlBridge.Core.Configuration;

namespace ValkyrieSamlBridge.Core.Saml;

public sealed record AuthnRequestMessage(
    string Id,
    DateTimeOffset IssueInstant,
    string Issuer,
    string? Destination,
    string? AcsUrl,
    int? AcsIndex,
    string? ProtocolBinding,
    bool ForceAuthn,
    bool IsPassive,
    IReadOnlyList<string> RequestedContextClasses,
    string? RequestedComparison);

// AcsUrl is validated against the app's registered endpoints.
// RelayState is the SP's value, unchanged.
public sealed record ValidatedAuthnRequest(AuthnRequestMessage Request, AppRegistration App, string AcsUrl, string? RelayState);

// A refusal. AcsUrl is set only when the ACS was validated, which allows a SAML error response to be
// sent to it. Otherwise the caller shows a local error page and never redirects or posts.
public sealed class SamlRequestException(string message, string? acsUrl = null, string? requestId = null) : Exception(message)
{
    public string? AcsUrl { get; } = acsUrl;

    public string? RequestId { get; } = requestId;
}

// Parses an AuthnRequest (SAML Core §3.4.1) strictly. Unknown child elements and the parts this
// bridge doesn't support (Subject, Conditions, Scoping) are refused rather than ignored.
public static class AuthnRequestParser
{
    private static readonly HashSet<string> AllowedChildren = new(StringComparer.Ordinal)
    {
        "Issuer", "Signature", "NameIDPolicy", "RequestedAuthnContext", "Extensions",
    };

    public static AuthnRequestMessage Parse(XmlDocument document)
    {
        var root = document.DocumentElement;
        if (root is null || root.NamespaceURI != SamlNames.ProtocolNs || root.LocalName != "AuthnRequest")
        {
            throw new SamlRequestException("The message is not an AuthnRequest.");
        }
        if (root.GetAttribute("Version") != "2.0")
        {
            throw new SamlRequestException("The AuthnRequest version must be 2.0.");
        }

        var id = root.GetAttribute("ID");
        if (!IsValidId(id))
        {
            throw new SamlRequestException("The AuthnRequest has no valid ID.");
        }

        if (!DateTimeOffset.TryParse(root.GetAttribute("IssueInstant"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var issueInstant))
        {
            throw new SamlRequestException("The AuthnRequest has no valid IssueInstant.", requestId: id);
        }

        foreach (XmlNode child in root.ChildNodes)
        {
            if (child.NodeType == XmlNodeType.Element && (child.NamespaceURI is not (SamlNames.ProtocolNs or SamlNames.AssertionNs or SamlNames.DsigNs) || !AllowedChildren.Contains(child.LocalName)))
            {
                throw new SamlRequestException("The AuthnRequest contains an element this bridge doesn't support.");
            }
        }

        var issuer = Child(root, SamlNames.AssertionNs, "Issuer")?.InnerText.Trim();
        if (string.IsNullOrEmpty(issuer))
        {
            throw new SamlRequestException("The AuthnRequest has no Issuer.");
        }

        var acsUrl = NullIfEmpty(root.GetAttribute("AssertionConsumerServiceURL"));
        var acsIndex = ParseOptionalInt(root.GetAttribute("AssertionConsumerServiceIndex"));
        var binding = NullIfEmpty(root.GetAttribute("ProtocolBinding"));
        var forceAuthn = ParseBool(root.GetAttribute("ForceAuthn"));
        var isPassive = ParseBool(root.GetAttribute("IsPassive"));

        var contextElement = Child(root, SamlNames.ProtocolNs, "RequestedAuthnContext");
        var classes = contextElement is null
            ? []
            : contextElement.GetElementsByTagName("AuthnContextClassRef", SamlNames.AssertionNs)
                .Cast<XmlElement>()
                .Select(e => e.InnerText.Trim())
                .ToList();
        var comparison = contextElement is null ? null : NullIfEmpty(contextElement.GetAttribute("Comparison"));

        return new AuthnRequestMessage(
            Id: id,
            IssueInstant: issueInstant,
            Issuer: issuer,
            Destination: NullIfEmpty(root.GetAttribute("Destination")),
            AcsUrl: acsUrl,
            AcsIndex: acsIndex,
            ProtocolBinding: binding,
            ForceAuthn: forceAuthn,
            IsPassive: isPassive,
            RequestedContextClasses: classes,
            RequestedComparison: comparison);
    }

    private static bool IsValidId(string id) =>
        id.Length is > 0 and <= 256 &&
        (char.IsAsciiLetter(id[0]) || id[0] == '_') &&
        id.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');

    private static XmlElement? Child(XmlElement parent, string ns, string name)
    {
        foreach (XmlNode child in parent.ChildNodes)
        {
            if (child is XmlElement element && element.NamespaceURI == ns && element.LocalName == name)
            {
                return element;
            }
        }
        return null;
    }

    private static bool ParseBool(string value) => value switch
    {
        "" or "false" or "0" => false,
        "true" or "1" => true,
        _ => throw new SamlRequestException("The AuthnRequest has an invalid boolean attribute."),
    };

    private static int? ParseOptionalInt(string value)
    {
        if (value.Length == 0)
        {
            return null;
        }
        return int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var index)
            ? index
            : throw new SamlRequestException("The AuthnRequest has an invalid AssertionConsumerServiceIndex.");
    }

    private static string? NullIfEmpty(string value) => value.Length == 0 ? null : value;
}

// Applies the checks on the request. Failures before the ACS is validated carry no
// ACS, so no SAML response is sent. Failures after that carry the ACS.
public static class AuthnRequestValidator
{
    public static ValidatedAuthnRequest Validate(
        AuthnRequestMessage request,
        XmlDocument document,
        string? rawRedirectQuery,
        AppRegistration? app,
        string? relayState,
        BridgeOptions options,
        DateTimeOffset now)
    {
        // A disabled app is refused like an unknown app, so the SP learns nothing extra.
        if (app is null || !app.Enabled || !string.Equals(request.Issuer, app.EntityId, StringComparison.Ordinal))
        {
            throw new SamlRequestException("The request does not match an enabled app.");
        }

        var acs = ResolveAcs(request, app);

        var requestId = request.Id;
        if (request.Destination is not null && request.Destination != options.SsoUrl)
        {
            throw new SamlRequestException("The Destination does not match this bridge.", acs, requestId);
        }
        if (request.ProtocolBinding is not null && request.ProtocolBinding != SamlNames.HttpPost)
        {
            throw new SamlRequestException("Only the HTTP-POST response binding is supported.", acs, requestId);
        }

        var oldest = now - BridgeOptions.AuthnRequestMaxAge - options.ClockSkew;
        var newest = now + options.ClockSkew;
        if (request.IssueInstant < oldest || request.IssueInstant > newest)
        {
            throw new SamlRequestException("The AuthnRequest is outside its time window.", acs, requestId);
        }

        var certificates = ConfirmedCertificates(app);
        var xmlSigned = document.GetElementsByTagName("Signature", SamlNames.DsigNs).Count > 0;
        bool signed;
        bool signatureValid;
        if (rawRedirectQuery is not null)
        {
            // HTTP-Redirect: a query signature covers the raw query string (SAML Bindings §3.4.4.1). An XML
            // signature is allowed too, and each one present must verify.
            var querySigned = RedirectSignature.IsPresent(rawRedirectQuery);
            signed = querySigned || xmlSigned;
            signatureValid = (!querySigned || RedirectSignature.Verify(rawRedirectQuery, certificates))
                && (!xmlSigned || XmlSignatureVerifier.Verify(document, certificates));
        }
        else
        {
            signed = xmlSigned;
            signatureValid = signed && XmlSignatureVerifier.Verify(document, certificates);
        }

        if (app.AuthnRequestsSigned && !signed)
        {
            throw new SamlRequestException("This app must sign its requests.", acs, requestId);
        }
        if (signed && !signatureValid)
        {
            throw new SamlRequestException("The AuthnRequest signature is invalid or not from a confirmed certificate.", acs, requestId);
        }
        if (signed && request.Destination is null)
        {
            throw new SamlRequestException("A signed AuthnRequest needs a Destination.", acs, requestId);
        }

        return new ValidatedAuthnRequest(request, app, acs, relayState);
    }

    // Exact matching only. Without an ACS in the request, the default endpoint is used.
    private static string ResolveAcs(AuthnRequestMessage request, AppRegistration app)
    {
        AppAcsEndpoint? endpoint;
        if (request.AcsIndex is { } index)
        {
            endpoint = app.AcsEndpoints.FirstOrDefault(e => e.Index == index)
                ?? throw new SamlRequestException("The AssertionConsumerServiceIndex is not registered for this app.");
        }
        else if (request.AcsUrl is not null)
        {
            endpoint = app.AcsEndpoints.FirstOrDefault(e => string.Equals(e.Location, request.AcsUrl, StringComparison.Ordinal))
                ?? throw new SamlRequestException("The AssertionConsumerServiceURL is not registered for this app.");
        }
        else
        {
            endpoint = app.DefaultAcs;
            if (endpoint is null)
            {
                throw new SamlRequestException("The app has no AssertionConsumerService.");
            }
        }

        if (request.AcsUrl is not null && !string.Equals(request.AcsUrl, endpoint.Location, StringComparison.Ordinal))
        {
            throw new SamlRequestException("The AssertionConsumerServiceURL and index disagree.");
        }

        return endpoint.Location;
    }

    private static List<System.Security.Cryptography.X509Certificates.X509Certificate2> ConfirmedCertificates(AppRegistration app) =>
        app.ConfirmedSigningCertificates
            .Select(der => System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(der))
            .ToList();
}
