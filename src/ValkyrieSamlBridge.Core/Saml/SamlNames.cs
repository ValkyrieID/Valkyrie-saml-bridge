namespace ValkyrieSamlBridge.Core.Saml;

public static class SamlNames
{
    public const string ProtocolNs = "urn:oasis:names:tc:SAML:2.0:protocol";
    public const string AssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    public const string MetadataNs = "urn:oasis:names:tc:SAML:2.0:metadata";
    public const string DsigNs = "http://www.w3.org/2000/09/xmldsig#";

    public const string HttpPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public const string HttpRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

    public const string BearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public const string BasicNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

    public const string StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public const string StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester";
    public const string StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    public const string StatusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
    public const string StatusNoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
    public const string StatusNoAuthnContext = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";

    public const string NameIdUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    public const string NameIdEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    public const string NameIdPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    public const string NameIdTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    public static readonly string[] SupportedNameIdFormats = [NameIdUnspecified, NameIdEmail, NameIdPersistent, NameIdTransient];

    public const string AcPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    public const string AcMobileTwoFactor = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";
    public const string AcUnspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
}
