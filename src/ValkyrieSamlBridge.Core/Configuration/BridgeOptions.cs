namespace ValkyrieSamlBridge.Core.Configuration;

// Public settings of the bridge. The public URL is the only source of the issuer, entity ID, and
// endpoint URLs; request headers are never used.
public sealed record BridgeOptions(Uri PublicUrl, TimeSpan AssertionLifetime, TimeSpan ClockSkew, TimeSpan PendingLoginLifetime)
{
    public const string SsoPath = "/saml/sso";
    public const string CallbackPath = "/saml/callback";
    public const string MetadataPath = "/saml/metadata";
    public const string IdpPathPrefix = "/idp/";

    // The largest AuthnRequest form accepted by POST /saml/sso (fail closed on oversized input).
    public const int MaxSsoRequestBytes = 64 * 1024;

    public const int MaxRelayStateLength = 512;

    // An AuthnRequest's IssueInstant may be this old, plus the clock skew. Not configurable.
    public static readonly TimeSpan AuthnRequestMaxAge = TimeSpan.FromMinutes(5);

    public static BridgeOptions Create(Uri publicUrl) => new(
        publicUrl,
        AssertionLifetime: TimeSpan.FromMinutes(2),
        ClockSkew: TimeSpan.FromMinutes(1),
        PendingLoginLifetime: TimeSpan.FromMinutes(10));

    public string EntityId => Endpoint(MetadataPath);

    public string SsoUrl => Endpoint(SsoPath);

    public string CallbackUrl => Endpoint(CallbackPath);

    public void Validate()
    {
        if (PublicUrl.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(PublicUrl.Query) || !string.IsNullOrEmpty(PublicUrl.Fragment) || PublicUrl.AbsolutePath != "/")
        {
            throw new InvalidOperationException("SAMLBRIDGE_PUBLIC_URL must be an https origin, such as https://sso.example.test, with no path, query, or fragment.");
        }
        if (AssertionLifetime <= TimeSpan.Zero || ClockSkew < TimeSpan.Zero || PendingLoginLifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("Timing settings must be positive, and the clock skew must not be negative.");
        }
    }

    private string Endpoint(string path) => $"{PublicUrl.AbsoluteUri.TrimEnd('/')}{path}";
}
