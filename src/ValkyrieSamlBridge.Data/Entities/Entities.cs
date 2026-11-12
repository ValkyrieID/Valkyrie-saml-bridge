namespace ValkyrieSamlBridge.Data.Entities;

public static class LoginFlows
{
    public const string SpInitiated = "sp-initiated";
    public const string IdpInitiated = "idp-initiated";
}

public sealed class SamlApp
{
    public int Id { get; set; }
    public required string Slug { get; set; }
    public required string EntityId { get; set; }
    public required string MetadataSource { get; set; }
    public DateTimeOffset RegisteredAt { get; set; }
    public bool Enabled { get; set; }
    // From the SP metadata. When true, the bridge refuses unsigned AuthnRequests.
    public bool AuthnRequestsSigned { get; set; }
    // Null until the admin sets it. Without a NameID claim the app can't log in.
    public string? NameIdClaim { get; set; }
    public string? NameIdFormat { get; set; }
    // Space-separated scopes the bridge requests for this app, besides openid. Null means the default.
    public string? RequestedScopes { get; set; }
    public List<SamlAppEndpoint> AcsEndpoints { get; set; } = [];
    public List<SamlAppCertificate> Certificates { get; set; } = [];
    public List<SamlAppClaimMapping> Attributes { get; set; } = [];
    public List<SamlAppRelayState> RelayStates { get; set; } = [];
}

public sealed class SamlAppEndpoint
{
    public int Id { get; set; }
    public int SamlAppId { get; set; }
    public required string Location { get; set; }
    public int Index { get; set; }
    public bool IsDefault { get; set; }
}

public sealed class SamlAppCertificate
{
    public int Id { get; set; }
    public int SamlAppId { get; set; }
    public required string Fingerprint { get; set; }
    public required byte[] Der { get; set; }
    public bool Confirmed { get; set; }
    public DateTimeOffset? ConfirmedAt { get; set; }
}

public sealed class SamlAppClaimMapping
{
    public int Id { get; set; }
    public int SamlAppId { get; set; }
    public required string Name { get; set; }
    public required string Claim { get; set; }
    public bool Required { get; set; }
}

public sealed class SamlAppRelayState
{
    public int Id { get; set; }
    public int SamlAppId { get; set; }
    public required string Value { get; set; }
}

// A login in progress between the AuthnRequest and the OIDC callback. Single use: the callback marks it
// Consumed and keeps the row until ExpiresAt, so its AuthnRequest ID stays blocked.
public sealed class PendingLogin
{
    public required string Id { get; set; }
    public bool Consumed { get; set; }
    // One of LoginFlows. Decides whether the callback can send a SAML error to the ACS.
    public string Flow { get; set; } = LoginFlows.SpInitiated;
    public required string AppEntityId { get; set; }
    public required string AcsUrl { get; set; }
    public string? RequestId { get; set; }
    public string? RelayState { get; set; }
    public required string OidcState { get; set; }
    public required string Nonce { get; set; }
    public required string CodeVerifier { get; set; }
    // True until the bridge has retried without prompt=none.
    public bool SilentAttemptPending { get; set; }
    public bool IsPassive { get; set; }
    public bool ForceAuthn { get; set; }
    // Requested AuthnContextClassRefs, one per line, plus the comparison type.
    public string RequestedClasses { get; set; } = string.Empty;
    public string? RequestedComparison { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    // Unix milliseconds. SQLite can't translate DateTimeOffset comparisons in queries, so expiry is compared as a number.
    public long ExpiresAtUnixMs { get; set; }
}

public sealed class SigningKey
{
    public int Id { get; set; }
    public required string KeyId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public bool Active { get; set; }
    // PKCS#8 private key, encrypted with the master key (context "signing-key").
    public required byte[] EncryptedPrivateKey { get; set; }
    public required byte[] CertificateDer { get; set; }
}


