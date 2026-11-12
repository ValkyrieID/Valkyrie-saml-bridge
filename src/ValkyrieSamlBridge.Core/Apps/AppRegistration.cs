namespace ValkyrieSamlBridge.Core.Apps;

// The settings the SAML flows need for one app. The data layer builds these from stored rows, so
// Core never touches the database.
public sealed record AppRegistration(
    string Slug,
    string EntityId,
    bool Enabled,
    bool AuthnRequestsSigned,
    IReadOnlyList<AppAcsEndpoint> AcsEndpoints,
    IReadOnlyList<byte[]> ConfirmedSigningCertificates,
    NameIdSetting? NameId,
    IReadOnlyList<AttributeSetting> Attributes,
    IReadOnlyList<string> RelayStates,
    string? RequestedScopes = null)
{
    // The ACS used when the request names none, and for unsolicited responses: the
    // endpoint marked default, otherwise the lowest index. Null when the app has no endpoint.
    public AppAcsEndpoint? DefaultAcs => AcsEndpoints.FirstOrDefault(e => e.IsDefault) ?? AcsEndpoints.MinBy(e => e.Index);
}

public sealed record AppAcsEndpoint(string Location, int Index, bool IsDefault);

public sealed record NameIdSetting(string Claim, string Format);

public sealed record AttributeSetting(string Name, string Claim, bool Required);
