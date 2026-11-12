namespace ValkyrieSamlBridge.Core.Configuration;

// Parses the bridge's environment settings. The web host and the CLI both use these
// methods, so both apply the same rules. Messages name the variable but never echo its value.
public static class BridgeSettings
{
    public const string PublicUrlVariable = "SAMLBRIDGE_PUBLIC_URL";
    public const string IssuerVariable = "SAMLBRIDGE_OIDC_ISSUER";
    public const string ClientIdVariable = "SAMLBRIDGE_OIDC_CLIENT_ID";
    public const string ClientSecretVariable = "SAMLBRIDGE_OIDC_CLIENT_SECRET";
    public const string DatabaseVariable = "SAMLBRIDGE_DATABASE";
    public const string DefaultDatabase = "saml-bridge.db";

    public static BridgeOptions ParseBridge(string? publicUrl)
    {
        if (publicUrl is null)
        {
            throw new InvalidOperationException($"{PublicUrlVariable} must be set to the bridge's public https origin.");
        }
        if (!Uri.TryCreate(publicUrl, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"{PublicUrlVariable} must be an absolute URL.");
        }

        var bridge = BridgeOptions.Create(uri);
        bridge.Validate();
        return bridge;
    }

    public static OidcClientOptions ParseOidc(string? issuer, string? clientId, string? clientSecret, Uri redirectUri)
    {
        if (string.IsNullOrEmpty(issuer))
        {
            throw new InvalidOperationException($"{IssuerVariable} must be set.");
        }
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
        {
            throw new InvalidOperationException($"{IssuerVariable} must be an absolute URL.");
        }

        var oidc = new OidcClientOptions(issuerUri, clientId ?? string.Empty, clientSecret ?? string.Empty, redirectUri);
        oidc.Validate();
        return oidc;
    }

    public static string ResolveDatabasePath(string? value) => string.IsNullOrWhiteSpace(value) ? DefaultDatabase : value;

    // These readers are the one place the web host and the CLI
    // read each variable, so both use the same names.
    public static string? ReadPublicUrl() => Environment.GetEnvironmentVariable(PublicUrlVariable);

    public static string? ReadIssuer() => Environment.GetEnvironmentVariable(IssuerVariable);

    public static string? ReadClientId() => Environment.GetEnvironmentVariable(ClientIdVariable);

    public static string? ReadDatabase() => Environment.GetEnvironmentVariable(DatabaseVariable);

    // The client secret is read from the environment only, by both hosts.
    // Configuration sources such as appsettings*.json and command-line arguments are never consulted for it.
    public static string? ReadClientSecret() => Environment.GetEnvironmentVariable(ClientSecretVariable);
}
