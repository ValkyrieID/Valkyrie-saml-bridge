namespace ValkyrieSamlBridge.Core.Configuration;

// Client settings for the bridge's confidential OIDC client.
// The client secret arrives decrypted; it is never logged or returned in an error.
public sealed record OidcClientOptions(Uri Issuer, string ClientId, string ClientSecret, Uri RedirectUri)
{
    public void Validate()
    {
        if (Issuer.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(Issuer.Query) || !string.IsNullOrEmpty(Issuer.Fragment))
        {
            // OIDC Core §2 requires an https issuer, with no query or fragment.
            throw new InvalidOperationException("The OIDC issuer must be an https URL without query or fragment.");
        }

        if (string.IsNullOrWhiteSpace(ClientId) || string.IsNullOrWhiteSpace(ClientSecret))
        {
            throw new InvalidOperationException("The OIDC client id and secret must be set.");
        }

        if (RedirectUri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(RedirectUri.Query) || !string.IsNullOrEmpty(RedirectUri.Fragment))
        {
            throw new InvalidOperationException("The redirect URI must be an https URL without query or fragment.");
        }
    }
}
