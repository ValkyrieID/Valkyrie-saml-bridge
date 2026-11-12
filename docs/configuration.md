# Configuration

The bridge reads all of its settings from environment variables only. The web host and every `admin` command use the same source. `appsettings*.json` files and command-line arguments are never read. Two of the settings are secrets and must be set in the environment, never on the command line: the master key and the client secret. Nothing is read from request headers. The web host refuses to start if a required value is missing or invalid.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SAMLBRIDGE_MASTER_KEY` | yes | Base64 of 32 random bytes. Encrypts the signing key. Generate one with `openssl rand -base64 32`. Keep it out of the database and out of source control. |
| `SAMLBRIDGE_PUBLIC_URL` | yes | The bridge's public origin, for example `https://sso.example.test`. Must be `https`, with no path, query, or fragment. It sets the issuer, the entity ID, and every endpoint URL. |
| `SAMLBRIDGE_OIDC_ISSUER` | yes | The issuer URL of the OIDC provider, an `https` URL with no query or fragment. |
| `SAMLBRIDGE_OIDC_CLIENT_ID` | yes | The client ID of the bridge's confidential client at the OIDC provider. |
| `SAMLBRIDGE_OIDC_CLIENT_SECRET` | yes | The client secret of that client. It is not stored in the database and is never logged. |
| `SAMLBRIDGE_DATABASE` | no | Path to the SQLite file. `apps` and the web host use the same file. Defaults to `saml-bridge.db` in the current working directory. |
| `ASPNETCORE_URLS` | no | The address the web host listens on, for example `http://+:8080`. |

The master key and the client secret are refused when they are passed as a command-line argument, so `admin` exits with an error and reads nothing. Prefer a secret store or an `--env-file` kept out of version control to pass them to the process.

## Startup

On start, the web host:

1. applies the SQLite migrations,
2. loads the bridge signing key, or creates one on first start (RSA-2048, self-signed, valid for five years), and stores its private key encrypted with the master key. Exactly one key must be active. Otherwise the bridge refuses to start. The key lifecycle is in [Rotate the signing key](/cli#rotate-the-signing-key).

The OIDC redirect URI is `{SAMLBRIDGE_PUBLIC_URL}/saml/callback`. Register exactly that URI for the client at the OIDC provider.

## OIDC client

Register the bridge as a confidential client at the OIDC provider:

- **Redirect URI:** `{SAMLBRIDGE_PUBLIC_URL}/saml/callback`, exact match.
- **Grant:** authorization code, with PKCE (`S256`).
- **Scopes:** the bridge requests `openid` plus the scopes set for each app with `apps set --scope` (see [SSO](/sso#scopes-requested-from-the-oidc-provider)). The provider must allow each scope an app uses for this client, or the claims won't be issued.

The bridge checks the provider's discovery document when it starts, and again at each login. A provider that can't be reached, or that fails one of these rules, stops the bridge from starting. The same rules are checked at each login, along with the callback response, and a login is refused when any of them fails:

- The discovery issuer equals `SAMLBRIDGE_OIDC_ISSUER`.
- `code` is in `response_types_supported`.
- `S256` is in `code_challenge_methods_supported`.
- The ID token signing algorithms are `RS256` and/or `ES256`, intersected with `id_token_signing_alg_values_supported`. The intersection must not be empty. `none` and `HS*` are never used.
- The authorization response carries `iss`, and it matches the issuer.
- The ID token carries `auth_time`.
- Token endpoint authentication is `client_secret_basic` by default. `client_secret_post` is used only when the provider advertises it. A provider that advertises neither method is refused. An empty list counts as absent.

### Example: ValkyrieID

ValkyrieID is one OIDC provider that works with the bridge. Its settings are the three OIDC variables. Replace the placeholders with your values:

```sh
SAMLBRIDGE_OIDC_ISSUER=https://valkyrie.example.test
SAMLBRIDGE_OIDC_CLIENT_ID=<client-id>
SAMLBRIDGE_OIDC_CLIENT_SECRET=<client-secret>
```

Allow the scopes the apps need for this client: `openid` for every login, and `profile`, `email`, `roles`, or `groups` only when an app's claims need them.

The master key is not stored in the database. Losing it makes the encrypted signing keys unrecoverable, including any inactive key not yet retired. The client secret is not encrypted by the master key; it is read from the environment only.
