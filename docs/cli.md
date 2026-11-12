# CLI

The `admin` command manages registered apps and signing keys. Run it from the directory that holds the database, or set `SAMLBRIDGE_DATABASE`. Bridge settings come only from environment variables. Apps and keys live in SQLite.

In the Docker image, `admin` is on the PATH and runs the bridge's CLI, for example `docker compose exec saml-bridge admin apps list`. Outside Docker, the same commands run as `dotnet ValkyrieSamlBridge.Web.dll apps list`, with the same arguments. The examples below use `admin`.

## Register an app

```sh
admin apps add --slug payroll --metadata payroll.xml
```

- `--slug` and `--metadata` are required. The slug uses 1 to 64 lowercase letters, digits, and inner hyphens.
- The metadata is a file. Download it yourself from a source you trust. The bridge doesn't fetch URLs and doesn't verify metadata signatures.
- The command prints the SHA-256 fingerprint of each signing certificate. Check those fingerprints against the app vendor's documentation before confirming them.

Metadata is refused when it:

- contains a DTD or external entity,
- is larger than 1 MB or nested more than 32 levels deep,
- has no HTTP-POST ACS endpoint, or an HTTP-POST ACS whose location isn't an absolute `https` URL,
- has an ACS location with a character outside letters, digits, and `- . _ ~ : / ? # [ ] @ ! $ & ( ) * + = %` (for example `;`, `'`, `"`, or a space),
- has no signing certificate.

ACS endpoints that use another binding are skipped.

To change an app's metadata, remove the app and add it again. Then set its sign-in settings again (see [Set the sign-in settings](#set-the-sign-in-settings)).

## Confirm the certificates

```sh
admin apps confirm payroll --fingerprint AB:CD:... --fingerprint EF:01:...
```

Give every fingerprint shown by `apps add`. If the set doesn't match the stored certificates exactly, nothing is confirmed. A certificate that isn't confirmed can't be used to verify AuthnRequests, and the app can't be enabled.

## Set the sign-in settings

```sh
admin apps set payroll --nameid-claim sub --nameid-format persistent --enable
admin apps set payroll --attribute "urn:oid:0.9.2342.19200300.100.1.3=email,required" --attribute "groups=groups"
admin apps set payroll --relay-state /dashboard --relay-state /reports
admin apps set payroll --disable
```

- `--nameid-claim` and `--nameid-format` (`persistent`, `transient`, `unspecified`, or `email`) set the subject. Both are needed before the app can sign in. The claim is read from the OIDC ID token.
- `--attribute name=claim[,required]` maps a SAML attribute to an ID token claim. Give it once per attribute. Each use replaces the whole attribute list. `required` refuses the login when the claim is missing. Names must be unique, ignoring case. Otherwise nothing is saved.
- `--relay-state` lists the RelayState values the app may use for IdP-initiated logins. Each use replaces the list. For IdP-initiated logins, any other RelayState is dropped. SP-initiated logins echo the SP's RelayState unchanged, so the list doesn't apply to them.
- `--scope` lists the scopes the bridge requests from the OIDC provider for this app. A scope name can be any name of 1 to 64 letters, digits, underscores, hyphens, colons, or dots. Each use replaces the list. `openid` is always requested. Without `--scope`, the app gets `openid`, plus `profile` and `email` as its claims need. `roles` and `groups` are requested only when named here. `--default-scopes` returns the app to the default list.
- `--enable` and `--disable` turn SSO on or off for the app. An enabled app serves both SP-initiated SSO and sign-in at `/idp/<slug>`. `--enable` is refused, and nothing is saved, unless the app has a default ACS, `--nameid-claim` and `--nameid-format` set, and every signing certificate confirmed. `--disable` is always allowed.
- Claim names must be letters, digits, and underscores, starting with a letter, 1 to 64 characters. Other names are refused.

## Disable or remove an app

```sh
admin apps disable payroll
admin apps remove payroll
```

- `apps disable <slug>` is the same as `apps set <slug> --disable`.
- `apps remove <slug>` deletes the app: its ACS endpoints, certificates, attribute mappings, and RelayState values. Logins in progress for the app are deleted too, so a callback for them is refused.
- Removing is permanent. To keep the app but stop SSO, disable it instead.
- An unknown slug fails with exit code 1 and changes nothing. The slug must match exactly, so `Payroll` or a slug with spaces doesn't match `payroll`.
- After a removal, the same slug can be registered again with `apps add`.

## Inspect

```sh
admin apps list
admin apps show payroll
```

## Rotate the signing key

```sh
admin keys rotate
# restart the bridge
admin keys retire
# restart the bridge
```

1. `keys rotate` creates a new signing key and makes it the only active key. The previous key stays in the database, inactive. The command prints the new key's SHA-256 fingerprint. It refuses, and changes nothing, unless exactly one key is active.
2. **Restart the bridge.** The running bridge keeps the key it loaded at startup, so it keeps signing with the old key until it restarts. The new key signs after the restart.
3. After the restart, `/saml/metadata` lists the new certificate first and the old one after it, as two signing `KeyDescriptor`s. Check that both certificates are there.
4. Give the new certificate to each SP, and wait until every SP trusts it. The old certificate stays published until you retire it, so an SP can switch over without a gap.
5. `keys retire` deletes every inactive key. It never deletes the active key. It refuses, and changes nothing, when there is no inactive key, so a second retire does nothing. Restart the bridge afterwards, so `/saml/metadata` stops listing the retired certificate.

The bridge loads every stored certificate at startup, but it signs only with the active key. It reads only the public certificate of an inactive key, so the old private key is never decrypted.

- `keys rotate` and `keys retire` read `SAMLBRIDGE_MASTER_KEY` from the environment and use `SAMLBRIDGE_DATABASE` like the other commands. `keys rotate` also reads `SAMLBRIDGE_PUBLIC_URL` for the certificate's name.
- They don't create the database. Start the bridge once first.
- The bridge refuses to start when more than one key is active, or when keys are stored and none is active. It never picks a key. The CLI doesn't repair this state, so fix the `SigningKeys` table with a backup in hand, or restore a backup.

## Settings

The `admin` command reads its settings from environment variables only, the same source as the web host, so every command opens the same database as the running bridge. It never reads `appsettings*.json`, and it doesn't accept settings as command-line arguments. `SAMLBRIDGE_MASTER_KEY` and `SAMLBRIDGE_OIDC_CLIENT_SECRET` are refused if they're passed as an argument, and the command never prints them. `SAMLBRIDGE_DATABASE` defaults to `saml-bridge.db` in the working directory when it isn't set. See [Configuration](/configuration).
