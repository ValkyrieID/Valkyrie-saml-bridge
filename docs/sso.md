# Single sign-on for an app

The bridge signs a user in through the OIDC provider, then posts a signed SAML response to the app. It supports two flows: SP-initiated (the app sends an AuthnRequest) and IdP-initiated (the user starts at `/idp/{slug}`). Diagrams of both flows are on the [Login flows](/flows) page.

## Endpoints

| Path | Method | Purpose |
| --- | --- | --- |
| `/saml/metadata` | GET | The bridge's IdP metadata: entity ID, SSO endpoints, and the signing certificate. Give this to each app. |
| `/saml/sso` | GET (HTTP-Redirect) or POST (HTTP-POST) | Receives the app's AuthnRequest. |
| `/idp/{slug}` | GET | Starts an IdP-initiated sign-in for one app. Put this link in the app's portal or bookmark. |
| `/saml/callback` | GET | The OIDC redirect URI. Users never call it directly. |
| `/healthz` | GET | Liveness check. |

The entity ID is `{SAMLBRIDGE_PUBLIC_URL}/saml/metadata`.

An app's ACS locations must be absolute `https` URLs that use only letters, digits, and `- . _ ~ : / ? # [ ] @ ! $ & ( ) * + = %`. Metadata with any other character, such as `;`, `'`, `"`, or a space, is refused at `apps add`.

## Flow

### SP-initiated

1. The app sends an AuthnRequest to `/saml/sso`. The bridge checks the issuer, the ACS, the Destination (required when the request is signed), the binding, the time window, the signature when required, and that the request ID is new.
2. The bridge redirects the browser to the OIDC provider with `prompt=none`. If there is no session at the provider, it asks again without `prompt`, so the user sees the sign-in page. `ForceAuthn` sends `prompt=login`, and the callback refuses a sign-in whose `auth_time` is older than the login start minus the clock skew. `IsPassive` never shows a sign-in page.
3. The OIDC provider returns the browser to `/saml/callback`. The bridge checks `iss` and `state`, exchanges the code, and validates the ID token. All claims come from the ID token.
4. The bridge posts a signed Response to the ACS. The response contains a signed Assertion. `InResponseTo` is the AuthnRequest ID. The request's `RelayState`, if any, is posted back unchanged. It is not checked against the app's allow-list.

### IdP-initiated

1. The user opens `/idp/{slug}`, optionally with `?RelayState=...`. An unknown slug and a disabled app get the same local error page.
2. The bridge runs the same OIDC steps as SP-initiated, starting with `prompt=none`.
3. The bridge posts a signed Response to the app's default ACS. There is no `InResponseTo`. The ACS, audience, and entity ID come only from the app's stored settings. The default ACS is the endpoint the metadata marks as default, or the lowest index.
4. `RelayState` is sent only when it's on the app's allow-list. Otherwise it's dropped. A second `RelayState` parameter is refused.

An enabled app serves both flows. `apps set --enable` and `apps set --disable` turn both on and off (see [CLI](/cli)).

## What the app receives

- **Subject (NameID):** the claim and format the admin sets with `apps set`. For example, `sub` in `persistent` format is the stable choice.
- **Attributes:** only the ones the admin maps. Each value comes from an ID token claim. `roles` and `groups` produce one value per entry. A missing optional attribute is left out, and a missing required one refuses the login.
- **AuthnContext:** from the `amr` value of the sign-in at the OIDC provider:

  | `amr` | AuthnContextClassRef |
  | --- | --- |
  | `pwd`, or `pwd mfa` (a recovery code) | `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` |
  | `pwd otp mfa` (an authenticator app) | `urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract` |
  | anything else | `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified` |

- **Timing:** the assertion is valid for 2 minutes. `AuthnInstant` is the OIDC `auth_time`.

## Allowed claims

Apps can map any claim name of letters, digits, and underscores, starting with a letter, 1 to 64 characters long. The name must come from the ID token of the OIDC provider. A name the provider doesn't send is handled like any missing claim: a required one refuses the login, and an optional one is left out.

Choosing a claim that users can change (for example `email`) as the NameID creates a new account at the app whenever the value changes. The CLI warns about this.

## Refusals

- **Local error page** (no response is sent anywhere): unknown or disabled app, an ACS or index that isn't registered, a replayed request, a missing or invalid pending login, or a state or `iss` mismatch. The bridge never redirects or posts to an unvalidated URL.
- **SAML error response** to the app's ACS, for SP-initiated logins only, once the ACS is validated. A request that fails a check after that (Destination, binding, IssueInstant, or signature) gets a `Requester` error. This includes a signed request with a forged or invalid signature, which goes to the signing app's ACS and not to the local page. A sign-in that failed at the OIDC provider, an ID token or nonce that fails validation, a `ForceAuthn` sign-in that is too old, or a missing required claim gets a `Responder` error (`AuthnFailed`). An AuthnContext the request asked for and the sign-in doesn't meet gets `NoAuthnContext`. `IsPassive` with no session gets `NoPassive`. An IdP-initiated login has no request to answer, so every refusal in its flow is the local page. Error responses echo the SP's `RelayState` unchanged, the same as a success response. They go only to the validated ACS.

## Signatures

- The bridge signs both the Response and the Assertion with RSA-SHA256.
- An AuthnRequest signature is verified when one is present, and it is required when the app's metadata has `AuthnRequestsSigned="true"`. Only RSA-SHA256 is accepted. For HTTP-Redirect, a query signature is checked over the raw query string. An XML signature on a Redirect request is accepted and verified the same way as on a POST request. When a Redirect request has both, each one must verify. SHA-1 and ECDSA are refused. A signed AuthnRequest needs a Destination, and it must match the bridge's SSO URL. An unsigned one may leave it out.
- The bridge doesn't verify signatures on the app's metadata. Only load metadata from a source you trust, and check the certificate fingerprint before confirming it (see [CLI](/cli)).

## Replay and time windows

- **AuthnRequest IDs:** each ID is accepted once, through the pending login. The callback marks the pending login consumed and keeps the row until it expires, so a repeated AuthnRequest ID is refused for as long as it could be accepted.
- **Assertion IDs:** each assertion gets a new random 128-bit ID. The bridge doesn't keep a list of them. An SP that reuses an assertion is outside the bridge's control, so the SP must enforce its own replay checks.
- **Clock skew:** 1 minute. An AuthnRequest's `IssueInstant` may be up to 5 minutes old, plus the skew, and up to the skew in the future. The window's edge is accepted.
- **Pending login:** 10 minutes. A callback after that is refused. The bridge deletes expired pending logins every 10 minutes.

## Scopes requested from the OIDC provider

The bridge asks the OIDC provider only for the scopes the admin sets for each app with `apps set --scope` (see [CLI](/cli)). A scope name can be any name of 1 to 64 letters, digits, underscores, hyphens, colons, or dots. `openid` is always requested. With no list set, the default is `openid`, plus `profile` for `preferred_username`, `name`, `given_name`, or `family_name`, and `email` for `email` or `email_verified`. `roles` and `groups` are never part of the default.

The bridge doesn't check that a mapped claim's scope is requested. If the provider doesn't put a required claim in the ID token, the login is refused. Give the app the scope each of its claims needs.

## Limits

- **Request size:** a `POST /saml/sso` body larger than 64 KB gets `413 Payload Too Large` and is not parsed.
- **RelayState:** at most 512 characters. A longer SP-initiated RelayState gets the local page. A longer IdP-initiated RelayState is dropped.
- **No rate limit:** the bridge doesn't limit request rates. Put the bridge behind a reverse proxy or firewall that does, if the endpoints are reachable from the internet.

## Limitations

- Single logout isn't supported. Signing out of the OIDC provider doesn't end app sessions, and signing out of an app doesn't end the OIDC session. Use short session lifetimes at the app.
- Metadata is registered from a file and its signature is not verified. Trust comes from the admin confirming the certificate fingerprint.
- Changing an app's metadata needs the app to be removed and added again (see [CLI](/cli#disable-or-remove-an-app)).
