# Login flows

These diagrams show how a sign-in moves through the bridge. The detailed rules are in [SSO](/sso).

## Components

```mermaid
flowchart LR
  user(["User browser"])
  app["SAML app (SP)"]
  bridge["valkyrie-saml-bridge"]
  oidc["OIDC provider<br/>(for example ValkyrieID)"]
  cli["admin CLI (same assembly as the bridge)"]
  db[("SQLite")]

  user -->|"open app"| app
  app <-->|"SAML AuthnRequest / Response<br/>(through the browser)"| bridge
  user <-->|"OIDC redirects"| oidc
  bridge <-->|"code + PKCE, ID token"| oidc
  bridge --- db
  cli --- db
```

The bridge is the only SAML party the app talks to. The user's OIDC session stays at the provider. The app never sees the provider, and the provider never sees the app.

## SP-initiated sign-in

The user starts at the app. The app sends an AuthnRequest.

```mermaid
sequenceDiagram
  autonumber
  actor U as User browser
  participant SP as SAML app (SP)
  participant B as Bridge
  participant O as OIDC provider

  U->>SP: Open a protected page
  SP-->>U: AuthnRequest (HTTP-Redirect or HTTP-POST)
  U->>B: GET or POST /saml/sso
  B->>B: Check issuer, ACS, Destination, signature, IssueInstant, request ID
  B->>B: Store pending login (cookie, 10 minutes)
  B-->>U: 302 to OIDC /authorize (prompt=none, PKCE S256, state, nonce)
  U->>O: /authorize
  alt Session exists at the provider
    O-->>U: 302 /saml/callback?code&state&iss
  else No session (login_required)
    O-->>U: 302 /saml/callback?error=login_required
    U->>B: GET /saml/callback
    B-->>U: 302 to OIDC /authorize (no prompt, new state)
    U->>O: Sign-in page
    O-->>U: 302 /saml/callback?code&state&iss
  end
  U->>B: GET /saml/callback
  B->>B: Take the pending login (single use, marked consumed), check state and iss
  B->>O: POST /token (code, PKCE verifier)
  O-->>B: ID token
  B->>B: Verify ID token (signature, iss, aud, nonce, exp, auth_time)
  B->>B: Build the claims and the signed Response
  B-->>U: Auto-submit form with SAMLResponse (InResponseTo = request ID)
  U->>SP: POST to the ACS
  SP-->>U: Signed in
```

`ForceAuthn` sends `prompt=login` instead of `prompt=none`. `IsPassive` never shows the sign-in page, and it gets a `NoPassive` status when there is no session. The callback refuses a `ForceAuthn` sign-in whose `auth_time` is older than the login start minus the clock skew, and sends an `AuthnFailed` error to the ACS.

A pending login is single use. The callback marks it consumed and keeps the row until it expires, so a repeated AuthnRequest ID is refused. A pending login lasts 10 minutes, and a background task deletes expired pending logins every 10 minutes.

For SP-initiated logins, the SP's `RelayState` is echoed unchanged, including in SAML error responses. The app's RelayState allow-list applies only to IdP-initiated logins.

## IdP-initiated sign-in

The user starts at the bridge, from a link such as `https://sso.example.test/idp/payroll`. No AuthnRequest exists, so the response has no `InResponseTo`.

```mermaid
sequenceDiagram
  autonumber
  actor U as User browser
  participant B as Bridge
  participant O as OIDC provider
  participant SP as SAML app (ACS)

  U->>B: GET /idp/payroll?RelayState=...
  alt Unknown slug or disabled app
    B-->>U: Local error page (same for both)
  else Allowed
    B->>B: Store pending login (flow = idp-initiated)
    B-->>U: 302 to OIDC /authorize (prompt=none)
    U->>O: /authorize
    O-->>U: 302 /saml/callback (code or login_required)
    U->>B: GET /saml/callback
    B->>O: POST /token
    O-->>B: ID token
    B->>B: Verify ID token, build signed Response from stored app settings
    B->>B: RelayState kept only if on the app's allow-list
    B-->>U: Auto-submit form with SAMLResponse to the default ACS
    U->>SP: POST to the ACS
    SP-->>U: Signed in
  end
```

The ACS, audience, and entity ID come only from the app's stored settings. The request can't choose them. Every refusal in this flow shows the local error page, because there is no SAML request to answer.

## Deciding on an AuthnRequest

```mermaid
flowchart TD
  start(["AuthnRequest arrives at /saml/sso"]) --> size{"POST: body 64 KB or less?"}
  size -- no --> r413["413, not parsed"]
  size -- "yes, or GET" --> app{"Issuer is an enabled app?"}
  app -- no --> local["Local error page"]
  app -- yes --> acs{"ACS or index matches<br/>a registered endpoint?"}
  acs -- no --> local
  acs -- yes --> dest{"Destination absent,<br/>or exact match?"}
  dest -- no --> samlerr["SAML Requester error to ACS"]
  dest -- yes --> time{"IssueInstant within<br/>5 minutes plus skew?"}
  time -- no --> samlerr
  time -- yes --> sig{"Signature valid, or absent<br/>and not required?"}
  sig -- no --> samlerr
  sig -- yes --> id{"Request ID not seen<br/>in a pending or consumed login?"}
  id -- no --> local
  id -- yes --> ok(["Store pending login, start OIDC"])
```

Refusals go to the local page until the ACS has been validated. After that, a refusal is a SAML error response to the ACS, for SP-initiated logins only (see [SSO](/sso#refusals)).

## Key rotation

Rotation changes the certificate SPs must trust. The old certificate stays published until every SP has the new one.

```mermaid
flowchart LR
  a["keys rotate<br/>(new key active, old key inactive)"] --> b["Restart the bridge<br/>(new key signs)"]
  b --> c["/saml/metadata lists<br/>new and old certificates"]
  c --> d["Give the new certificate<br/>to each SP"]
  d --> e{"Every SP<br/>trusts it?"}
  e -- no --> d
  e -- yes --> f["keys retire<br/>(old key deleted)"]
  f --> g["Restart the bridge<br/>(old certificate leaves metadata)"]
```

See [CLI: Rotate the signing key](/cli#rotate-the-signing-key) for the commands.
