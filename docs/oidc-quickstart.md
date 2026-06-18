# OIDC Local Client Quickstart

This guide is for first-run local evaluation of CairnID as an OpenID Connect provider. It does not claim OpenID certification, production readiness, or suitability for live relying parties.

Use a separate sample relying party (RP) that you run outside this repository. The RP is only a configurable OIDC client. It must support discovery, Authorization Code flow, PKCE `S256`, and a callback at `http://localhost:3000/callback`.

## Local origins

Start CairnID as described in the repository quick start or local Docker Compose docs. The local evaluation origins are:

- API and OIDC issuer: `http://localhost:8080`
- Web login, consent, and admin UI: `http://localhost:5173`
- External sample RP: `http://localhost:3000`

Bootstrap the first administrator at `http://localhost:5173/login`, then open the admin applications area and create an OIDC client for the sample RP.

## Admin client setup

Create a public client first so no local secret is needed.

| Admin field | Value |
| --- | --- |
| Client ID | A stable value such as `local-sample-rp` |
| Client name | Human-readable local RP name |
| Public client | Checked |
| Authorization redirect URIs | `http://localhost:3000/callback` |
| Post-logout redirect URIs | Empty unless the sample RP supports RP-initiated logout |
| Scopes | `openid profile email`; add `groups` only if the RP reads group claims; add `offline_access` only if refresh-token behavior is being evaluated |
| Consent policy | `Required once` unless you intentionally want every authorization to show consent |

Cairn derives these protocol values for the created public client:

- Response type: `code`.
- Grant types: `authorization_code`; `refresh_token` is enabled by the current local client model and is optional to exercise. Refresh tokens are issued only when the authorization request includes `offline_access` and the client allows it.
- Token endpoint auth method: `none` for a public client.
- PKCE: required. The authorization request must send `code_challenge_method=S256`, and the token request must send the matching `code_verifier`.

If the external RP is confidential, leave `Public client` unchecked. Cairn returns the raw `client_secret` once at creation or rotation time. Confidential clients may authenticate at the token endpoint with `client_secret_basic` or `client_secret_post`; `private_key_jwt` is not in scope for this quickstart. Current confidential clients also allow `client_credentials`, but that grant is outside this browser RP flow.

Local redirect URI caveats:

- HTTP redirect URIs are accepted only for `localhost`, `127.0.0.1`, or `[::1]` with a numeric port.
- Remote HTTP redirect URIs are rejected. Use HTTPS outside local loopback evaluation.
- Redirect matching is exact, including path and trailing slash.
- Fragments are not allowed in registered redirect URIs.

## Configure the sample RP

Configure the external sample RP with:

| RP setting | Value |
| --- | --- |
| Issuer or discovery URL | `http://localhost:8080` or `http://localhost:8080/.well-known/openid-configuration` |
| Client ID | `<client-id>` |
| Client secret | Empty for a public client; `<client-secret>` for a confidential client |
| Redirect URI | `http://localhost:3000/callback` |
| Response type | `code` |
| Scope | `openid profile email` for a first pass |
| PKCE | Enabled, method `S256` |
| Token endpoint auth method | `none` for public clients; `client_secret_basic` or `client_secret_post` for confidential clients |

Do not add the sample RP to this repository. Keep its source, dependencies, and secrets outside the CairnID checkout.

## Curl and browser verification checklist

Set the issuer for the shell commands:

```powershell
$env:ISSUER="http://localhost:8080"
```

1. Discovery returns the local issuer and strict code-flow metadata:

```powershell
curl.exe -i -sS "$env:ISSUER/.well-known/openid-configuration"
```

Check for `issuer` equal to `http://localhost:8080`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `response_types_supported` containing only `code`, `code_challenge_methods_supported` containing `S256`, and `token_endpoint_auth_methods_supported` containing `none`, `client_secret_basic`, and `client_secret_post`.

2. JWKS returns public signing keys:

```powershell
curl.exe -i -sS "$env:ISSUER/.well-known/jwks.json"
```

The response should be JSON with a `keys` array. When signing keys are configured, active keys should be public RS256 signing keys and must not expose private key material.

3. Authorization redirects through the browser:

Open this URL after replacing the angle-bracket values:

```text
http://localhost:8080/oauth2/authorize?response_type=code&client_id=<client-id>&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile%20email&state=<state>&nonce=<nonce>&code_challenge=<s256-code-challenge>&code_challenge_method=S256
```

Expected shape:

- Without a Cairn browser session, Cairn redirects to `http://localhost:5173/login?return_to=<encoded-authorize-url>`.
- After login, if consent is required, Cairn redirects to `http://localhost:5173/consent?return_to=<encoded-authorize-url>&client_id=<client-id>&client_name=<client-name>&scopes=<scopes>`.
- After login and consent, Cairn redirects to `http://localhost:3000/callback?code=<authorization-code>&iss=http%3A%2F%2Flocalhost%3A8080&state=<state>`.

4. Token exchange returns OAuth JSON:

For a public client:

```powershell
curl.exe -i -sS -X POST "$env:ISSUER/oauth2/token" `
  -H "Content-Type: application/x-www-form-urlencoded" `
  --data-urlencode "grant_type=authorization_code" `
  --data-urlencode "client_id=<client-id>" `
  --data-urlencode "code=<authorization-code>" `
  --data-urlencode "redirect_uri=http://localhost:3000/callback" `
  --data-urlencode "code_verifier=<pkce-code-verifier>"
```

For a confidential client using `client_secret_basic`, add:

```powershell
  -u "<client-id>:<client-secret>"
```

For `client_secret_post`, send `client_secret=<client-secret>` in the form body instead. A successful authorization-code exchange returns `access_token`, `token_type` set to `Bearer`, `expires_in` set to `900`, `id_token`, and `scope`. It returns `refresh_token` only when the authorization grant included `offline_access`.

5. UserInfo returns scope-gated claims:

```powershell
curl.exe -i -sS "$env:ISSUER/oauth2/userinfo" `
  -H "Authorization: Bearer <access-token>"
```

The access token must be a user token with `openid`. The response includes `sub`; `profile` adds `name`, `email` adds `email` and `email_verified`, and `groups` adds current tenant-scoped group slugs.

## Out of scope

This local quickstart intentionally excludes:

- Implicit and hybrid response types.
- Resource-owner password grants.
- Dynamic client registration.
- General `claims` parameter support. Cairn currently accepts only the narrow Basic OP userinfo `name` essential path used by conformance preparation.
- Request objects through `request` or `request_uri`.
- Production deployment hardening, external HTTPS issuer setup, and OpenID Foundation suite execution.

## Release evidence tie-in

This quickstart helps operators rehearse the same local client fields and endpoint checks that are relevant to Config OP and Basic OP preparation: discovery, JWKS, `code` authorization, PKCE `S256`, token endpoint client authentication, and UserInfo claim gating. It is not conformance evidence. Release evidence still requires the documented OpenID conformance preparation, production-like HTTPS issuer checks, token-free metadata smoke artifacts, and external OpenID Foundation suite results.
