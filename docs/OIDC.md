# OIDC Identity Provider

"Sign in with your mail server." Owney can act as an OpenID Connect provider so
external apps authenticate users against their Owney account, and so those apps
can be granted scoped access to Owney's own APIs (mail/JMAP, MCP).

**Status:** authorization-code + PKCE flow, passkey login, refresh-token
rotation, and scope enforcement are implemented, wired into the real binary, and
covered by tests (named below). Default **off** (`[oidc] enabled = false`).

---

## What works today

| Capability | Proven by |
|---|---|
| Discovery + JWKS documents | `oidc_http::discovery_document_is_public_and_well_formed`, `jwks_publishes_one_rs256_key`; live-curled in the lab |
| RS256 signing key: generate, persist, reload, sign→verify | `oidc::keys::tests::*` (round-trips a minted ID token through the published JWKS) |
| Passkey enrollment (bearer-authed, AccountId-keyed) | `oidc_http::enroll_start_*`, `enroll_finish_rejects_garbage_credential` |
| `/authorize` validation, open-redirect guard | `oidc_http::authorize_*` (bad client/redirect → error page, **never** a redirect; bad scope/PKCE → redirect with error) |
| Full ceremony: enroll → login → consent → code → token | `oidc::e2e_tests::full_enroll_login_consent_token_flow` (real software authenticator) |
| Code exchange + PKCE + ID token verification | `oidc::flow_tests::code_exchange_returns_verifiable_id_token_and_access_token`, `pkce_mismatch_is_rejected`, `code_is_single_use` |
| Refresh rotation + reuse-detection (family revoke) | `oidc::flow_tests::refresh_rotation_and_reuse_detection` |
| Scope enforcement (Mail vs MCP), IMAP unaffected | `oidc_http::scoped_token_without_mail_scope_is_forbidden_on_jmap`, `scoped_token_with_mail_scope_passes_auth_on_jmap`, `scoped_token_is_invisible_to_imap_path` |
| Admin CLI (clients, grants, enroll helper) | run live against a temp instance; see "Administration" |

## What is intentionally *not* here yet

- **No dynamic client registration** — clients are created by an admin
  (`admin create-oauth-client`).
- **No consent management UI for end users** — an admin can revoke a grant
  (`admin revoke-oauth-grant`); users cannot yet self-manage from a page.
- **Authorization codes and WebAuthn ceremony state are in-memory** — they live
  in the process (single-instance only) with short TTLs. Refresh tokens, grants,
  and clients *are* persisted in SQLite.
- **No `prompt`/`max_age`/`login_hint` handling, no request objects, no
  front/back-channel logout.**
- **Rotating the signing key** means deleting the key file; there is no
  overlap/rollover window (old tokens stop verifying once the JWKS changes).

---

## Enabling it

```toml
[oidc]
enabled = true
access_token_ttl_secs  = 3600      # 1 hour
id_token_ttl_secs      = 3600
refresh_token_ttl_secs = 2592000   # 30 days
```

`issuer` is your `api.public_url` (or `https://<hostname>` if unset). **WebAuthn
requires a secure context**: production must serve the issuer over HTTPS.
`http://localhost` is treated as secure by browsers, which is why the lab works
over plain HTTP on a localhost-mapped name.

On first start with OIDC enabled, the server generates an RS256 key under
`<data_dir>/oidc/rs256-<kid>.pkcs1.der` (mode 0600) and logs the `kid`.

## Endpoints

| Method | Path | Auth |
|---|---|---|
| GET | `/.well-known/openid-configuration` | public |
| GET | `/oidc/jwks.json` | public |
| GET | `/oidc/enroll` | none (page); the two POSTs below are the boundary |
| POST | `/oidc/enroll/start`, `/oidc/enroll/finish` | Bearer (an app-password token) |
| GET | `/oidc/authorize` | none (starts the browser flow) |
| POST | `/oidc/authorize/login/start`, `/login/finish` | session-bound to the parked request |
| GET/POST | `/oidc/consent` | login-proof marker from the finished assertion |
| POST | `/oidc/token` | client auth (Basic or `client_secret_post`; public = PKCE only) |
| POST | `/oidc/revoke` | client auth |
| GET/POST | `/oidc/userinfo` | Bearer (OIDC access token with `openid`) |

## Scopes

| Scope | Grants |
|---|---|
| `openid` | required; asserts an authentication, releases `sub` |
| `email` | `email` + `email_verified` claims |
| `profile` | `name` claim |
| `offline_access` | a rotating refresh token |
| `owney:mail` | the access token may call JMAP mail/data + push endpoints |
| `owney:mcp` | the access token may call `/mcp` |

Access tokens are opaque `msk_…` strings stored (hashed) in the same
`app_passwords` table as admin tokens, but **scoped** and **expiring**. The
scope-aware HTTP path (`authenticate_scoped`) accepts them; the legacy
`account_by_token` path used by **IMAP LOGIN rejects scoped tokens outright**, so
an OIDC-delegated token can never be used as an IMAP password.

## Security model

- **PKCE S256 is mandatory** on `/authorize`; the code is bound to the client,
  redirect URI, PKCE challenge, nonce, and scopes.
- **Open-redirect guard:** an unknown `client_id` or an unregistered
  `redirect_uri` renders an error *page* and never redirects. Redirect URIs must
  match a client's registered set *exactly*.
- **Refresh reuse detection:** refresh tokens rotate on every use. Presenting an
  already-rotated token revokes the whole family (and its access tokens).
- **Login is a passkey assertion** verified by `webauthn-rs`. A credential is
  only accepted if it belongs to the account the ceremony was started for.

## Administration

```bash
# Register an app. Confidential prints a secret once; public is PKCE-only.
owneyd admin create-oauth-client "My Web App" \
    --redirect-uri https://app.example.com/callback
owneyd admin create-oauth-client "Mobile App" \
    --redirect-uri https://app.example.com/cb --public

owneyd admin oauth-clients                       # list
owneyd admin revoke-oauth-client <client_id>     # disable + kill its tokens

owneyd admin oauth-grants alice@example.com      # what alice authorized
owneyd admin revoke-oauth-grant alice@example.com <client_id>

# Mint a token + print the URL a user visits to enroll a login passkey.
owneyd admin enroll-passkey alice@example.com
```

## Trying it in the lab

`scripts/lab.sh` enables `[oidc]` on both instances. After `lab.sh up`:

```bash
curl -s http://alice.local:8381/.well-known/openid-configuration | jq .
curl -s http://alice.local:8381/oidc/jwks.json | jq '.keys[0].kid'
```

A full browser flow needs a real passkey (the automated equivalent is the
`e2e_tests` software-authenticator test). To enroll interactively, run
`admin enroll-passkey`, open the printed `/oidc/enroll` URL, and paste the token.
