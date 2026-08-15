# Keycloak auth-proxy and master-realm probes

Use when a target exposes Keycloak under a path like `/keycloak/` and an app-local proxy endpoint like `/authx/oidc/keycloak/auth`.

## Auth proxy vs direct client behavior

Some deployments create the OIDC request through an app proxy that sets `state` and PKCE cookies, then redirects into Keycloak. Directly calling the Keycloak auth endpoint with the visible `client_id` can return `Client not found` or other 400s because the public flow depends on proxy-created context.

Test both layers separately:

```bash
# Proxy entrypoint — observe generated state, PKCE, and fixed redirect_uri
curl -sk -D - 'https://TARGET/authx/oidc/keycloak/auth?redir_url=https%3A%2F%2FTARGET%2F'

# Direct Keycloak — useful but not authoritative if proxy owns flow state
curl -sk -D - 'https://TARGET/keycloak/realms/REALM/protocol/openid-connect/auth?client_id=CLIENT&redirect_uri=https%3A%2F%2FTARGET%2Fcallback&response_type=code&scope=openid&state=test'
```

If the proxy always sets a fixed Keycloak `redirect_uri` such as `/authx/login/keycloak`, external `redir_url` values may be stored only in `state`. That is not an open redirect by itself. To validate impact, you need a completed login/callback or valid authorization code showing the post-auth redirect honors attacker-controlled state.

## Redirect validation interpretation

- Proxy returns `302` to Keycloak with fixed `redirect_uri` despite `redir_url=https://evil.example` → no direct OAuth code theft yet; continue only if post-auth state redirects externally.
- Direct Keycloak rejects arbitrary `redirect_uri` with `400` → good sign, but inconclusive if the app uses a proxy flow.
- PKCE method in generated proxy URL is `S256` → proxy resists trivial plain-downgrade unless you can replace the proxy-generated request while preserving cookies/state.

## Master realm exposure

Many Keycloak deployments expose `/keycloak/realms/master` and its `.well-known/openid-configuration` publicly. This is high-signal recon, not a finding by itself.

Probe safely:

```bash
BASE=https://TARGET/keycloak/realms/master
curl -sk "$BASE" | python3 -m json.tool
curl -sk "$BASE/.well-known/openid-configuration" | python3 -m json.tool
curl -sk -X POST "$BASE/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin'
```

Interpretation:

- `invalid_grant` for `admin-cli` ROPC means the client accepted the password-grant path but credentials are wrong. It is not default-credential success and not reportable alone.
- `unauthorized_client` means the client exists but that grant is disabled.
- Default credentials failing is a negative result; do not continue brute forcing without explicit authorization.
- Public admin console HTML with `/admin/...` APIs returning `401` is expected access control, not a finding.

## Reportability

Report only if one of these is proven:

- valid credentials/default creds/token mint;
- unauthenticated admin API read/write;
- dynamic registration bypass/SSRF;
- post-auth open redirect/code theft through proxy state;
- token exchange/CIBA/device flow usable by a public or weak client;
- source maps/JS leak a real client secret or privileged client ID.
