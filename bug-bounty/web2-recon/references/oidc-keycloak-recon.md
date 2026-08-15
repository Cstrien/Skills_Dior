# OIDC / Keycloak First-Look Recon

Session-derived recon pattern for targets that redirect to a Keycloak (or
compatible) OIDC identity provider. One `curl` call to the discovery document
reveals the entire IdP configuration — grant types, endpoints, signing
algorithms, dynamic registration state, and supported flows.

## 1. Two requests that map the IdP

```bash
REALM=prod-realm
BASE=https://target.example

# OIDC discovery → all endpoints, grant_types_supported, scopes, response modes
curl -sk "$BASE/realms/$REALM/.well-known/openid-configuration" | python3 -m json.tool

# Realm config → public_key, token-service, account-service, tokens-not-before
curl -sk "$BASE/realms/$REALM" | python3 -m json.tool
```

## 2. High-signal fields in the discovery document

| Field | What it tells you | Why it matters |
|---|---|---|
| `grant_types_supported` | List of allowed OAuth grants | If `password` (ROPC) is listed, the token endpoint accepts username/password directly — possible brute-force surface, 2FA bypass candidate |
| `registration_endpoint` | Dynamic Client Registration URL | If present, DCR is enabled; test whether policy blocks untrusted hosts |
| `device_authorization_endpoint` | Device code flow URL | Device flow may have weaker rate limits or no CSRF |
| `backchannel_authentication_endpoint` | CIBA flow URL | CIBA may allow cross-device auth without user presence |
| `token_endpoint_auth_methods_supported` | Auth methods for token endpoint | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth` |
| `code_challenge_methods_supported` | PKCE methods | If `plain` is listed, PKCE can be downgraded |
| `introspection_endpoint` | Token introspection | May leak token metadata if callable without auth |
| `revocation_endpoint` | Token revocation | Test if tokens can be revoked for other users |
| `end_session_endpoint` | Logout URL | Open redirect candidate via `post_logout_redirect_uri` |
| `check_session_iframe` | Session status iframe | Clickjacking / session-status leak |
| `id_token_signing_alg_values_supported` | Signing algorithms | If `HS256` is listed, algorithm confusion attacks may apply |
| `tls_client_certificate_bound_access_tokens` | mTLS token binding | If false, tokens are bearer-only (no client cert binding) |

## 3. Quick probes after discovery

### ROPC (password grant) check

If `password` is in `grant_types_supported`, test whether the token endpoint
accepts credentials:

```python
import urllib.request, urllib.error, ssl, urllib.parse
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
data = urllib.parse.urlencode({
    'grant_type': 'password', 'username': 'test@test.com',
    'password': 'test', 'client_id': 'neon-console'
}).encode()
req = urllib.request.Request(
    'https://target.example/realms/prod-realm/protocol/openid-connect/token',
    data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
try:
    r = urllib.request.urlopen(req, timeout=10, context=ctx)
    print('Status:', r.status, r.read(500).decode())
except urllib.error.HTTPError as e:
    print('Status:', e.code, e.read(500).decode('utf-8','replace'))
# 'invalid_grant' = ROPC is enabled (credentials validated, just wrong)
# 'unsupported_grant_type' = ROPC is disabled
```

**Key distinction:**
- `invalid_grant` / `Invalid user credentials` → ROPC is ENABLED (accepts username+password, just got wrong ones)
- `unsupported_grant_type` → ROPC is disabled (grant type not registered for this client)

If ROPC is enabled, hand off to `oauth-pentest` → Section 15 (ROPC 2FA bypass) and rate-limit testing.

### Dynamic Client Registration check

```python
import urllib.request, urllib.error, ssl, json
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
data = json.dumps({"redirect_uris": ["https://example.com/callback"]}).encode()
req = urllib.request.Request(
    'https://target.example/realms/prod-realm/clients-registrations/openid-connect',
    data=data, headers={'Content-Type': 'application/json'})
try:
    r = urllib.request.urlopen(req, timeout=10, context=ctx)
    print('Status:', r.status, r.read(500).decode())
except urllib.error.HTTPError as e:
    print('Status:', e.code, e.read(500).decode('utf-8','replace'))
# 403 'insufficient_scope' + 'Trusted Hosts' policy = DCR enabled but IP-restricted
# 201 = DCR open (can register arbitrary OAuth clients)
# 400 'invalid_client_metadata' = DCR enabled, validates client metadata
```

**Keycloak DCR policy responses:**
- `403 insufficient_scope` + `Policy 'Trusted Hosts' rejected` → DCR is enabled but restricted to trusted hosts/IPs. Not exploitable from external, but confirms the endpoint exists.
- `201 Created` with client_id/secret → DCR is open. Can register arbitrary clients → redirect_uri abuse, impersonation.
- `400 invalid_client_metadata` → DCR is enabled, validates metadata. Try without `client_id` field (let Keycloak generate it).

### redirect_uri validation test

Test the authorization endpoint with attacker-controlled redirect URIs:

```python
import urllib.request, urllib.error, ssl, urllib.parse
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

redirect_tests = [
    "https://evil.com/callback",
    "https://target.example.evil.com/callback",
    "https://target.example/oauth/../anything",
    "https://target.example@evil.com/callback",
    "http://localhost:8080/callback",
    "https://evil.com/callback#target.example",
    "javascript:alert(1)",
]
for rd in redirect_tests:
    params = urllib.parse.urlencode({
        'client_id': '<client_id>',
        'redirect_uri': rd,
        'response_type': 'code',
        'scope': 'openid profile email'
    })
    url = f'https://target.example/realms/prod-realm/protocol/openid-connect/auth?{params}'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        r = urllib.request.urlopen(req, timeout=10, context=ctx)
        print(f'{rd[:50]:55s} -> {r.status} (REDIRECT ACCEPTED!)')
    except urllib.error.HTTPError as e:
        print(f'{rd[:50]:55s} -> {e.code}')
    except Exception as e:
        print(f'{rd[:50]:55s} -> ERR {type(e).__name__}')
# 400 for all = redirect_uri validation is strict (exact match)
# 302/200 for any = open redirect → token leakage → ATO
```

## 4. Source maps on Keycloakify login pages

Keycloakify (React-based Keycloak theme) bundles may expose source maps:

```bash
# From the login page HTML, extract the JS bundle path
curl -sk https://target.example/ | grep -oE 'src="[^"]+\.js[^"]*"'

# Download the .js.map for each bundle
curl -sk "https://target.example/<path>/bundle.js.map" -o map.json

# Verify it's valid JSON (not SPA fallback HTML)
python3 -c "import json; d=json.load(open('map.json')); print('sources:', len(d.get('sources',[])))"

# Extract high-signal source paths
python3 -c "
import json, re
d = json.load(open('map.json'))
for s in d.get('sources', []):
    if re.search(r'src/|api|auth|token|login|config|key|secret|endpoint', s, re.I):
        print(s)
"
```

Source maps can reveal:
- Internal build paths (e.g. `.databricks/cache/yarn_node_modules/...` showed Neon uses Databricks for builds)
- Application source files (`../../src/login/KcPage.tsx`, `../../src/login/i18n.ts`)
- Analytics integration keys (Segment write key in `analytics/provider.tsx`)
- OAuth/IdP configuration in source (`pageIds.ts` showing Keycloak login-action routes)

## 5. Pitfalls

- `invalid_grant` on ROPC test does NOT mean credentials are invalid — it means the grant type IS supported. The response distinguishes "grant not supported" (`unsupported_grant_type`) from "credential mismatch" (`invalid_grant`).
- Dynamic Client Registration returning `403 Trusted Hosts` means the endpoint EXISTS and is POLICY-RESTRICTED, not that DCR is disabled. If the policy is misconfigured (e.g., trusts `*` or a spoofable host header), it becomes exploitable.
- Source maps on a Keycloakify login theme are separate from the main SPA's source maps. Always check both the IdP theme AND the main application bundles.
- Keycloak `end_session_endpoint` with `post_logout_redirect_uri` is a redirect target — test it for open redirect, not just the authorization endpoint's `redirect_uri`.
