# Terraform registries (Terrakube) + Dex OIDC — unauth recon chain

Session-validated (smarttaxdev registry, 2026-10). Terraform/Terrakube registries and
Dex-backed OIDC on dev/test hosts expose a clean metadata→probe chain. Compact but
recurring — Dex is everywhere in the K8s/IaC ecosystem.

## Trigger

- `/.well-known/terraform.json` reachable on a host (Terraform registry protocol)
- `/dex/.well-known/openid-configuration` or `/dex/keys` paths
- Spring Boot actuator on a registry host

## The chain

```bash
H="https://registry.example.com"
A="https://api-registry.example.com"   # often a different host, disclosed by terraform.json

# 1. terraform.json discloses the API host + OIDC client config (unauth)
curl -sk "$H/.well-known/terraform.json" | jq .
# → modules.v1/providers.v1 URLs, and login.v1 { client: "<client_id>", authz/token endpoints, grant_types }

# 2. Dex discovery + JWKS (unauth)
curl -sk "$A/dex/.well-known/openid-configuration" | jq '{grant_types_supported, code_challenge_methods_supported}'
curl -sk "$A/dex/keys" | jq '.keys[] | {kid, alg}'

# 3. Dex device-code flow: the INITIATION is unauthenticated by protocol design
curl -sk -X POST "$A/dex/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=<from terraform.json>&scope=openid+profile+email+groups+offline_access"
# → {"device_code":"...","user_code":"XXXX-XXXX","verification_uri":".../dex/device","expires_in":300,"interval":5}

# 4. Token poll — correctly gated (expected outcomes, NOT a vuln):
curl -sk -X POST "$A/dex/token" -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=<dc>&client_id=<cid>"
# → authorization_pending → slow_down (rate limiter works)
# Only a bug if a token is EVER issued without user approval at verification_uri.

# 5. Dex connector detection: auth endpoint redirects reveal the backing IdP connector
curl -sk -D - -o /dev/null "$A/dex/auth?client_id=<cid>&redirect_uri=https://ui.example/callback&response_type=code&scope=openid"
# → Location: /dex/auth/entra?...  (connector name = Entra/AD/LDAP/GitHub/…)
```

## What counts as findings here

| Observation | Severity |
|---|---|
| `login.v1.client: "${AppClientId}"` (unresolved placeholder leaked in terraform.json) | Info — template misconfig |
| Actuator `/actuator` + `/actuator/health` unauth (env/heapdump/beans 401) | Info/Low |
| Full OIDC metadata + JWKS public | Info |
| Device-flow initiation unauth | Normal protocol — not a finding |
| Unresolved redirect to internal IdP connector names | Info (topology disclosure) |

## Hardened negatives (session-verified)

- `/terraform/modules/v1/*` registry protocol endpoints → 401 (auth required)
- `env`, `heapdump`, `beans`, `configprops`, `metrics`, `prometheus` actuator → 401
- Dex token poll without approval → `authorization_pending`/`slow_down`
- Token-exchange grant without subject_token_type → 400 request_not_supported

## Pitfall

Don't burn time brute-forcing the registry API (`/api/v1/organization`, `workspace`, `job`) —
all 401 and the auth is Dex-issued JWT, not bypassable from outside. The value is the
metadata disclosure + the OIDC connector topology, then pivot to the backing IdP (Entra).
