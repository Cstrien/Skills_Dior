# PulsePoint Exchange — ASP.NET Bug Bounty Engagement (Aug 2026)

## Target

`https://exchange.pulsepoint.com/AccountMgmt/Login.aspx`

## Tech Stack

- ASP.NET Webforms on .NET Framework 4.x (IIS behind nginx reverse proxy)
- ViewState: signed-only (`__VIEWSTATEENCRYPTED=""`), not encrypted
- Auth: Forms auth via `CWAuthTkt_CROSS_DOM` cookie
- 3-node load-balanced farm: `ma2-portal01/02/03.pulse.corp`
- Modern auth infrastructure: `p2-auth.pulsepoint.com` (FastAPI on Google Cloud Run + IAP)

## Findings

### 1. Unauthenticated WCF Service + WSDL + Internal Hostname Leak (Medium)

`AccountService.svc` accessible without auth (200) while all other `.svc` files redirect to login (302). Full WSDL at `?singleWsdl` discloses data contracts with sensitive fields (`Password`, `SecurityAnswer`, `SecurityAnswerPlain`). Three metadata endpoints each leak a DIFFERENT internal hostname:

- `.svc` help page → `http://ma2-portal01.pulse.corp`
- `?disco` → `http://ma2-portal02.pulse.corp`
- `?wsdl` → `http://ma2-portal03.pulse.corp`

Operations exposed: `createMasterAccount`, `saveAccountSignupDetails`, `getAccountSignupDetails`, `updateAccountSignupDetails`. Most return 500 "An non-fault exception has occured." but `updateAccountSignupDetails` returns `{"d":null}` (200) suggesting it may execute.

### 2. OpenAPI Spec Disclosure on Auth Infrastructure (Medium)

`https://p2-auth.pulsepoint.com/openapi.json` (and all 6 environment variants: prod, dev, stg, disposable, gcpglo, gcpglo-stg) returns 200 with 94KB OpenAPI 3.1 spec. Discloses 33 endpoints including:

- `POST /admin/v1/users` — Create User
- `GET /admin/v1/users` — List Users
- `POST /admin/v1/service-accounts` — Create Service Account
- `POST /internal/cleanup` — Run Nightly Cleanup
- `POST /auth/token/exchange` — Exchange Token for Life Platform

Admin endpoints are IAP-protected (401/302) but the spec itself is a complete attack-map. Also leaks OAuth client names (`bi-lore-cli`, `bi-lore-mcp-bridge`) and all 5 grant types.

JWKS endpoints (`.well-known/jwks.json`) leak key IDs with environment names and dates: `portal-auth-prod-2026-08-04`, `portal-auth-dev-2026-08-05`, `portal-auth-stg-2026-08-05`. All environments share the same RSA public key.

### 3. Permissive CORS (Low)

All endpoints return `Access-Control-Allow-Origin: *` with `Cookie` and `Token` in allowed headers. No `Access-Control-Allow-Credentials: true` (correct), so credential theft is not possible. But unauthenticated endpoints like `AccountService.svc` can be read cross-origin from any site.

### 4. Client-Side Password Crypto Weakness (Low)

Login JS does `SHA-256(password).substring(0, 19)` — only 19 of 64 hex chars sent. AES-GCM encryption uses `VIEWSTATEGENERATORCUSTID` (visible in HTML) as the key.

## Key Techniques Used

### proxyOptions extraction from Signup.aspx
```bash
curl -sk "https://exchange.pulsepoint.com/AccountMgmt/Signup.aspx" | \
  grep -oE 'proxyOptions\s*=\s*\{[^}]+\}'
# Reveals all 19 backend service names + proxy paths
```

### .svc auth-state differential
```bash
for svc in AccountService UserService SecurityServices Publisher Advertiser; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://exchange.pulsepoint.com/AccountMgmt/UIWebServices/${svc}.svc")
  echo "$code ${svc}.svc"
  # 200 = UNAUTH, 302 = auth-gated, 404 = missing
done
```

### Internal hostname extraction from WCF metadata
```bash
for ep in "" "?disco" "?wsdl"; do
  curl -sk "https://exchange.pulsepoint.com/AccountMgmt/UIWebServices/AccountService.svc$ep" | \
    grep -oE 'http://ma2-portal[0-9a-z]+\.pulse\.corp'
done | sort -u
```

### OpenAPI discovery on auth infrastructure
```bash
# Check all p2-auth variants
for host in p2-auth p2-auth-dev p2-auth-stg p2-auth-disposable gcpglo-p2-auth gcpglo-p2-auth-stg; do
  curl -sk -o /dev/null -w "%{http_code} %{size_download} $host\n" \
    "https://$host.pulsepoint.com/openapi.json"
done
```

## What Did NOT Work

- ViewState parser differential: all 7 payload shapes returned 200 with the login page (no error differential). The app silently rejects invalid ViewState and re-renders the login form.
- SQL injection in login/forgotpassword: all inputs handled gracefully, no error differential.
- User enumeration via ForgotPassword: all usernames (valid and invalid) return identical responses (3095 bytes stripped). No timing differential (1.27σ, not significant).
- CrossDomainProxy SSRF: proxy requires auth, redirects to Logout.ashx.
- SOAP-based WCF calls: timeout (POST with SOAP envelope hung indefinitely).
- `createMasterAccount` via JSON REST: returns generic 500 error regardless of payload completeness.
