---
name: js-bundle-secret-hunting
description: "Use when hunting JS bundles for leaked API keys and hosts."
version: 1.0.0
author: hermes-curator
license: internal
tags: [bug-bounty, js-analysis, secrets, gatsby, vite, api-keys]
related_skills: [web2-recon, js-analysis-anti-false-positive, client-side-js-security-analysis, hunt-source-leak, postmessage-vulnerabilities]
---

# JS Bundle Secret & Internal-Host Hunting

Extracting secrets, env configs, and internal API surface from client-side bundles on bug bounty targets. Complements `web2-recon` (pipeline) and `client-side-js-security-analysis` (grep discipline) — this skill covers the **build-artifact layer**: where frameworks stash env values, how to validate the keys you find, and which ones are reportable.

## Where the loot hides (by build system)

| Build system | What to fetch | Why |
|---|---|---|
| Vite | Inline `aS={VITE_X:...}` object baked into app chunk | **Plaintext, all env vars** (unlike CRA which needs NEXT_PUBLIC_ prefix) — non-prefixed secrets still leak if bundled |
| Gatsby | `/page-data/<path>/page-data.json` + `/page-data/sq/d/<hash>.json` | **Static query results are pre-rendered JSON** — often contains full API specs (OpenAPI JSON embedded in `allSwaggerSpec.edges[].node.internal.content`), full content dumps, and config that the SPA would otherwise lazy-load |
| Next.js | `_buildManifest.js` (routes), `_app-*.js` (config), `__NEXT_DATA__` | Route map + SSR config incl. INTERNAL_* URLs |
| CRA/webpack | `chunk-*.js` | Same as Vite |
| CRA/webpack | `<chunk>.js.map` — **check `.map` on every JS chunk you fetch** | **Full original sources with `sourcesContent`** (221 files on one target) — comments, configs, internal URLs, everything pre-minification |
| Any SPA | `<script type="application/json" id="__APP_ENV__">` | Inline env JSON (cross-TLD pivot gold) |

## Source-map playbook (React/CRA/webpack)

Public `.map` files are the cheapest full-source leak on SPAs. Two-step check that takes seconds:

```bash
# 1. Probe maps for every chunk you've already fetched (URL = chunk URL + ".map")
for f in static/js/main.20ef0d63.chunk.js static/js/2.edb84bb3.chunk.js; do
  printf "%-40s map: " $f; curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' $T/$f.map
done
# 200 + large size = jackpot. (SPA-fallback caveat below still applies — verify it parses as JSON.)

# 2. Download and enumerate sources + content
curl -sk $T/static/js/main.20ef0d63.chunk.js.map -o m.map
python3 -c "import json;d=json.load(open('m.map'));print(len(d['sources']),'files, content:',any(d.get('sourcesContent') or []))"
```

What maps give you that minified bundles don't:
- **`sourcesContent` = original code** — grep it like source code, not minified sludge: `dangerouslySetInnerHTML`, `innerHTML =`, hardcoded creds, commented-out config.
- **File tree = internal app structure** (`api/`, `configs/`, `redux/slice/`, `containers/<feature>/`) — names the features before you ever open the app.
- **`configs/*` files** — API base URLs, sometimes with commented-out **dev/internal URLs** (`http://10.x.x.x:port`, `192.168.x.x`, vendor hostnames) that map the internal network and the software vendor.
- **`firebase-config.js`-style SDK config files** — Firebase Web API keys + project IDs + VAPID keys. Web API keys alone are usually note-only (designed-public, restricted by Firebase rules), but record them: pair with `projectId` to probe for weak Firestore/FCM rules or open Realtime DB.
- **XSS sinks**: `dangerouslySetInnerHTML={{__html: <field>}}` where `<field>` comes from an API (`noidung1+2+3`, `htmlData`) = second-order/stored XSS chain candidate — check whether the source API feeding it is writable via the same auth-bypass/BAC bug elsewhere.

Reference example with all of the above: `references/cskh-sourcemap-engagement-2026-10.md`.


**Key rule:** a `200` on `/page-data.json` paths is not proof of content — SPA fallbacks return `index.html`. Verify the body parses as JSON with expected keys (see `web2-recon` source-map pitfall — same discipline applies).

## High-signal grep patterns

```
VITE_ [A-Z_]{4,}          # Vite env — grab the whole assignment object
aS={VITE_                 # minified Vite env block (find it, extract whole object)
NEXT_PUBLIC_              # CRA/Next
SENTRY_DSN|sentry\.io     # DSN format: https://KEY@host/PROJECT
contentful|ctfassets      # delivery keys: SPACE + accessToken pair
logz\.io|LOGZ_TOKEN       # shipping tokens
facetec|liveness|biometrics
ACCESS_KEY|SECRET_KEY     # paired creds (often together in one config object)
listener\.logz\.io|ingest\.sentry\.io
api\.fstr|sorting-hat     # telemetry SDKs often carry app keys
wsloja|api-int|-int\.     # -int suffix hosts = internal mirror of public API
dc-ifood|\.k8s\.|aws-production|k8s\.aws   # internal cluster DNS patterns
```

**Client-side API-signing secrets (high value):** any chunk with `crypto.subtle.importKey` + `sign("HMAC"` ships the request-signing secret in plaintext. Replicate the canonical-string scheme (often `Object.keys(d).sort()` → `|k=v` join) in Python to mint signed requests directly — this bypasses the whole signing/anti-abuse layer (device registration, bot gating). Full extraction recipe + captcha-header pattern: `references/nextjs-api-signing-and-captcha-headers.md`.

**Paired-key insight:** SDK configs ship *sets* — finding one Vite env block usually yields 5-15 keys at once (analytics + payment + anti-fraud + CDN). Dump the entire config object, don't cherry-pick.

## Masked vs full secrets — the check that saves false reports

Minifiers mask secrets at build time: `VITE_SENTRY_DSN: "https://faa8c5...8f27@..."` and `GOOGLE_API_KEY: "AIzaSy...P1xA"` appear in bundles. **Masked keys are not findings.** Verify before claiming:

1. Extract full candidate values (if literal `...` in the middle, it's masked, skip).
2. Probe each **on its own vendor API** — a key that "exists" in JS means nothing until the endpoint accepts it:

| Key type | Validation probe |
|---|---|
| Contentful delivery | `GET https://cdn.contentful.com/spaces/<SPACE>/entries?limit=1` with `Authorization: Bearer <key>` — also try `preview.contentful.com` and `api.contentful.com` (CMA) and `graphql.contentful.com/content/v1/spaces/<SPACE>/environments/master` (GraphQL POST `{__typename}`) |
| Logz.io | `POST https://listener.logz.io:8071/?token=<key>&type=<marker>` — 200 = shipping token VALID (ingest oracle); `api.logz.io` endpoints 404 with shipping tokens |
| Sentry DSN | `POST https://<host>/api/<project>/envelope/` with minimal envelope |
| FaceTec | device key + production key in config block (`VITE_FACETEC_PRODUCTION_KEY_*`) — usually session-gated server-side, note but don't overstate |

3. **Ingest-oracle test with marker discipline:** when a log endpoint returns 200, prove ingestion with a unique marker (`cpmark987-<timestamp>`) — a 200 with no ingestion path is weaker than 200 + verified write.
4. Always distinguish *delivery* vs *write* access — e.g. Contentful delivery keys fail on CMA (`OrganizationAccessGrantRequired`) but may succeed on GraphQL. Severity scales with write.

## Internal-host extraction → resolution decision tree

JS bundles leak `INTERNAL_*_URL` / `*_API_INT` config for the server-side twin of every public API. On finding one:

```
NXDOMAIN  → internal-only, note as intel (host naming scheme is still recon value)
Public IP → probe TLS: client-cert REQUEST during handshake = mTLS-required (host exists, endpoint intentional)
Public IP + no cert request → probe headers/body, check for public-but-forgotten endpoint
```

Do not scan `dc-ifood`-style cluster DNS from an external host expecting hits — 96% is VPC-internal; CT logs list them from internal cert issuance, not public exposure.

## Gatsby page-data playbook (worked example: iFood benefits developer portal)

1. `/page-data/index/page-data.json` → read `staticQueryHashes[]`.
2. For each hash: `/page-data/sq/d/<hash>.json` → static query results (often the whole spec/content set).
3. Localized paths: `/page-data/en-US/docs/references/page-data.json` — **locale-prefixed page-data often carries MORE data** (full swagger specs with servers, securitySchemes, paths) than the default-locale page-data.
4. Grep page-data JSON for `allSwaggerSpec`, `internal.content`, `openapi` → parse out `specId`, `info.title`, `servers[]`, `components.securitySchemes`, `paths[]`.
5. Feed `paths[]` into endpoint probing on the *actual* API host (servers[].url is often a placeholder `https://example-ifood.com.br` — find the real host from the BFF's JS bundle, e.g. help center chunk exposing `baseURL: "https://consumer-api.ifood.com.br"`).

## Endpoint probing discipline (validation-oracle mapping)

For each discovered endpoint, send shape-valid bogus payloads and classify:

- `{}` → `IAM-2000 "must not be null"` = endpoint exists, schema unauthed-visible
- `ClientSecretNotFound for client ID X` = client-ID enumeration oracle (check rate limit!)
- `OTP-2001 "Authorization code expired or does not exist"` = code-validation gate reached
- `AFC-2003 Unauthorized` on header-gated endpoint = server-side session validation present
- `411 Length Required` on GET = POST-only endpoint

Record the oracle ladder per endpoint in hunt notes — it's the retest blueprint once an account exists. **Measure rate limits per endpoint, not per flow**: one endpoint in a chain may be throttled ("API rate limit exceeded") while sibling endpoints are open.

## Reportable vs note-only

- **Reportable:** valid write-capable keys (CMA, preview), ingest-capable tokens (logz shipping 200 + proven ingestion), secrets that gate paid infrastructure.
- **Note-only / info:** delivery-read-only API keys (very common, often accepted-low), masked values, client IDs by design, internal hostnames with no reachable endpoint.
- Always test the key against ALL its API variants before classifying (delivery vs preview vs management).

## Related
- `web2-recon` — recon pipeline that feeds the URL set
- `js-analysis-anti-false-positive` — discipline rules for JS claims
- `client-side-js-security-analysis` — grep targets for XSS/secrets
- `hunt-source-leak` — source disclosure class
- `postmessage-vulnerabilities` — postMessage listener exploitation (origin trust, state injection)

**Keycloak + identity-service + Next.js BFF platforms (2026):** when the target runs this stack
(sso.* + identity.* + /bff/* Next apps), the highest-value surface is the identity service itself:
unauth `/sync/*` mass data dumps, `/api-docs/swagger-ui-init.js` full API spec, admin endpoints
accepting any valid Bearer JWT, and a public mobile client enabling unthrottled password grants.
Also: Keycloak `admin-cli` direct grant is frequently enabled on prod. Full worked example:
`references/vau-keycloak-bff-engagement-2026-09.md`.

## When to Use
- You downloaded SPA/Next/Gatsby bundles during recon and are deciding what to grep for.
- A bundle contains `VITE_`/`NEXT_PUBLIC_` variables, Sentry DSNs, Contentful keys, or SDK config blocks.
- You found a Gatsby site and want its API specs / full content without auth.
- You found candidate keys in a bundle and need to validate which are real before reporting.

## Session-specific detail
- `references/ifood-engagement-2026-09.md` — worked example: iFood engagement (all bundle sources, Contentful/Logz validation results, postMessage chain, Kong endpoint oracle ladder).
- `references/cskh-sourcemap-engagement-2026-10.md` — worked example: React SPA with public `.js.map` → 221 source files; config comments leaking vendor + internal IPs; `dangerouslySetInnerHTML` second-order XSS chain.
- `references/nextjs-api-signing-and-captcha-headers.md` — Next.js targets that SIGN API requests client-side: HMAC secret + api_key extraction from chunks, Python signature replication, hooking fetch to find real routes (JS strings ≠ deployed routes), captcha tokens in custom `X-*-Token` headers, headless reCAPTCHA Enterprise v3 token minting, per-module baseUrl resolution, forgot-password anti-enumeration discipline.
