---
name: web2-recon
description: Web2 recon pipeline — subdomain enumeration (subfinder, Chaos API, assetfinder), live host discovery (dnsx, httpx), URL crawling (katana, waybackurls, gau), directory fuzzing (ffuf), JS analysis (LinkFinder, SecretFinder), continuous monitoring (new subdomain alerts, JS change detection, GitHub commit watch). Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, or attack surface mapping.
---

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

---

## SETUP (one-time)

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify all tools installed (jq is required by the default shell pipelines)
which subfinder httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client jq
# If jq is missing, install it or use Python JSON parsing fallback for recon APIs:
#   curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
#     | python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]"
```

### OIDC / Keycloak first-look

When the first browser visit redirects to an IdP URL like `/realms/<realm>/protocol/openid-connect/auth`, immediately pull OIDC metadata before broader crawling. It reveals endpoints, grant types, dynamic-client-registration state, device/CIBA support, and token signing algorithms in one request:

```bash
REALM=prod-realm
BASE=https://target.example
curl -sk "$BASE/realms/$REALM/.well-known/openid-configuration" | python3 -m json.tool
curl -sk "$BASE/realms/$REALM" | python3 -m json.tool
```

Hand off OAuth-specific testing to `oauth-pentest`, especially for ROPC/password grant, redirect_uri validation, dynamic client registration policy, device flow, and account-linking flows.

---

## THE 5-MINUTE RULE

> If a target shows nothing interesting after 5 minutes of recon, move on. Don't burn hours on dead surface.

**5-minute kill signals:**
- All subdomains return 403 or static marketing pages
- No API endpoints visible in URLs
- No JavaScript bundles with interesting endpoint paths
- nuclei returns 0 medium/high findings
- No forms, no authentication, no user data

---

## STANDARD RECON PIPELINE

### Pre-Hunt: Always Run First

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
# Pitfall: crt.sh is frequently overloaded and returns 502 Bad Gateway.
# The % wildcard in the URL must be URL-encoded as %25 (not raw %).
# If crt.sh fails, skip to the fallback sources below — do NOT block on it.
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" --max-time 30 \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 0b: Fallback sources (run in parallel with crt.sh — these are more reliable)
# HackerTarget — free, no API key, returns CSV of hostnames (often 50-100+ for enterprise targets)
curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" --max-time 20 \
  | awk -F',' '{print $1}' | sort -u >> /tmp/subs.txt

# RapiddNS — free, no API key, scrapes multiple CT log sources
curl -s "https://rapiddns.io/subdomain/$TARGET?full=1" --max-time 15 \
  | grep -oP '[a-zA-Z0-9._-]+\.${TARGET//./\\.}' | sort -u >> /tmp/subs.txt

# web.archive.org CDX API — free, returns historical URLs (extract hostnames)
curl -s "https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=5000" --max-time 30 \
  | sed 's|https\?://||;s|/.*||' | sort -u >> /tmp/subs.txt

echo "[+] After fallback sources: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source, requires free API key)
# If CHAOS_API_KEY is unset, this returns 401 — skip gracefully.
if [ -n "$CHAOS_API_KEY" ]; then
  curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
    -H "Authorization: $CHAOS_API_KEY" \
    | jq -r '.[]' >> /tmp/subs.txt
  echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"
fi

# Step 2: subfinder (passive multi-source)
# Pitfall: subfinder can hang for 2+ minutes on large enterprise domains (e.g. atlassian.com)
# because some passive sources are slow or rate-limit. Use -timeout to cap per-source wait,
# and run it in the background so you can proceed with DNS resolution on what you already have.
subfinder -d $TARGET -silent -timeout 3 | anew /tmp/subs.txt &
SUBFINDER_PID=$!
# Don't wait — proceed to DNS resolution with what we have. Merge subfinder output later.

assetfinder --subs-only $TARGET 2>/dev/null | anew /tmp/subs.txt || true

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt) subdomains (subfinder still running in bg PID=$SUBFINDER_PID)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---

## ATTACK SURFACE TRIAGE

### Find Interesting Targets in URL List

```bash
# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt
```

### gf Patterns (Quick Classification)

```bash
# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt
```

---

## JS ANALYSIS

### SecretFinder (API keys, tokens in JS bundles)

```bash
# Activate venv
source ~/tools/SecretFinder/.venv/bin/activate

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan all JS URLs found in recon
cat /tmp/urls.txt | grep "\.js$" | head -50 | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### LinkFinder (Endpoints hidden in JS)

```bash
source ~/tools/LinkFinder/.venv/bin/activate

# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli

# All pages (crawls JS from HTML)
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli

deactivate
```

---

## DIRECTORY FUZZING

### ffuf — Standard Fuzzing

```bash
# Directory discovery on a live host
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -ac \
     -t 40 \
     -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 \
     -ac \
     -t 20

# IDOR fuzzing with authenticated request
# Create req.txt with Authorization: Bearer TOKEN
ffuf -request /tmp/req.txt \
     -request-proto https \
     -w <(seq 1 10000) \
     -fc 404 \
     -ac \
     -t 10
```

---

## TARGET SCORING — GO / NO-GO

Score before spending time. Skip if score < 4.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**< 4:** Skip
**4-5:** Only if nothing better available
**6-8:** Good — spend 1-3 days
**>= 9:** Excellent — spend up to 1 week

### Pre-Dive Hard Kill Signals

1. Max bounty < $500 → not worth your time
2. All recent reports are N/A or duplicate → hunters saturated it
3. Scope is only a static marketing page → no attack surface
4. Company < 5 employees with no revenue → won't pay
5. Explicitly excludes your planned bug class in rules

---

## TECH STACK DETECTION (2 min)

```bash
# Response headers reveal backend
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

# Common signals:
# Server: nginx + X-Powered-By: PHP/7.4 → PHP backend
# Server: gunicorn OR X-Powered-By: Express → Python/Node.js
# X-Powered-By: ASP.NET → .NET
# Server: Apache Tomcat → Java
# X-Runtime: Ruby → Ruby on Rails

# Framework from JS bundle paths:
# /_next/static/ → Next.js
# /static/js/main.chunk.js → CRA (React)
# /packs/ → Ruby on Rails + Webpacker
# /__nuxt/ → Nuxt.js (Vue)
```

### Stack → Primary Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints (/actuator/env) | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (ReturnUrl) |
| Next.js | SSRF via Server Actions | Open redirect via redirect() |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

---

## CONTINUOUS MONITORING SETUP

Set up once per target. Alerts you before other hunters.

### New Subdomain Alerts (daily cron)

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfinder -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

# Schedule: crontab -e → 0 8 * * * /bin/bash ~/monitors/subs-watch.sh
```

### GitHub Commit Watch

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Schedule: */30 * * * * /bin/bash ~/monitors/github-watch.sh
```

---

## PORT SCANNING (often skipped — don't skip)

```bash
# naabu — fast port scanner from ProjectDiscovery
# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports
# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

## SECRET SCANNING IN JS BUNDLES

```bash
# trufflehog — high-signal secret detection with entropy analysis
# Scans JS files and git repos
pip install trufflehog3 2>/dev/null || true
trufflehog filesystem --only-verified recon/$TARGET/ 2>/dev/null

# SecretFinder — manual JS bundle scan (already in tools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\.js$" | head -100 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AWS_SECRET\|AKIA" /tmp/js-files/ 2>/dev/null
```

### Lightweight JS analyzer fallback

When SecretFinder/LinkFinder are unavailable or too heavyweight for a quick bug-bounty pass, use the included zero-dependency regex analyzer:

```bash
python3 ~/.hermes/skills/bug-bounty/web2-recon/scripts/lightweight_js_analyzer.py recon/$TARGET/js
```

### gRPC-web / protobuf SPA recon

Large minified SPA bundles (especially Lattice-style apps with bundled `protobuf`/`connectrpc`/`grpc-web`) hide the real API surface in binary gRPC methods that URL crawling never finds. Extract service/method names from JS method descriptors, then POST gRPC-web frames directly. See `references/grpc-web-spa-recon.md` for extraction and framing recipes, response interpretation, and identity-method probes such as `GetSSOURL` / `GetSPMetadata`.

It writes `js_urls.txt`, `js_paths.txt`, and `js_snippets.txt` in the current directory. This is especially useful for Next.js/React bundles where `/login` or `/dashboard` exposes large chunks containing API base hosts and auth/account/portfolio endpoints.

For API docs / developer / partner portals, use the reference `references/api-docs-and-partner-portal-recon.md`: download bootstrap + Webpack Module Federation lazy chunks, keep analyzer output per app/host, distinguish SPA HTML fallbacks from real API responses, and triage routes like `getServiceEndpointListingExternal`, `onboardServiceByYamlUrl`, upload/file-manager, partner/vendor/payment/invoice endpoints.

For internal infrastructure discovered via sibling domains (VPN portals, Sentry, observability tools), use `references/internal-infra-and-vpn-recon.md`: Cisco ASA VPN group enumeration from unauthenticated XML auth responses, Sentry DSN extraction from env configs, S3 bucket discovery via Cloudflare-proxied subdomains, NetBird/Pritunl/OpenVPN fingerprinting, and cross-TLD pivot patterns.

For React/Vite/CRA/Refine SPAs where every path returns `index.html`, use `references/spa-api-base-and-fallback-recon.md`: verify source-map hits by JSON parsing (not HTTP 200), extract hidden API base prefixes from minified bundles (e.g. `baseURL="/checkinapi"`), and probe same-IP alternate admin/security services discovered by port scan.

### Source map exposure check (production SPA quick win)

After downloading JS bundles, always test `bundle.js.map` for every first-party chunk, not just `sourceMappingURL` comments. Some production builds leave maps accessible even when the main bundle is minified. A large source map (hundreds of KB to MBs) can expose original source paths, service modules, auth/token handling, API endpoints, environment hostnames, and comments.

**Pitfall — SPA catch-all false positive:** A `200` status on `bundle.js.map` is not proof. Many SPA deployments (React Router, Vite, Next.js, CRA) route ALL unknown paths to `index.html`, including `.map` URLs. Always download the body and verify it is valid JSON with `version`/`sources`/`mappings` fields, not the HTML fallback. See `references/spa-api-base-and-fallback-recon.md` for the validation script.

```bash
# Build js-urls.txt from browser/HTML crawl first, then:
while read js; do
  case "$js" in
    http*) url="$js.map" ;;
    /*)    url="https://$TARGET$js.map" ;;
    *)     url="https://$TARGET/$js.map" ;;
  esac
  curl -skL --max-time 8 -o /tmp/mapcheck -w "$url -> %{http_code} %{size_download}\n" "$url"
done < js-urls.txt
```

When maps are exposed, download them and parse `sources` / `sourcesContent` for high-signal paths:

```bash
python3 - << 'PY'
import json, pathlib, re
for p in pathlib.Path('js/sourcemaps').glob('*.map'):
    data=json.loads(p.read_text(errors='ignore'))
    print(p, 'sources=', len(data.get('sources', [])))
    for s in data.get('sources', []):
        if re.search(r'api|auth|token|login|password|secret|config|env|customer|account|suitability|signature', s, re.I):
            print(' ', s)
PY
```

Feed recovered source paths/endpoints back into API hunting; source maps often reveal protected routes and service names that the minified bundle hides.
```

### CDN/WAF TLS-fingerprint fallback

When normal `curl`, headless browser navigation, or HTTP/2 requests fail with protocol errors/timeouts on Akamai-like edges, but the task is passive asset mapping, try browser TLS impersonation before giving up. The bundled helper uses `curl_cffi` to fetch HTML plus JS/CSS assets with Chrome/Safari TLS fingerprints:

```bash
python3 -m venv ~/venvs/browserfp
. ~/venvs/browserfp/bin/activate
pip install curl_cffi
python3 ~/.hermes/skills/bug-bounty/web2-recon/scripts/browser_tls_fetch_assets.py \
  https://www.target.com recon/target.com/browserfp --impersonate chrome120
cd recon/target.com
python3 ~/.hermes/skills/bug-bounty/web2-recon/scripts/lightweight_js_analyzer.py browserfp
```

Use this only for normal web retrieval and endpoint mapping. Do not frame it as bypassing authentication or OTP; it is a transport/browser-fingerprint fallback for passive recon.

## GITHUB DORKING FOR TARGET

## GITHUB DORKING FOR TARGET

```bash
# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# Useful dorks (search on github.com):
# org:TARGET_ORG password
# org:TARGET_ORG api_key
# org:TARGET_ORG "Authorization: Bearer"
# org:TARGET_ORG .env
# org:TARGET_ORG "BEGIN RSA PRIVATE KEY"

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

## 30-MINUTE RECON PROTOCOL

### Minutes 0-5: Read Program Page

```
Note:
- ALL in-scope assets (every domain listed)
- Out-of-scope list (read carefully — common trap)
- Safe harbor statement
- Impact types accepted (some exclude "low")
- Average bounty amount (signals program generosity)
```

### Minutes 5-15: Asset Discovery

Run the standard pipeline above. Focus on live.txt output.

### Minutes 15-25: Surface Map

Run gf patterns and the interesting-params grep above.

### Minutes 25-30: Manual Exploration

Open Burp Suite. Browse the app with proxy on:
1. Register an account
2. Perform main user actions (create/read/update/delete resources)
3. Note all API calls in Burp history
4. Look for endpoints not in your URL list

### After 30 min: Prioritize

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
```

---

## Toolchain fallback (when `dnsx` / `httpx` crash)

The projectdiscovery Go binaries (`dnsx`, `httpx`, `naabu`) occasionally `SIGSEGV` on macOS arm64 due to a cgo / system-resolver interaction. The crash signature is identical regardless of install method — both `brew install` and `go install github.com/projectdiscovery/<tool>@latest` produce binaries that segfault at the same address. Smoke-test once before relying on them in a real engagement:

```bash
dnsx -version   # if SIGSEGV: use the dig fallback below
httpx -version  # if SIGSEGV: use the curl fallback below
```

**Linux pitfall — dnsx ANSI color codes corrupt output files.** `dnsx -resp` writes ANSI escape sequences (`\x1b[35m`, `\x1b[0m`, etc.) into output files even with `-silent` and `-no-color` flags on some Linux builds. Any downstream parser (Python `re`, `awk`, `jq` pipelines) will silently fail to match patterns because the escape codes sit inside the IP brackets. Always strip ANSI before parsing:

```bash
sed -r 's/\x1b\[[0-9;]*m//g' resolve.txt > resolve.clean.txt
```

```python
# In Python, strip ANSI before regex
import re
clean = re.sub(r'\x1b\[[0-9;]*m', '', raw_output)
```

**httpx may silently produce empty output files on some Linux setups.** If `httpx -l hosts.txt -o out.txt` creates a 0-line file despite known-live hosts, fall back to the curl-based probe below rather than debugging the binary.

### `dnsx` → `dig` fallback

```bash
# Replaces: dnsx -l subs.txt -a -resp -silent
while read s; do
  ips=$(dig +short +tries=1 +time=3 "$s" \
    | grep -E '^[0-9.]+$' \
    | paste -sd, -)
  [ -n "$ips" ] && echo "$s|$ips"
done < subs.txt
```

### `httpx` → `curl` fallback

```bash
# Replaces: httpx -l subs.txt -silent -status-code -title -tech-detect
while read s; do
  resp=$(curl -s -L -m 5 -o /tmp/body \
    -w "%{http_code}|%{url_effective}|%{header_server}" \
    "https://$s")
  code=$(echo "$resp" | cut -d'|' -f1)
  if [ "$code" != "000" ]; then
    title=$(grep -oE '<title[^>]*>[^<]*</title>' /tmp/body | head -1 | sed 's/<[^>]*>//g')
    echo "$s|$resp|$title"
  fi
done < subs.txt
```

**Trade-off:** Serial vs. concurrent. The fallback handles ~24 subdomains in 14 seconds; the same workload on `httpx` with default 50 threads finishes in 2-3 seconds. For VDP-scale recon (< 100 subdomains) the fallback is fine. For mass recon (1000+) fix the toolchain first.

Verified against HackerOne's own VDP in `docs/verification/recon-hackerone-vdp.md`.

---

## API Spec / Swagger / OpenAPI Discovery (2024-2026 surface)

API spec endpoints are the single highest-leverage recon target on any modern .NET / Node / Python / Java backend. The spec discloses every endpoint, HTTP methods, parameter names + types + formats, models, validation rules — a complete attack-map in JSON. Default routes are commonly left enabled in production. **Add this wordlist to the directory-fuzzing phase** (after the standard `common.txt` pass).

### Default discovery path wordlist (paste into `swagger-paths.txt`)

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger
/swagger/
/swagger/index.html
/swagger/ui/index.html
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/swagger/v3/swagger.json
/swagger/docs/v1
/swagger/docs/v2
/swagger-ui
/swagger-ui/
/swagger-ui.html
/swagger-resources
/swagger-resources/configuration/ui
/nswag
/nswag/index.html
/api/swagger
/api/swagger.json
/api/swagger/v1/swagger.json
/api/openapi
/api/openapi.json
/api/v1/swagger.json
/api/v2/swagger.json
/api-docs
/api-docs/swagger.json

# OpenAPI generic
/openapi
/openapi.json
/openapi.yaml
/openapi.yml
/openapi/v1.json
/openapi/v2.json
/openapi/v3.json
/.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs
/v3/api-docs
/v3/api-docs.yaml
/v3/api-docs/swagger-config
/swagger-ui/index.html

# Python (FastAPI / Flask-RESTPlus / Connexion / DRF)
/docs
/docs/
/redoc
/redoc/
/openapi.json
/swagger.json
/swagger/?format=openapi
/swagger.yaml

# Express / Node / Hapi
/api-docs
/api-docs.json
/swagger.json
/swagger-stats
/graphql-docs

# GraphQL adjacent (often co-located)
/graphql
/graphiql
/playground
/altair
/voyager
/graphql/console
/graphql-explorer

# ReDoc / RapiDoc / Stoplight / alt UIs
/redoc
/redoc.html
/redoc-ui.html
/rapidoc
/rapidoc.html
/stoplight
/elements

# Misc / dev-leftover
/actuator
/actuator/openapi
/actuator/mappings
/q/openapi
/q/swagger-ui
/docs/swagger.json
/api/v1/docs
/api/v2/docs
/internal/swagger
/admin/swagger
/management/swagger
```

### Integration with the standard pipeline

```bash
# After live-hosts.txt is built (Phase 1 / 2), run:
ffuf -w swagger-paths.txt -u "https://FUZZ.target.com" -mc 200,302 -fs 0 -t 50 -o swagger-hits.json
# Or with httpx for content-aware filtering:
httpx -l live-hosts.txt -path swagger-paths.txt -mc 200 -mr "swagger|openapi" -json | tee swagger-hits.jsonl
# For every hit:
jq '.paths | keys' swagger.json > endpoints.txt
jq '.components.schemas' swagger.json > schemas.json   # mass-assignment field candidates
```

### Why this matters for recon-to-hunting handoff

- **Spec → mass IDOR/BOLA** — `jq '.paths | keys' swagger.json` becomes the input list for `Autorize`/`ffuf` per-user testing.
- **Spec → mass-assignment payload construction** — `components.schemas.UserUpdateDto` enumerates `isAdmin`, `emailVerified`, `tenantId`, `role`.
- **Spec → hidden endpoint discovery** — `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes documented but never auth-gated.
- **Spec → injection-class seeding** — every parameter's type + format + enum + max-length means payloads pass validation before reaching the sink. Especially valuable against ASP.NET Core where the model binder rejects malformed input before any controller logic.

### Tools

- `kiterunner` — natively ingests OpenAPI spec, generates requests against the API.
- `sj` (Swagger Jacker) — purpose-built for Swagger spec exploitation.
- `apidetector` (brinhosa) — Swagger-UI mass scanner.
- `XSSwagger` (vavkamil) — detects vulnerable Swagger UI versions (CVE-2018-25031 family).
- `nuclei -t http/exposures/apis/` — built-in templates for default spec paths.

### Anti-pattern reminder

A 404/403 on `/swagger` does NOT mean no spec is exposed. Many .NET projects route the spec under `/api/swagger/v1/swagger.json` rather than `/swagger`. Always test the full path list, not just the root.

### Auth-infrastructure OpenAPI discovery

Modern identity brokers (FastAPI, Keycloak, custom OAuth services) on dedicated auth subdomains (`auth.*`, `id.*`, `sso.*`, `p2-auth.*`) frequently expose `/openapi.json` on ALL environments (prod, dev, stg, disposable). This discloses admin/internal endpoints (`/admin/v1/users`, `/internal/cleanup`) that are IAP/auth-gated but provide a complete attack-map. Also check `/.well-known/jwks.json` — JWKS key IDs often leak environment names and rotation dates, and shared keys across environments indicate key-reuse risk.

```bash
# After subdomain enum, probe auth infrastructure for OpenAPI
for host in auth id sso p2-auth identity login; do
  for env in "" dev stg disposable; do
    target="${host}${env:+-$env}.target.com"
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$target/openapi.json" 2>/dev/null)
    [ "$code" = "200" ] && echo "[+] OpenAPI: https://$target/openapi.json"
  done
done
```

Full attack-chain analysis is in `hunt-api-misconfig` → `NSwag / Swagger / OpenAPI Spec Exposure`.

---

## Related Skills & Chains

- **`offensive-osint`** — When recon needs concrete probes / wordlists / regexes beyond the basic pipeline. Workflow primitive: this skill produces the URL set; `offensive-osint` provides the secret regexes, GraphQL/Swagger paths, and identity-fabric probes you apply to that URL set.
- **`osint-methodology`** — When you need a severity rubric for what you discovered. Workflow primitive: after recon outputs `subdomains.txt` / `live-hosts.txt` / `urls.txt`, score each asset against `osint-methodology`'s findings rubric to decide what gets a finding versus what stays in the asset graph.
- **`hunt-subdomain`** — When recon surfaces stale CNAMEs / dangling DNS. Workflow primitive: any subdomain in `subdomains.txt` whose CNAME points to S3 / GitHub Pages / Heroku / Shopify / Azure should auto-route to `hunt-subdomain` for takeover validation.
- **`security-arsenal`** — When the URL set is classified by `gf` and ready for active testing. Workflow primitive: `gf xss/ssrf/sqli/idor` output names become payload-class queries against `security-arsenal`'s payload library.
- **`bb-methodology`** — When recon completes and Phase 1 transitions to Phase 2 (Mapping). Workflow primitive: hand the live host + URL set back to `bb-methodology` Phase 2 for endpoint mapping and Phase 3 vulnerability discovery routing.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream pipeline covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Cross-TLD pivot discipline

Phase 2C's HackerOne VDP recon walked from `hackerone.com` (24 subdomains) into a sister TLD `hacker.one` (12 more subdomains found in JS bundle references). Operators who only enumerate `*.target.com` miss attack surface that the target legitimately operates on a different domain.

Always grep JS bundles for plausible sibling TLDs:

```bash
# pull all JS, grep for sibling-TLD candidates
for url in $(cat live-hosts.txt); do
  curl -s "$url" | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//'
done | sort -u > js-urls.txt

# then on each JS file
for j in $(cat js-urls.txt); do
  curl -s "$j" | grep -oE '[a-z0-9.-]+\.(io|app|one|dev|test|cloud|ai|co)' | sort -u
done | sort -u > sibling-tld-candidates.txt
```

Common sibling-TLD patterns: `target.com → target.io / target.app / target.one / target.dev / target.test / target-corp.com / target-cdn.net`. Always validate via WHOIS or by checking if the cert chain trusts the same internal CA before treating the sister TLD as in-scope.

### Subdomain wordlist priorities by 2026

Top discovery prefixes by hit rate against enterprise VDPs in our 2024-2026 corpus:

```
mta-sts.*          api.*              docs.*
dev-*              staging-*          *-qa
*-stage            *-uat              events.*
portal.*           customer.*         partner.*
vendor.*           internal-*         admin-*
employee-*         hr.*               jobs.*
sso.*              auth.*             id.*
```

Internal-looking subdomains often expose more surface than the marketing site — `partner.target.com` and `vendor-portal.target.com` frequently have weaker auth than the main app because they're scoped for "trusted" external users. Always send a probe to the long-tail wordlist after the standard subfinder run completes.

### Live-host probe: how to fingerprint stack quickly

`curl -sI <host>` headers are 80% of the fingerprint:

- `Server:` — apache / nginx / cloudflare / kestrel (= .NET Core) / openresty / envoy
- `X-Powered-By:` — PHP version, ASP.NET version, Express.js
- `X-Drupal-Cache`, `X-Generator: Drupal 9` — Drupal
- `X-Generator: WordPress` — WordPress
- `Via:` — CDN chain (1.1 varnish, 1.1 cloudfront)
- `Set-Cookie:` names — `JSESSIONID` (Java), `PHPSESSID` (PHP), `ASP.NET_SessionId` (.NET), `connect.sid` (Express), `laravel_session` (Laravel)

JS bundle filename patterns:

- `/_next/static/` = Next.js
- `/_nuxt/` = Nuxt
- `/assets/static/` with hash filenames = Vite
- `/static/js/main.*.chunk.js` = Create React App
- `runtime.*.js + polyfills.*.js + main.*.js` = Angular CLI

The first 10s of recon should yield a stack guess; the rest is targeting. If your fingerprint contradicts itself (Server says nginx, Set-Cookie says ASP.NET) you've found a reverse proxy front-end — note the origin app for later smuggling/cache attacks.

### Same-IP alternate-service discovery (don't stop at the web app)

After resolving the target IP, always run a port scan (`nmap --top-ports 1000` or `naabu`) and HTTP-probe the open ports. Admin/security infrastructure is frequently co-located on the same host even when the public web app is hardened. High-signal services to recognize from headers/body:

| Port(s) | Service | Fingerprint |
|---|---|---|
| 8080 | Kaspersky Security Center Web Console | `meta[name=author]=Kaspersky`, `Version: 15.x` in footer, login form with "Administration Server" |
| 3800/3809 | Splunk Web / splunkd REST | `Server: Splunkd`, Atom XML feed with `<generator version="10.x">`, `/services` returns XML |
| 9200 | Elasticsearch | JSON `security_exception`, `WWW-Authenticate: Basic/Bearer/ApiKey`, port 9200 |
| 9100+ | Various admin panels | `connect.sid` cookies (Express), `/actuator` (Spring Boot), `/_cat/indices` (ES) |

These may be exposure findings even when authenticated (should not be on public Internet), and they seed follow-up CVE/default-credential/rate-limit testing if in scope. See `references/spa-api-base-and-fallback-recon.md` § 4 for the probe recipe.

### GitHub Pages 404 vs takeover signal

Critical distinction operators get wrong:

- **"Page not found · GitHub Pages"** with HTTP 404 means the repo EXISTS — NOT a takeover.
- **"There isn't a GitHub Pages site here"** means the repo was deleted — TAKEOVER candidate.

Same distinction for CloudFront:

- **"Error - 404"** with `Server: CloudFront` = distribution exists, origin returned 404 — NOT a takeover.
- **"The request could not be satisfied"** with `X-Cache: Error from cloudfront` = origin missing entirely — potential takeover.

Phase 2C verified both patterns live. Always check the EXACT response body string before filing a takeover finding — the takeover-scanner tools (subzy, subjack) match on multiple fingerprints and frequently false-positive on the "still owned, just empty" case.

### Subdomain source reliability on large enterprise targets (2026)

Not all free passive sources are equal. During an atlassian.com recon pass (87 subdomains collected), the reliability ranking was:

| Source | Subdomains | Reliability | Notes |
|---|---|---|---|
| HackerTarget API | 51 | High | Free, no key, CSV output. Best single free source for enterprise domains. |
| RapiddNS | 38 | High | Free, no key. Scrapes CT logs + other sources. Good overlap coverage. |
| web.archive.org CDX | 6 (hostnames) | Medium | Free, extracts hostnames from historical URLs. Low yield but finds hosts others miss. |
| crt.sh | 0 (502) | Low (frequently down) | Often returns 502 Bad Gateway or JSON parse errors. Use `%25` encoding not raw `%`. Don't block on it. |
| subfinder | (timed out at 120s) | Medium (slow) | Hangs on large enterprise domains. Use `-timeout 3` per-source + background execution. |
| waybackurls | 0 | Low | Frequently returns nothing on large targets. Use web.archive.org CDX API directly instead. |
| assetfinder | N/A | Not installed by default | Install via `go install github.com/tomcat/assetfinder@latest` or skip. |
| Chaos API | 0 (401) | Requires key | Free key at chaos.projectdiscovery.io. Worth setting up but don't block on it. |

**Lesson:** Never depend on a single source. Run HackerTarget + RapiddNS + web.archive.org CDX in parallel as the minimum free baseline, then layer subfinder in the background. crt.sh is a bonus when it works, not a dependency. Merge all sources and deduplicate before DNS resolution.

### Parallel dig-based DNS resolution (when dnsx is unavailable or unreliable)

When dnsx segfaults or produces corrupted output, use Python `concurrent.futures` with `dig` for fast parallel resolution. This resolved 83/87 atlassian.com subdomains in ~6 seconds:

```python
import subprocess, concurrent.futures, re

with open('subdomains_all.txt') as f:
    hosts = [l.strip() for l in f if l.strip()]

def resolve(host):
    try:
        r = subprocess.run(['dig', '+short', '+tries=1', '+time=3', host, 'A'],
                          capture_output=True, text=True, timeout=5)
        ips = [l.strip() for l in r.stdout.strip().split('\n')
               if l.strip() and re.match(r'^\d+\.', l.strip())]
        if ips:
            return f"{host}|{','.join(ips)}"
    except:
        pass
    return None

resolved = []
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    futs = {ex.submit(resolve, h): h for h in hosts}
    for f in concurrent.futures.as_completed(futs):
        r = f.result()
        if r:
            resolved.append(r)

resolved.sort()
print(f"Resolved: {len(resolved)}")
```

**Same-IP clustering signal:** After resolution, group hosts by IP. Multiple hostnames pointing to the same IP (e.g. `api.atlassian.com`, `api-private.atlassian.com`, `auth.atlassian.com`, `aug.atlassian.com`, `beta-developer.atlassian.com` all → `13.227.180.4`) reveals shared CloudFront/CDN distributions. These shared-origin hosts are prime candidates for Host-header injection, cache poisoning, and origin-bypass testing — the same backend serves different virtual hosts, so header manipulation may cross-contaminate responses.

### Cross-TLD pivot via inline env config (JSON script tags)

SPAs frequently embed a full environment config as an inline `<script type="application/json">` tag in the HTML — not as a `window.__ENV__` assignment and not in `.env` files. These configs leak sibling domains, internal infrastructure hostnames, API gateway URLs, Sentry DSNs, and third-party service endpoints.

**Pattern:** Look for `<script id="__APP_ENV__" type="application/json">` or similar inside the HTML body. The JSON contains API base URLs, auth endpoints, analytics collectors, and often references to entirely different domains (sibling TLDs, internal infra).

```bash
# Extract inline env JSON from HTML
curl -sk "https://$TARGET" | grep -oP '<script[^>]*type="application/json"[^>]*>.*?</script>' | \
  sed 's/<script[^>]*>//;s/<\/script>//' | python3 -m json.tool

# Grep for sibling domains, internal hostnames, API gateways
curl -sk "https://$TARGET" | grep -oP '<script[^>]*type="application/json"[^>]*>.*?</script>' | \
  grep -oP 'https?://[^\s"'"'"']+' | sort -u
```

**High-value fields to extract:**
- `apiUrls.*` / `apiUrl` / `baseUrl` — API gateway base URLs (often on different subdomains)
- `auth.*` / `authApiUrl` — auth flow endpoints
- `sentry.dsn` — Sentry DSN (reveals internal hostname + project ID)
- `analytics.collectorUrl` / `telegrafApiUrl` — telemetry endpoints
- `abApiUrl` / `abProjectId` — A/B testing project IDs (test unauth feature flag access)
- Any `https://` URL referencing a different domain — sibling TLD pivot

**Lesson from a bancoplata.mx engagement:** A single env config on `empresa.bancoplata.mx` (`__PYME_WEB_ENV__` script tag) revealed `platacard.mx` (card brand sibling, 49 more subdomains), `diftech.net` (internal infra with VPN, Sentry, OpenReplay — 21 more subdomains), `prime.bancoplata.mx` (API gateway with 60+ endpoints), and a Sentry DSN pointing to `sentry.prime.diftech.org`. Always grep env configs for domains that differ from the target's primary domain — this is the highest-yield single request in recon.

### S3 bucket discovery via Cloudflare-proxied subdomains

Some subdomains serve as Cloudflare proxies to non-public S3 buckets. The bucket itself returns `AccessDenied` on direct S3 access, but the Cloudflare proxy at the subdomain serves the bucket listing and object contents. This creates a public read interface to a bucket that appears private.

**Detection:**
```bash
# Check for S3 bucket listing on subdomain
curl -sk "https://$SUBDOMAIN/" | grep -i "ListBucketResult\|NoSuchBucket\|AccessDenied"
# If ListBucketResult: bucket is publicly listable via this proxy
# Extract the bucket name from the XML response
curl -sk "https://$SUBDOMAIN/" | grep -oP '<Name>[^<]+</Name>'
# Try direct S3 access (should fail if proxied correctly)
curl -sk "https://$BUCKET_NAME.s3.amazonaws.com/" | head -5
# The x-amz-bucket-region header on the direct S3 403 confirms the bucket exists and leaks its region
curl -sI "https://$BUCKET_NAME.s3.amazonaws.com/" 2>/dev/null | grep -i x-amz-bucket-region
```

**Key insight:** A `403 AccessDenied` on the direct S3 URL does NOT mean the bucket is private. Always check if a subdomain proxies to it. The `x-amz-bucket-region` header on the direct S3 response confirms the bucket exists and leaks its region even on denied requests.

**Lesson from a bancoplata.mx engagement:** `certs.platacard.mx` served as a Cloudflare proxy to `vault-pki-storage-prod` S3 bucket (us-west-2). Direct S3 access returned `AccessDenied`, but the Cloudflare proxy at `certs.platacard.mx` returned a full `ListBucketResult` XML with all object keys (HashiCorp Vault PKI certificates, CRLs). The bucket name was visible in the XML `<Name>` field.

### VPN group name enumeration from Cisco ASA XML auth

Cisco ASA VPN portals (`vpn.*`, `cvpn.*`) return an unauthenticated XML response on `GET /` that leaks all configured VPN group names. These group names reveal internal org structure and enable targeted brute-force attacks.

```bash
# Cisco ASA VPN group enumeration (unauthenticated)
curl -sk "https://vpn.$TARGET/" | grep -oP '<option value="[^"]+"'
# Returns: vpn-devops, vpn-developers, vpn-pentest-co, etc.

# Cisco AnyConnect VPN (different path)
curl -sk "https://cvpn.$TARGET/+CSCOE+/logon.html" | grep -oP 'action="[^"]*"'
# Check for SAML endpoint: /+CSCOE+/saml/sp/login
```

**Pitfall:** The XML response is served by the ASA's webvpn module. If the target uses a different VPN solution (Pritunl, NetBird, OpenVPN), the response format differs. Check `Server` header and response body format to fingerprint the VPN type. Pritunl returns an HTML login page, NetBird returns a Next.js dashboard with `/api/*` endpoints requiring auth.

### Sentry DSN extraction from env configs

Sentry DSNs embedded in client-side env configs reveal internal infrastructure hostnames and project IDs. The DSN format is `https://{key}@{host}/{project_id}`.

```bash
# Extract Sentry DSN from env config
curl -sk "https://$TARGET" | grep -oP 'sentry[^}]*"dsn"\s*:\s*"[^"]+"'
# Test if the Sentry API is accessible
curl -sk "https://$SENTRY_HOST/api/0/" | head -5
# Test the envelope endpoint (responds with auth validation messages)
curl -sk -X POST "https://$SENTRY_HOST/api/$PROJECT_ID/envelope/" \
  -H "Content-Type: text/plain" \
  -d '{"event_id":"test","sent_at":"2026-01-01T00:00:00Z"}'
```

**Risk:** An exposed Sentry DSN can be used to inject crafted error events (polluting the error stream) or to query the Sentry API for existing error data (stack traces, internal paths, user data) if the project has weak auth. The Sentry hostname itself reveals internal infrastructure (e.g. `sentry.prime.diftech.org` reveals the `diftech.org` domain).

### Toolchain fallback

Already covered in this file's Phase 2C addition. Quick reminder: dnsx/httpx may segfault on macOS arm64; the dig+curl fallback works for < 100-host runs in ~14 seconds. Don't burn an hour debugging Go binary panics when the fallback gets you to the same URL set.

### dnsx ANSI color codes corrupt output files (Linux)

On some Linux builds, `dnsx -resp` writes ANSI escape sequences (`\x1b[35m`, `\x1b[0m`, etc.) into output files even with `-silent` and `-no-color` flags. Any downstream parser (Python `re`, `awk`, `jq` pipelines) will silently fail to match patterns because the escape codes sit inside the IP brackets. Always strip ANSI before parsing resolved output:

```bash
sed -r 's/\x1b\[[0-9;]*m//g' resolve.txt > resolve.clean.txt
```

```python
# In Python, strip ANSI before regex
import re
clean = re.sub(r'\x1b\[[0-9;]*m', '', raw_output)
```

### httpx may silently produce empty output files (Linux)

If `httpx -l hosts.txt -o out.txt` creates a 0-line file despite known-live hosts, fall back to the Python `urllib` + `concurrent.futures` probe below rather than debugging the binary. The serial curl fallback in the toolchain section also works but is slower for > 50 hosts.

```python
import ssl, urllib.request, concurrent.futures, re
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def probe(host):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                body = r.read(8192).decode(errors='ignore')
                title = (re.search(r'<title[^>]*>([^<]+)</title>', body, re.I) or [None,''])[1].strip()
                return f"{url} [{r.status}] [{r.headers.get('Server','')}] [{title[:60]}] [cl={r.headers.get('Content-Length','')}]"
        except Exception as e:
            err = str(e)[:50]
            if any(c in err for c in ['403','401','404']):
                return f"{url} [{err[:3]}] [blocked/auth]"
            continue
    return None

with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    futs = {ex.submit(probe, h): h for h in hosts}
    for f in concurrent.futures.as_completed(futs):
        r = f.result()
        if r: print(r, flush=True)
```
