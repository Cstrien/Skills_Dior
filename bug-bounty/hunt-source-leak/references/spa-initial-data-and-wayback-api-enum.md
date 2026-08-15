# SPA window.* Config Leak + Wayback API Endpoint Enumeration

Two high-yield recon techniques for modern SPA targets (Vue, React, Next.js, Nuxt).
Both are unauth, passive, and produce an attack-surface map before any active probing.

## 1. SPA `window.INITIAL_DATA` / `window.__*` Config Leak

### Pattern

Modern SPAs inject server-side config into a `<script>` tag in the HTML `<head>`
before the JS bundle loads. The variable name varies (`INITIAL_DATA`, `__INITIAL_STATE__`,
`__APOLLO_STATE__`, `__NEXT_DATA__`, `__NUXT__`), but the content is the same: a JSON
blob with runtime configuration, internal infrastructure references, and sometimes
secrets.

### How to extract

```bash
# Fetch the page and extract the INITIAL_DATA blob
curl -sk -A "Mozilla/5.0" "https://target.com/" \
  | grep -oP 'window\.\w+\s*=\s*\{[^}]*\}' | head -5

# Or: capture the full script block and pretty-print
curl -sk -A "Mozilla/5.0" "https://target.com/" -o page.html
python3 -c "
import re, json
html = open('page.html', errors='ignore').read()
m = re.search(r'window\.(\w+)\s*=\s*(\{.*?\});', html)
if m:
    name, blob = m.group(1), m.group(2)
    print(f'Variable: window.{name}')
    try: print(json.dumps(json.loads(blob), indent=2)[:2000])
    except: print(blob[:2000])
"
```

### What to look for (high-signal keys)

| Key | What it leaks | Next step |
|-----|--------------|-----------|
| `traceId` / `requestId` | Internal trace/logging ID | Enumerate trace IDs for request correlation |
| `ip` / `country` / `subdivision` | Server-side geo-IP detection | Confirm IP detection → geo-bypass testing |
| `cdnDomain` / `staticSrc.cdn` | Internal CDN domain | Enumerate CDN for asset misconfig |
| `cda.domain` | Content delivery/anti-bot domain | Test CDA bypass |
| `afh.routerDomain` | Anti-fraud/anti-headless router | Test AFH bypass |
| `sduiConfig.hash` | Server-driven UI config hash | Fetch SDUI templates with hash |
| `appLocaleId` | Internal locale ID mapping | Test locale-based access control |
| `api.global` / `api.custom` | Custom API base URL | Test API endpoints directly |
| `imgproxy.url` | Internal imgproxy endpoint | SSRF test via image proxy |
| `forbiddenEndpoints` | List of blocked endpoints | Confirm what they're trying to protect → hunt there |
| `redirectFishing.domains` | Redirect-fishing domain list | Test redirect manipulation |
| `firebaseOptions` / `amplitudeApiKey` | Third-party service keys | Test key permissions |

### Assessment

`window.INITIAL_DATA` is an **attack-surface map**, not a standalone bug. Follow
`js-analysis-anti-false-positive` discipline:
- `cdnDomain`, `appLocaleId`, `traceId` alone → Low/Informational (internal infra mapping)
- `forbiddenEndpoints` list → High-signal hunting target (they blocked it for a reason)
- `imgproxy.url` with SSRF → chainable to Critical
- `firebaseOptions.apiKey` with misconfigured rules → chainable to data access

Do NOT report the blob alone. Report what it enables you to reach.

---

## 2. Wayback CDX API Endpoint Enumeration

### When to use

When the target is a SPA with `/api/*` microservice backend and you need to map
the API surface without active fuzzing (which may trigger WAF/bot management).

### Technique

```bash
# Query Wayback CDX for all archived /api/ paths
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/api/*&output=text&fl=original&collapse=urlkey&limit=1000" \
  | sort -u > wayback_api.txt

# Extract unique API paths (strip query params)
grep -oP 'https://target.com/api/[^?&]+' wayback_api.txt \
  | sort -u > api_endpoints.txt

wc -l api_endpoints.txt
cat api_endpoints.txt
```

### Why this works

Wayback archives API responses, not just HTML. The CDX `collapse=urlkey` dedupes
URLs so you get a clean list of unique API paths. The `output=text` format gives
one URL per line, easy to pipe.

### What to look for

| Pattern in API path | Hunting opportunity |
|---|---|
| `/api/MS-*/v*-*` | Microservice naming convention (MS-BONUS-BALANCES, MS-SMALL-THINGS) |
| `/api/internal/*` | Internal API exposed externally |
| `/api/USER-SERVICE-API/*` | Auth/user service → auth bypass, IDOR |
| `/api/FREE-MONEY/*` | Bonus/raffle endpoints → business logic |
| `/api/PROXY-SERVICE-*/v1-*` | Proxy service → SSRF, request smuggling |
| `/api/web/v1/user` | User endpoint → auth bypass, info disclosure |
| `/api/fss/conf/*` | Feature/config service → config dump |
| `/api/translations/*` | Translation service → low value usually |

### Test discovered endpoints

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

# Test each endpoint unauthenticated
while read url; do
  resp=$(curl -sk -A "$UA" "$url" -w "\n%{http_code}" 2>&1)
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -1 | head -c 200)
  echo "[$code] $url → $body"
done < api_endpoints.txt
```

### Rate-limit pitfall

Some targets (e.g., behind Cloudflare Bot Management) will start returning 403
after 10-20 rapid API requests. **Capture successful responses immediately** —
the first request to each endpoint is usually clean. Space requests 2-3 seconds
apart if you need to enumerate many endpoints. A 403 after a successful 200 does
not invalidate the earlier finding — save the evidence.

---

## Session Example: 1win.com Casino

From an authorized private engagement on 1win.com/casino:

**INITIAL_DATA leak** revealed: `traceId`, client IP/country, `cdnDomain`
(v3.bundlecdn.com), `cda.domain` (bundlecda.com), `afh.routerDomain`
(flowmetric.life), `sduiConfig.hash`, `appLocaleId`, `regionalAccessPolicy`.

**Wayback CDX API enumeration** found 49 unique API paths including:
- `MS-BONUS-BALANCES/v2-bonus-list` — returned full bonus catalog unauthenticated
  (bonusId, depositPercent, minDeposit, maxBonusAmount, wagerMultiplier, S3 image URL)
- `internal/casino-categories` — returned 16,774 games + IDs + providers unauthenticated
- `USER-SERVICE-API/api-v3-oauth-config` — returned OAuth client_ids + internal
  redirect domain `vv-ftend-3.com`
- `MS-SMALL-THINGS/rules-all` — required `locale` param (400 without, 403 with after rate-limit)

**S3 bucket name disclosure** from forum.1win.com page source:
`web-k8s-forum-prod.s3.eu-central-1.amazonaws.com` (Invision Community uploads).
The bucket denied listing (403) but individual files were accessible.

**Key lesson**: The CDX API enumeration + INITIAL_DATA extraction combo mapped the
entire attack surface in 2 minutes of passive recon, before any active probing
that would have triggered Cloudflare Bot Management blocks.

---

## 3. JS Bundle Module Extraction — Endpoints Hidden in Sub-Modules

### When to use

After downloading the main JS bundle, the initial grep for API paths finds
~20 endpoints. But large SPAs (Vue, React, Next.js) split code across dozens
of lazy-loaded modules (`assets/*.js`). Critical auth/registration/payment
endpoints often live ONLY in these sub-modules, not in the main bundle.

### Technique

```python
import re, subprocess, os

# Step 1: Extract all module references from the main bundle
with open("main_bundle.js", "r", errors="replace") as f:
    js = f.read()

# Match "assets/name-hash.js" and "./module-name.js" patterns
all_assets = re.findall(r'"((?:assets/)[^"]+\.js[^"]*)"', js)
all_assets = list(set(all_assets))
print(f"Found {len(all_assets)} module references")

# Step 2: Fetch modules with interesting names
keywords = ['auth', 'user', 'oauth', 'bonus', 'billing', 'casino', 'payment',
            'deposit', 'wallet', 'game', 'balance', 'token', 'api', 'setup',
            'plugin', 'config', 'query', 'fetch', 'logger', 'amplitude',
            'firebase', 'recaptcha', 'captcha', 'geetest', 'betting', 'bet']

priority = [a for a in all_assets if any(k in a.lower() for k in keywords)]

# Step 3: Download priority modules
base = "https://target.com/resources/v1/app/"
for mod in priority:
    url = base + mod
    fname = f"/tmp/jsmod_{mod.split('/')[-1]}"
    subprocess.run(["curl", "-sk", "-A", ua, "--max-time", "10",
                    url, "-o", fname], timeout=15)

# Step 4: Extract API paths from ALL downloaded modules
all_js = ""
for f in os.listdir("/tmp"):
    if f.startswith("jsmod_"):
        with open(f"/tmp/{f}", "r", errors="replace") as fh:
            all_js += fh.read() + "\n"

# This regex catches most microservice API patterns
api_paths = re.findall(
    r'["\'](?:/api/|/USER|/web/v|/internal/|/CASINO|/MS-|/FREE|/PROXY|/v1/|/v2/|/domains/)[^"\']+["\']',
    all_js, re.I
)
for p in sorted(set(api_paths)):
    print(f"  {p}")
```

### Why this works

The main bundle is the entry point, but auth/registration/payment modules are
lazy-loaded. The main bundle contains import references like
`"assets/use-oauth-finish-C7OpfQ7T.js"` — fetching and analyzing these
sub-modules reveals endpoints that the main bundle never references directly.

### Session example (1win.com)

Main bundle grep found 21 API paths. Sub-module extraction found additional
endpoints not in the main bundle:

| Module | New endpoints found | What they revealed |
|---|---|---|
| `use-oauth-finish` | `/USER-SERVICE-API/api-v3-oauth-social`, `/web/v1/auth/login`, `/domains/exist` | Auth flow: prepare → oauth-social → login |
| `logger` | `/api/v1/ms-affiliate-links/coreAuthVisit`, `/api/v1/seotext` | Tracking endpoints |
| `plugin-feature-flags` | `/USER-SERVICE-API/api-v1-balances-get-activated`, `/USER/visitor-save` | Balance API, visitor tracking |
| `use-game-session` | `/CASINO-3/bff-v0-categories` (BFF endpoint) | BFF API gateway pattern |
| `round-external` | `/v1/token-api/public/rounds`, `/v1/token-api/public/token/sale_state` | Token sale API |

### Auth flow mapping from module code

Reading the module source (even minified) reveals the request sequence and
parameter expectations. For 1win.com, the `use-oauth-finish` module showed:

```javascript
// Registration prepare (no captcha required)
ht="/USER-SERVICE-API/api-v3-user-new-prepare"
// POST body: {data:{email, password}} → returns {state:"<6-char>"}

// Social OAuth
wt="/USER-SERVICE-API/api-v3-oauth-social"
// POST body: {data:{socialId, code, state}}

// Login (captcha required)
_t="/web/v1/auth/login"
// POST body: {login, password} → 403 captcha.required without GeeTest
```

This mapping revealed that registration prepare works WITHOUT captcha while
login requires it — a business logic differential worth testing.

---

## 4. Captcha Differential Testing

### Pattern

When a target uses captcha (GeeTest, reCAPTCHA, hCaptcha), not all endpoints
enforce it equally. Test every auth-adjacent endpoint for captcha requirements:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

# Registration prepare — does it require captcha?
curl -sk -A "$UA" -X POST -H "Content-Type: application/json" \
  -d '{"data":{"email":"test@test.com","password":"Test123!"}}' \
  "https://target.com/api/USER-SERVICE-API/api-v3-user-new-prepare"
# → {"state":"olpugj"} (200 OK — NO captcha)

# Login — does it require captcha?
curl -sk -A "$UA" -X POST -H "Content-Type: application/json" \
  -d '{"login":"test@test.com","password":"Test123!"}' \
  "https://target.com/api/web/v1/auth/login"
# → {"error":{"code":"captcha.required"}} (403 — captcha required)
```

### What to look for

| Endpoint | Expected | Actual | Finding |
|---|---|---|---|
| Registration prepare | Captcha | No captcha | **State token issued without verification** |
| Login | Captcha | Captcha required | Normal |
| Password reset | Captcha | No captcha | **Brute-force reset token** |
| Email change | Captcha | No captcha | **Account takeover chain** |
| OAuth callback | State validation | No state check | **CSRF / account linking** |

### Session example (1win.com)

`api-v3-user-new-prepare` accepted ANY email (including `admin@1win.com`,
`support@1win.com`) with no captcha, no rate limit, and returned a state token.
5 rapid sequential requests all succeeded. The completion endpoint was not
findable via curl (likely requires browser with captcha), but the state token
generation itself is an uncontrolled primitive.

---

## 5. Unauthenticated Business Logic Endpoint Testing

### Pattern

After Wayback CDX enumeration, test every discovered endpoint unauthenticated.
Many microservice APIs return real data without auth — especially bonus/raffle/
exchange/payment-config endpoints that the frontend fetches before login to
display promotional content.

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

# Test each endpoint — GET and POST with empty/minimal body
for ep in $(cat api_endpoints.txt); do
  # GET
  resp=$(curl -sk -A "$UA" "$ep" -w "\n%{http_code}")
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -1 | head -c 200)
  [ "$code" = "200" ] && echo "[GET $code] $ep → $body"

  # POST with empty JSON
  resp=$(curl -sk -A "$UA" -X POST -H "Content-Type: application/json" \
    -d '{}' "$ep" -w "\n%{http_code}")
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -1 | head -c 200)
  [ "$code" = "200" ] && echo "[POST $code] $ep → $body"
done
```

### High-value endpoint patterns

| Pattern | What it may return unauth | Impact |
|---|---|---|
| `*/bonus-*` | Bonus IDs, wager multipliers, deposit limits | Bonus abuse planning |
| `*/raffle-*` | Raffle config, prize details, live stream URLs | Data leak + stream access |
| `*/exchange-rates*` | Full crypto/fiat rate catalog | Low alone, confirms API gateway unauth |
| `*/categories*` | Product/game catalog, internal IDs | IDOR seed list |
| `*/oauth-config*` | OAuth client_ids, redirect URIs | OAuth chain testing |
| `*/balance*` | Account balances (if IDOR possible) | Financial data leak |
| `*/pwa-amount*` | Promotional bonus amounts | Business logic exposure |

### Session example (1win.com)

| Endpoint | Auth | Returned data | Severity |
|---|---|---|---|
| `FREE-MONEY/v1-bonus-pwa-amount?currency=USD` | None | `{"success":true,"amount":200}` | Medium |
| `FREE-MONEY/v2-raffle-getCurrent?currency=USD` | None | Raffle config + HLS stream URL | Low-Med |
| `MS-BONUS-BALANCES/v2-bonus-list?currency=USD` | None | Bonus IDs, wager data, S3 URLs | Medium |
| `internal/casino-categories` | None | 16,774 games, IDs, providers | Low-Med |
| `PROXY-SERVICE-CDP/v1-landings-GetExchangeRates` | None | All crypto/fiat rates | Low |
| `CASINO-3/bff-v0-categories?withVip=true` | Required (401) | Error code 601 — confirms VIP content | Info |

### Rate-limit pitfall

Cloudflare Bot Management targets return 403 after 10-20 rapid requests.
**Capture the first successful response immediately** — save it to disk. A
403 on retry does NOT invalidate the earlier 200. Space requests 2-3 seconds
apart when enumerating many endpoints.
