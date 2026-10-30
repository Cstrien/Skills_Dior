# Next.js API-Signing Secrets, Hidden Routes, and Custom Captcha Headers

From the ticketbox.vn assessment (Oct 2026). Seven verified patterns for Next.js targets that sign API requests client-side.

---

## Pattern 1 — HMAC request-signing secret hardcoded in a public chunk

Apps that sign API requests client-side MUST ship the signing secret to the browser. It lives in a webpack module — usually adjacent to an `api_key` constant and a WebCrypto HMAC routine.

**Where to look**: any chunk containing `crypto.subtle.importKey` + `crypto.subtle.sign("HMAC"`.

**Extraction** (verbatim minified source from chunk `943-*.js`, module 51188):

```js
let l = async e => {
  let t = Object.keys(e).sort().reduce((t, r) => `${t}|${r}=${e[r]}`, ""),   // canonical string
      r = new TextEncoder,
      n = r.encode(t),
      l = r.encode("<40-char secret — plaintext in bundle>"),
      o = await window.crypto.subtle.importKey("raw", l, {name: "HMAC", hash: "SHA-256"}, !1, ["sign"]);
  return Array.from(new Uint8Array(await window.crypto.subtle.sign("HMAC", o, n)))
    .map(e => e.toString(16).padStart(2, "0")).join("")                       // hex
}
```

**Python replication** (verified byte-identical):

```python
def sign(d):
    s = "".join(f"|{k}={d[k]}" for k in sorted(d))
    return hmac.new(SECRET.encode(), s.encode(), hashlib.sha256).hexdigest()
```

The wrapper adds `api_key` + `requested_at` to every request body, then `signature`. Replicating this let us mint `device_token` JWTs via the device-registration endpoint (`POST /v1/users/devices`) and talk to the whole signed API surface directly — defeating the request-signing/anti-abuse layer even without account access.

## Pattern 2 — JS endpoint strings ≠ deployed routes: hook fetch and drive the real UI

Static JS strings said `/users/password/forgot` (plus `/v1|v2/users/otps/send` etc.) — **every one 404'd** when probed directly. The actually-fired route was `/v2/users/forgot-password` (kebab-case, different version, different host). Route strings in stale/renamed bundles are unreliable.

**Definitive method** — hook fetch, then click through the real UI flow:

```js
const orig = window.fetch;
window.__cap = [];
window.fetch = function(...a) {
  const u = typeof a[0]==='string' ? a[0] : a[0]?.url;
  if (u && /api/.test(u)) window.__cap.push({u, m: a[1]?.method, b: a[1]?.body ? String(a[1].body) : null});
  return orig.apply(this, a);
};
// → click through the flow in the page, then read window.__cap
```

Read `window.__cap` after the request fires. If a disabled button blocks the flow (captcha pending), `btn.disabled = false; btn.click()` — some apps gate only client-side (itself a finding when the server doesn't re-validate). Supplement with `performance.getEntriesByType('resource')` if the hook missed a request.

## Pattern 3 — Captcha token in a custom header, not the body

The API demanded a captcha but rejected every body param tried (`token`, `captcha_token`, `recaptcha_token`, `g-recaptcha-response`, ...) with `"recaptcha token is required"`.

**Fix**: grep ALL downloaded chunks for the literal `Recaptcha`/`captcha` — the header name appeared in another chunk's request-builder module:

```
g["X-Tb-Recaptcha-Token"] = t
```

Custom `X-*-Token` headers are a common home for captcha tokens. When body-param brute force fails, grep the bundle for `Token"` and `captcha` case-insensitively before concluding the param is unknown.

## Pattern 4 — Minting a valid reCAPTCHA Enterprise v3 token headless

The page ran reCAPTCHA Enterprise (v3-style `grecaptcha.enterprise`) **and** a decorative Turnstile badge. In a headless browser on the real origin:

```js
const g = window.grecaptcha.enterprise;
await new Promise(r => g.ready(r));
const tok = await g.execute('0', {action: 'forgot_password'});   // widget id '0'
```

The token **passed server-side validation** — the follow-up request reached business logic. Two lessons:
- v3/Enterprise scoring did not hard-block an automated browser at default threshold.
- A scary-looking Turnstile badge may be decorative for a given flow — identify which captcha the endpoint actually validates (React fiber walk below) before burning time defeating the wrong one:

```js
document.querySelectorAll('*').forEach(el => {
  const rk = Object.keys(el).find(k => k.startsWith('__reactFiber'));
  // walk .return chain; look at memoizedProps for {sitekey, onVerify, ...}
});
```

## Pattern 5 — Full-chunk enumeration + per-module base URLs

The CDN 403'd `/_next/static/*` with a default curl UA; a browser UA got 200. To map the whole client:

1. `GET /_next/static/<buildId>/_buildManifest.js` → all page routes + chunk names (~107 chunks, seconds to download in parallel with browser UA).
2. **Resolve each route's host before probing**: different fetch-wrapper modules carry different default `baseUrl`s (here: `api-v2.../event/api`, `api-movie.../v1`, `/v2`, `/admin`). The same path string may be valid on only one host/prefix — trace the module's import chain (`x=n(<module-id>)` → module's `baseUrl)||"..."` default) before curling.

## Pattern 6 — Two-tier captcha: which gate applies to which endpoint

`GET /v2/users/login-methods?platform=web` (unauth) returned `{"google":true,"version":4}` — version 4
meant the **Turnstile** path was active for login/sign-up, while OTP and forgot-password stayed on
reCAPTCHA Enterprise. When a target runs both:

- reCAPTCHA Enterprise endpoints: mint tokens headless via `execute()` (Pattern 4) — attackable.
- Turnstile-gated endpoints (sitekey `0x4AAAA...`): **hard stop in automation browsers**. The interactive
  checkbox never solves in headless Chromium (stays idle, silent error), `turnstile.render()` with your
  own callback times out without producing a token, and server validation rejects fabricated tokens
  (`invalid turnstile`). Don't burn rotation time on it — pivot to reCAPTCHA-gated endpoints or ask
  the user for a real-browser-registered test account.

The full auth-component config often sits in a **dynamic chunk not listed in `_buildManifest.js`**
(load it by triggering the login modal, then read `performance.getEntriesByType('resource')`): it
contained `apiBaseURL`, the Turnstile sitekey, the Google client_id, **and a dev-domain leak**
(`api-v2.ticketbox.dev` alongside the production base — check dev domains for DNS resolution and
weaker posture).

Also grep for **cookie-based captcha tokens**: `getTKBCaptcha:e=>c(`tkc_${e}`)` shows the app reads a
`tkc_<key>` cookie set by an image/drag-captcha module — meaning some endpoints take their captcha
from a cookie you may be able to set yourself.

## Pattern 7 — Route fuzzing recipe for Go/gin backends

When static JS routes all 404, fuzz route names directly with `POST {}` and classify by response body:

- `404 page not found` (plain text, gin) = route missing — skip
- `{"errors":[{"extensions":{"code":"bad_request"...` = route EXISTS, param validation running
- `invalid_device_token` = route exists; supply the forged device token from Pattern 1
- `captcha token is required` / `recaptcha token is required` = route exists, needs the captcha header

Fuzz **both snake_case and kebab-case variants** of each logical name across `/v1/` and `/v2/` prefixes,
in parallel (~15 threads). Ticketbox's v2 surface used kebab-case (`forgot-password`, `sign-up`,
`otps`) while stale JS still referenced snake-case v1 paths — this surfaced 9 live routes the static
grep missed.

## Anti-enumeration note (avoid a false positive)

Both a nonexistent email and a plausible corporate email returned byte-identical `invalid_email_v2` errors. Do NOT claim user enumeration on a forgot-password endpoint until you have one **confirmed-registered** account to diff against. Register a test account first, then compare.

Also verify the HMAC forge PoC with two independent stacks (Python `hmac` + browser WebCrypto) per the multi-tool reproduction bar — the ticketbox forge was confirmed by both before being reported.

## Engagement quirks

- HAProxy hosts behind `oauth2-proxy` (Google SSO): `/oauth2/start?rd=<url>` embeds the target in OAuth `state` — tested, not an open redirect (`/oauth2/sign_out` normalizes to `/`).
- `www.` host may 301 while apex serves the app — probe both.
- Backend fingerprinting by 404 body: Go/gin returns `"404 page not found"` plain; Node returns `"Cannot POST /path"` — tells you which backend a route lives on.
- Go-gin JSON APIs return HTTP 200 with an `errors[]` array in the body (status inside `extensions.status_code`) — don't rely on status codes alone; parse the body.
