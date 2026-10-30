---
name: akamai-protected-flow-testing
description: Use when a target returns 428 sec-cp-challenge JSON.
tags: [waf-bypass, akamai, api-testing, auth-bypass]
related_skills: [bb-methodology, web2-recon, hunt-api-misconfig, proxy-waf-bypass, hunt-ato]
version: 1.0.0
---

# Akamai-Protected Flow Testing

## When to Use

Load this skill when any of these signals appear on a target:

Verified patterns from an authorized e-commerce engagement (Oct 2026). Every claim here was
tested live against a real Akamai estate (Bot Manager + mPulse + sec-cp-challenge). Companion
reference: `references/akamai-428-crypto-challenge-and-webpack-runtime.md` (full transcripts).

## When this triggers

- Any POST/auth endpoint returns **HTTP 428** with JSON `{"sec-cp-challenge": "true", "provider": "crypto", ...}`
- Manual API replay gets `400 {"code":1001,"message":"Invalid input"}` while the real app succeeds
- `curl`/`urllib` return **empty bodies or connection drops with no error** on an Akamai host
- App works in browser; identical request hand-built in the page console gets 428

## The 428 sec-cp-challenge — what mining does and does not solve

The 428 body carries a PoW challenge (`token` ~342 chars base64url = 256 raw bytes,
`difficulty` ~15000, `nonce`, `verify_url`). Two things people get wrong:

1. **Solving the PoW is not enough.** Finding `sha256(salt||counter)` below target and
   POSTing `{"nonce": N}` / `{"answer": N}` / raw N to `verify_url` returns
   `{"success":false}` 403 regardless. The challenge binds to the browser sensor session.
2. **The app's own request layer passes; your fetch doesn't.** The SPA's bundled client
   carries sensor-bound state a hand-built `fetch` from the same page lacks. Practical rule:
   **drive the app's UI path** (React state mutation, real key events) — do not hand-roll
   fetches from the console when you need a request through.

Behavioral asymmetry on one host (all verified): `emaillogin` POST = silent connection RST;
`recoverpass` POST = no challenge ever; `getotp`/`verifyotp` POST = 428 until cleared.
Protections differ **per endpoint**, not per host — always probe each auth endpoint separately.

Rate-of-requests triggers 428s independently of pacing (10 rapid calls → burned mid-loop;
4s pacing after that did not recover). In-session oracle budget observed: 1×428 → 3 clean
oracle responses → persistent 428s. **Reload the page** to reset the flow; retrying the
burned session does nothing.

## Webpack runtime extraction — unlock the real payload format

When the app sends `{phoneNumber, otp, urt}` but you can only produce `{phoneNumber, otp}`,
the missing field comes from a transform module. Extract it live:

```js
let captured = null;
window.webpackChunk.push([['probe_' + Date.now()], {}, req => { captured = req; }]);
const mod = captured(15461);                      // auth-service module id
const payload = mod.j5({phoneNumber, otp});       // j5 adds "urt" tracking id
const headers = mod.b3;                           // x-meta-app + deviceId headers
```

Chunk globals vary (`webpackChunk`, `webpackJsonp<name>`, `webpackChunk:<app>`) — enumerate
`Object.keys(window)` for arrays-of-arrays with `.push`. Find the module id by grepping the
route chunk (e.g. `m-otplogin.*.js`) for the endpoint string.

Before extraction: `400 Invalid input` (misleading). After: clean oracle
`400 {"code":111023,"message":"Incorrect OTP"}`.

## CDP + React form automation

```bash
xvfb-run -a chromium --remote-debugging-port=9222 --remote-allow-origins='*' \
  --user-data-dir=/tmp/prof --no-first-run --no-sandbox --disable-gpu https://target/
```
`--remote-allow-origins='*'` is mandatory (CDP WS handshake 403s without it). Drive with
`Runtime.evaluate` (`awaitPromise:true` for async); read network results via
`performance.getEntriesByType('resource')` → `.responseStatus`.

Setting React-controlled inputs, by reliability:
1. **Works:** native setter + `InputEvent('input',{bubbles,data,inputType:'insertText'})` + `KeyboardEvent('keyup')`.
2. **Fails:** calling `props.onChange({...spread target})` — handler needs the real node (`getAttribute`).
3. **Fails:** `Input.dispatchKeyEvent` / `Input.insertText` on React OTP boxes — value never lands.
4. OTP components auto-submit on the Nth digit via keyup — set all boxes, then wait for the app's request.

## Silent TLS fingerprint drops

`curl`/`urllib` on Akamai-fronted hosts can return **empty output with no error at all** —
not a 403 page. Before concluding an endpoint is dead: retry with `curl_cffi`
(`impersonate="chrome120"` or `"safari17_0"`). This is a transport fallback for authorized
testing, not an auth bypass; document it as such.

## Cross-app client-id acceptance (cidx pattern)

SSO portals keyed by a client id usually accept any registered app's cidx. Harvest from
anywhere in the estate: partner hosts' `__NEXT_DATA__` blocks, boot configs, and the guest
JWT cookie (payload carries the cidx). `GET /_next/data/<buildId>/login.json?cidx=<id>`
returns `{appName, showEmail, showSignUp, googleClientId}` — cheap cidx prober + app inventory.
Unlinked auth endpoints (recoverpass, changepassword) then become reachable with different
protections than the main login.

## Password-recovery 3-state enumeration oracle

`POST /recoverpass?cidx=<valid>` form-encoded: `SUCCESS` (active) / `"Account has been
deleted"` / `"Account Doesn't exists"`. Rate limit was **per-email on the mail-send only**;
the enumeration oracle across different emails ran 30 parallel probes with zero throttling.
Per-email limiter ≠ enumeration mitigation — say this explicitly in reports.

## Pitfalls

- Do not treat a 428 body as an app error or retry immediately — read the JSON.
- Do not brute-force OTP through this class of control: 3-attempt window then challenge.
- Do not report "no rate limiting" from a session that got 428s — the per-email limiter exists;
  the enumeration axis is the unmitigated one.
- Full transcripts: `references/akamai-428-crypto-challenge-and-webpack-runtime.md`.
- Reusable CDP driver (launch + evaluate + React-input setter + webpack probe):
  `scripts/cdp2.py` — copy to the engagement's recon dir, adapt the module id and selectors.
