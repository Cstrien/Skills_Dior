# Source Map → Bug Candidate Pivot Workflow

Use this when a source-map analysis starts producing an inventory but the user needs actionable pentest bugs.

## Principle

A source map is usually not the final bug. Treat it as an attack-surface oracle:

1. **Inventory** source, routes, config names, auth pages, feature flags, SDKs.
2. **Classify each lead by bug class** (XSS, OAuth, MFA bypass, CSRF, open redirect, cookie tossing, sensitive config leak).
3. **Separate confirmed findings from leads.** Do not report a lead as a vulnerability until the terminal impact is proven live.
4. **Write next tests as copy-pasteable HTTP/browser steps.** The value is a hunt plan that can become PoC evidence.

## When analyzing Keycloakify / auth source maps

High-value pivots:

- `dangerouslySetInnerHTML` + sanitizer usage → auth-page XSS testing against error messages, IDP errors, expired-token pages, reset-password messages.
- Custom pages like `select-2fa-method.ftl`, `login-otp.ftl`, `webauthn-authenticate.ftl`, `select-authenticator.ftl` → MFA bypass / factor downgrade testing.
- `login-idp-link-email.ftl`, `first-broker-login`, provider aliases, `social.providers` → OAuth/IDP account-linking takeover testing.
- `tryAnotherWay=on` forms → MFA method-switch workflow testing; only report if it bypasses/downgrades MFA or transitions to post-MFA state.
- `kcContext.properties` keys such as analytics/GTM/PostHog keys → distinguish server-injected config from hardcoded secrets. Only report if actual values are leaked or attacker can control the property.
- Internal build paths (`.databricks/cache/.../lakebase/web/...`) → low/info source/build disclosure unless chained to secrets or exploitable internal endpoints.
- Weak CSP (`unsafe-inline`, `unsafe-eval`) → not reportable alone, but important as an XSS chain amplifier.

## Bug-oriented output format

After the inventory, include a table like:

| Candidate | Evidence from source map | What to test next | Valid only if | Severity if confirmed |
|---|---|---|---|---|
| Auth-page XSS | `dangerouslySetInnerHTML(kcSanitize(message.summary))` | Inject canaries through auth/IDP/reset error flows | JS executes on auth origin and exfiltrates OAuth/session context | High |
| MFA downgrade | `select-2fa-method.ftl`, `tryAnotherWay=on` | Try stale loginAction and direct method switch | Password-only/pre-MFA session reaches post-MFA state or weaker factor forced | High/Critical |
| Account-linking takeover | `login-idp-link-email.ftl`, social provider aliases | Test OAuth state/account-link CSRF and stale link replay | Attacker IDP links to victim account | Critical |
| Open redirect OAuth chain | login/OIDC routes, redirect_uri parameters | Test exact redirect_uri validation and open redirect chain | Auth code/token lands on attacker and can be exchanged | Critical |

## Triage guardrails

- Source-map exposure can be reportable as Low/Info, but do not inflate it to High unless secrets, private source, or exploitable routes are demonstrably exposed.
- Open redirect alone, weak CSP alone, missing cookie flags alone, and internal paths alone are usually N/A/Info unless chained.
- For OAuth/MFA claims, the terminal proof is account access or post-MFA state, not static code evidence.
- If a source-map URL no longer returns 200 live, mark the exposure as historical unless the program accepts stale evidence.

## Minimal live checks to run before report drafting

- Re-fetch the exact `.js.map` URL and save headers/body proof.
- Capture a real login/OIDC flow to obtain current `realm`, `client_id`, `redirect_uri`, `state`, `execution`, `tab_id`, `session_code`.
- Use a test account to enable 2FA and verify method-switch/downgrade behavior.
- Test auth error/message sinks with unique canaries and browser execution, not just reflection.
- For OAuth redirect bugs, show the code/token reaches attacker-controlled origin and is usable.
