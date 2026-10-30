# Corporate SSO-host custom endpoints — peprouter / entramigcookie / hrdCookie (2026 session-verified)

Companion to `forgerock-openam-recon.md` + `forgerock-openidm-recon.md`. Enterprise
SSO hosts (`login.<corp>.com`) frequently run a thin custom app IN FRONT of AM with
custom unauth endpoints that leak policy state and set cookies across the whole
corporate domain. These were all recovered by grepping the login SPA bundle for
`this.httpClient.post("https://login.…/<name>` literals.

## 1. Policy oracle + HRD confusion (`/peprouter`)

```bash
# Query form (POST body = same params as query string):
curl -sk -X POST "https://login.corp.com/peprouter?apptype=wsfed&appname=urn:federation:MicrosoftOnline" \
  -H "Content-Type: application/x-www-form-urlencoded" -H "X-Requested-With: XMLHttpRequest" \
  --data "apptype=wsfed&appname=urn%3Afederation%3AMicrosoftOnline&domain=gmail.com&usertype=internal"
# → {"AuthenticateToServiceConditionAdvice":["/<realm>:azureTree"]}
```

Both `domain` AND `usertype` are fully client-controlled and the policy engine does
NOT bind them to the account's real domain: `domain=gmail.com&usertype=internal`
returns the internal-tree advice. Enumerate `apptype` (wsfed/oauth/saml) × `appname`
× `domain` × `usertype` to map federation routing (start appnames with
`urn:federation:MicrosoftOnline`; other RP identifiers usually return `{}`).

Body shape matters: malformed bodies → 500 (no leak), unknown appnames → 200 `{}`.
Body construction (from the SPA's `constructPolicyBody`):
`apptype=X&appname=Y&domain=<email.split('@')[1]>&usertype=internal|external`.

The SPA consumes the advice as `SERVICE` and routes to the matching auth tree —
a crafted link can force victims through unintended auth chains.

## 2. Cross-subdomain cookie injection (`/entramigcookie`, `/hrdCookie`)

```bash
curl -sk -D - -X POST "https://login.corp.com/entramigcookie?value=INJECTED_VALUE_123" \
  -H "X-Requested-With: XMLHttpRequest"
# → set-cookie: pwc_user_hrd=SU5KRUNURURfVkFMVUVfMTIz;  (base64 of the arbitrary value)
#     Domain=.corp.com AND Domain=.corp-internal.com   ← BOTH domains, one cookie!
#     Expires: +1 YEAR; SameSite=None; HttpOnly; Secure
```

- Unauthenticated, arbitrary attacker value, persisted 1 year, scoped to BOTH the
  public and the internal corporate domain. `pwc_user_hrd` is the Home-Realm-Discovery
  hint consumed server-side (OpenIG/policy layer) = auth-routing poisoning primitive
  for every corporate app reading it, **without needing XSS**.
- Value is base64'd server-side → CRLF header injection NOT possible (test and record).
- JSON payloads stored verbatim: `{"role":"admin","usertype":"internal"}` round-trips.
- Path-traversal / `<script>` values → WAF 403 (Incapsula) — record the block.
- The server strips emails to their DOMAIN part (`value=x@pwcinternal.com` → cookie
  value `pwcinternal.com`), so the cookie carries a domain hint, not a full identity.
- `/hrdCookie?email=<addr>` is the same family (email → domain extracted server-side).
- Craft the cookie in the browser (or via this endpoint from the victim's session via
  any subdomain XSS) and test whether it flips tree routing on the login flow.

## 3. SPA-flow replay pitfalls (verified dead-ends — do not re-burn hours)

- **RedirectCallback loops forever** when following `redirectUrl` with curl — the SPA
  needs browser JS state. The `X-CDSSO-Nonce` header + `/nonce` endpoint + cookie
  warm-up (`GET /login/` first) still loop on real installs. Drive a real browser or move on.
- **authId is session-bound**: authId minted in session A submitted from session B →
  401 "Session has timed out" (errorCode 110). The `FRDPAUTHID` cookie (holds authId,
  10-day expiry) is therefore not fixation-prone without an XSS primitive elsewhere.
- **Empty-password bypass on fallback trees**: trees like `bypass-passwd-fallback`
  auto-submit a magic account (`internaluser@corp.com`) — worth ONE empty-password
  test, but the LDAP callback still enforces the password (401 Authentication Failed).
- **Client-cert trees** (`pwc-cert`, `internal_bypass`, `cyberark`) → 401
  "User certificate not found" — enforced, not curl-bypassable.
- `/cdsso?token=X` validates server-side and returns `{}` for any token; GOTO
  navigation is client-side (SPA route param) — phishing-only, not a server vuln.
- SAML ACS (`/ui/api/v1/auth/saml/loginResponse/<provider>`) validates signatures —
  garbage assertion → 302 to `/ui/login?oauthMessage=HTTP 401` (no bypass).
- Tomcat 9 fingerprint via malformed URL: `ssoEmail=<script>` → 400 with
  `org.apache.coyote.http11.Http11InputBuffer.parseRequestLine` stack trace
  (URL HTML-encoded, reflection not exploitable — record as version disclosure).

## 4. IdentityServer4/Duende adjacent IdPs (same SPA-mining step)

Next.js SPA chunks (`/_next/static/chunks/*.js`, Turbopack) embed full OIDC configs
verbatim: `{authority, client_id, scope, redirect_uri}` per auth provider (including
Azure AD `api://<guid>/<Scope>` scopes + tenant). Follow the `authority` host:

- `/.well-known/openid-configuration` (JWKS at `/.well-known/openid-configuration/jwks`
  — non-standard suffix)
- `scopes_supported` leaks the ENTIRE internal API scope inventory (34 scopes
  in-session: genai, benchmarkapi, lumina_api, sec_filings, transactionanalyzer…)
- **Client enumeration oracle**: `POST /connect/deviceauthorization` with guessed
  client_ids → `unauthorized_client` = client EXISTS (grant disabled for it);
  `invalid_client` = nonexistent. Two-tier differential = valid client discovery.
- `connect/authorize` with PKCE plain/garbage, implicit (`id_token token`),
  `prompt=none` → all redirect to opaque `/home/error?errorId=…` (negative; record).
- Page title `IdentityServer4` = EOL product (successor: Duende) — report EOL even
  with no bypass. grant_types incl. `implicit` + `device_code` on a corporate IdP
  is itself a finding.
- App `/api/health` endpoints often leak `clientId`, git `sha`, `environment` unauth.

## 5. Azure API Management recognition

401 body `Access denied due to missing/invalid subscription key...` = APIM gateway.
Test `Ocp-Apim-Subscription-Key` (case variants), `api-key`, `x-api-key`,
`Subscription-Key`, `?subscription-key=` — all rejected = keys enforced (negative,
record). Look in the SPA bundle for the key-distribution config endpoint
(e.g. `POST /api/auth/primary/get {email, channel}` → per-user
`speechSubscriptionKey`/`speechRegion` to localStorage) and for embedded
`environment={production:false, loginIdentifier:"<64-char secret>"}` — dev-build
flags and secret identifiers on prod URLs are findings on their own.
