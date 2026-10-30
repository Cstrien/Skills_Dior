# iFood (ifood.com.br) Bug Bounty — Engagement Notes 2026-09-17

Session-specific findings from the ifood.com.br hunt. Use as worked examples for `js-bundle-secret-hunting` and `postmessage-vulnerabilities`. Recon state lives in `~/recon/ifood.com.br/` on the Kali box (hunt_notes.md is the master file).

## Attack surface snapshot

- 681 subdomains (crt.sh 502'd; HackerTarget 51 + RapiddNS/CDX 145 + subfinder 636), 545 resolved, 336 live.
- www = Cloudflare challenge; curl_cffi chrome110 still 403. **API hosts are NOT challenged** — always pivot to API/BFF hosts for JS fetching.
- Kong gateway everywhere (`x-kong-response-latency`, `no Route matched with those values`); Keycloak at `partners-auth.ifood.com.br` realm `partners` (OIDC metadata full incl. device_code/CIBA/token-exchange).
- Sibling domains: `ifood-devel.com.br` (dead CT-log infra: GitLab/Jenkins/K8s dash/Prometheus/Mattermost — NXDOMAIN, ignore), `dc-ifood.com` (788 CT subs, ~96% VPC-internal NXDOMAIN; `payment-card-manager.ifood-pci-production` public IP but **mTLS**: TLS handshake asks for client cert → host exists, intentionally hardened).
- `institucional.ifood.com.br` = WordPress + Elementor Pro 4.2.3 + Site Kit 1.186.0, wp-login open.
- `shop-admin.ifood.com.br` JS leaked dev sibling `shop.ifood-devel.com.br` (dead).
- homolog.ifood.com.br = OPEN full Next.js clone of www (same buildManifest routes), good for env/config reading.

## Key sources found in bundles

| Host | Finding |
|---|---|
| `webmiddleware.ifood.com.br/assets/entry-index-*.js` | `WSV3_ACCESS_KEY`/`WSV3_SECRET_KEY`, ClearSale/Cybersource/SendBird/APPsFlyer IDs, FULL Sentry DSN (00485e...bff7), `ifood://snapshot-share` (hardcoded, not a bug) |
| `help.ifood.com.br/assets/@vue-*.js` | `aS` env block: Contentful space+key (VALID), Logz token (VALID shipping), `VITE_KEY` uuid (fstr appKey), masked Sentry DSNs, `VITE_MIDDLEWARE_CONSUMER_HELP_URL=https://consumer-help.ifood.com.br`, `VITE_REFUND_URL=https://ifood-service-refund-bff.aws.nv-latam.k8s.aws-production.dc-ifood.com` (public ELB, resolves) |
| `account-challenges.ifood.com.br/assets/index-*.js` | FaceTec config: `deviceKeyIdentifier`, public face scan PEM, `VITE_FACETEC_PRODUCTION_KEY_*`, biometrics endpoints on `cw-marketplace.ifood.com.br/v1/biometrics/*` |
| `homolog.ifood.com.br/_next` chunks | INTERNAL_* URLs: `consumer-api-int`, `logistics-api-int`, `marketplace-int`, `wsloja-int`, `payment-card-manager-search.nv-payments.k8s.aws-production.dc-ifood.com`, `payment-wallets-search.aws.cluster-01.k8s.payin-production.dc-ifood.com` — ALL NXDOMAIN (internal-only), plus `account-challenges.ifood.com.br` (live, Akamai) |

## Contentful space v29q7lht8cmj (help center) — delivery key VALID

- `cdn.contentful.com` works; CMA + preview rejected; **GraphQL introspection works** (136 types).
- Full dump of 2006 entries / 22 content types in `~/recon/ifood.com.br/contentful/`.
- Intel: 77 zendeskTags (fraud__pmri_hc, account__hacked_account...), sales channels IFOOD + EMBEDDED_UBER, capability gates fChatDriver/fChatIFood/..., test/A-B content live in PROD ("Teste do Jean", "TESTE AI"), order state machine (91 contexts) + event taxonomy (32).
- No PII/credentials in entries (published content only).

## Logz.io shipping token — VALID ingest

`POST https://listener.logz.io:8071/?token=jevVLXDQZUpJKVlkRtfpgyqiydhLZTqR&type=cpmark987` → 200. Management API (`api.logz.io/v1/*`) 404 with shipping token. = log-pipeline write access (flooding/pollution vector).

## Confirmed finding #1 — help.ifood.com.br postMessage → arbitrary localStorage

- `https://help.ifood.com.br/scripts/postLocalStorageListener.js`: `{type:'postLocalStorage', name, value}` → `localStorage.setItem(name, value)` — NO key allowlist.
- Origin check: suffix match on `ifood.com.br / ifood-devel.com.br / ifood-sandbox.com.br` — ANY `*.ifood.com.br` accepted.
- **Verified live in browser console** (origin `https://attacker-external.ifood.com.br`, marker `cpmark987abc_test`).
- Impact chain: `getCapability(ACCESS_TOKEN)` reads `{...localStorage, ...cookies}` → forged JWT `aAccessToken` shadows real token until cookie exists → `sub` of forged token becomes in-app accountId → **help/chat actions attributed to victim account** (identity confusion). NOT full ATO: `getRefreshToken()` reads cookie `aRefreshToken` FIRST then window prop — localStorage write can't reach either.
- Full ATO escalation requires XSS on any `*.ifood.com.br` (set window prop + postMessage) = A→B gadget.
- Token refresh endpoints in `@vue` chunk: `JWT_REAUTH: "/v2/access_tokens"`, `OAUTH2_REAUTH: "/consumers/v1/auth/refresh_token"` on consumer-api; POST `{clientId, token}` → `{"ClientSecretNotFound","Secret not found for client ID X"}` (500) — **unthrottled client-ID enumeration oracle**. clientId comes from JWT payload `sub`→`client_id` decode in `fetchAccessToken` (opaque vs jwt branching).
- Cookie utils: `setAuthCookie` sets `aRefreshToken`/`aAccessToken` on domain `.ifood.com.br` (root), iOS additionally sets `window[aRefreshToken]` (opaque-token path).

## account-challenges (FaceTec biometrics) flow

- App: `account-challenges.ifood.com.br` (iframe-embeddable identity/age verification, FaceTec liveness).
- API on `cw-marketplace.ifood.com.br`: `GET /v1/biometrics/session-token` (header `x-ifood-auth-context-id` UUID), `POST /v1/biometrics/match-face`, `POST /v1/biometrics/enroll-face-bureau`(+`/status`), `POST /v1/customers/age/evaluate`, `POST /v1/account/challenges/identity-verify`, `GET /v1/customers/me/account`.
- `x-ifood-auth-context-id` random UUID → `AFC-2003 Unauthorized` (server-side validation present, no oracle). Empty header → `AFC-2001 Invalid request parameters`. Empty JSON on match-face (no header) → `AFC-2001`.
- Parent postMessage listener (`account-challenges:access-token`): origins = `localhost:5174, localhost:3000, homolog.ifood.com.br, www.ifood.com.br` (exact list — solid).
- callback URL client-side validation `isIfoodCallbackUrl`: hostname === ifood.com.br/.ifood.com.br suffix — no subdomain allowlist; embedded-iframe mode skips callback requirement.
- Challenge types: `match_face_id_scan, identity_verification, age_verification, otp_email, otp_phone, update_phone, match_face`; age_verification/update_phone require accessToken via URL param.

## /v1/account/block flow (mapped, unauth-only so far)

- Client: help center route `/account/block` (Block-Bj6qstFT.js).
- `POST cw-marketplace /v1/account/block/validate` `{email, emailAccess(bool), cpf(###.###.###-##), phone(minLength 19)}` → returns block_id + sends OTP.
- `POST cw-marketplace /v2/identity-providers/OTP/access-tokens` `{auth_code, key}` → `{access_token}`; errors OTP-2001 (expired/nonexistent), OTP-2002.
- `POST cw-marketplace /v1/account/block` `{block_id, token}` → final block.
- Unauth probes: `/block` `{}` → `IAM-2000 "must not be null"`; `/block/validate` → hit "API rate limit exceeded" (per-endpoint limit ~30/min seen; /block itself NOT throttled the same way).
- Unauth `{}` on OTP access-tokens → `OTP-2000 Bad Request "Invalid data"`; with `{auth_code:"123456", key:"..."}` → OTP-2001 oracle.

## Keycloak partners-auth.ifood.com.br (realm: partners)

- No dyn client registration (Kong 404s `clients-registrations/*`), device grant = 500 error-id (route broken), admin console 301→`/realms/partners/account` (locked).
- `password`/`client_credentials`/`token-exchange` with unknown client → `unauthorized_client` (correct behavior, no oracle).
- JWKS: 3 keys RSA512 CN=partners (2025-08, 2025-07, 2026-03 notBefore) + RSA-OAEP; metadata lists HS256 (symmetric) among supported algs — needs client secret, standard.
- Scopes leak org structure: `rolebackoffice_permission, roleportalparceiro_permission, appseparador_permission, managementiamprofile_permission, merchants, organization`.

## Kong API hosts (no-CF surface)

- `benefits-api.ifood.com.br`: `POST /auth/token` Basic-auth (401 `error.invalid_client`), `/api/v2/{employees,recharges,financial/balances,cards}` 401 w/ `ifood-ratelimit-limit: 60` headers. Full OpenAPI specs (Benefits Partners API + Auth Partners API) extracted from Gatsby page-data → `~/recon/ifood.com.br/benefits_specs.json`.
- `self-signin-api` `/v3/api-docs` → 401 `{"message":"no jwt token"}` (Springdoc behind JWT gate — try again with consumer JWT).
- `embedded-api` → Kong key-auth (`www-authenticate: Key realm="kong"`, "No API key found in request").
- `consumer-api.ifood.com.br` = help-center BFF: `POST /consumers/v1/auth/refresh_token` oracle; `{"no jwt token"}` on all endpoints (Kong JWT plugin).

## Untested next steps

1. OTP brute on `/v2/identity-providers/OTP/access-tokens` (6-digit, OTP-2001 oracle, throttle unverified).
2. Contentful space enumeration with same key pattern (other iFood spaces via GraphQL).
3. Full chain #1 with a real test account (registration flow on homolog).
4. Benefits API with Basic creds from partner onboarding (public developer portal says request access).
