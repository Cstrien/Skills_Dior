# Okta `/.well-known/okta-organization` + Sign-In Widget Config Extraction

Session: The Trade Desk Partner Portal pentest (2026-07-18)

## `/.well-known/okta-organization` Endpoint

Public, unauthenticated endpoint on every Okta tenant that returns org metadata.

### Request
```bash
curl -sk "https://thetradedesk.okta.com/.well-known/okta-organization" | python3 -m json.tool
```

### Response
```json
{
  "id": "00o3u5snGaSmnDpgO355",
  "cell": "ok7",
  "pipeline": "idx",
  "settings": {
    "analyticsCollectionEnabled": true,
    "bugReportingEnabled": true,
    "omEnabled": false,
    "pssoEnabled": false,
    "desktopMFAEnabled": false,
    "itpEnabled": true
  },
  "alternates": [
    {"href": "https://openpath-login.thetradedesk.com"},
    {"href": "https://walmart-login.thetradedesk.com"}
  ]
}
```

### Key fields
- `id` — Okta org ID. Use for API calls and log correlation.
- `cell` — Okta infrastructure cell/region (ok7 = US).
- `pipeline` — Auth pipeline type (`idx` = Identity Experience Engine).
- `settings.desktopMFAEnabled` — Whether Okta Verify desktop MFA is on.
- `alternates` — **Highest-value field.** Array of alternate branded login portals. Each is a full Okta subdomain with its own:
  - CSP policy (with different `frame-ancestors`, `connect-src`, `script-src`)
  - Branding assets
  - Potentially different OIDC client apps and scope sets
  - Potentially weaker security posture (custom branding = custom config)

### CSP headers from alternate portals
Each alternate portal returns its own CSP. Compare them to the main tenant CSP for differences:

```
Main tenant frame-ancestors: 'self' https://pubdesk.thetradedesk.com
openpath-login frame-ancestors: 'self' https://pubdesk.thetradedesk.com
walmart-login frame-ancestors: 'self' https://pubdesk.thetradedesk.com
```

Internal infrastructure domains visible in CSP `connect-src`:
- `<tenant>-admin.okta.com` — Okta admin console
- `<tenant>.kerberos.okta.com` — Kerberos/AD delegation
- `<tenant>.mtls.okta.com` — mTLS client cert auth
- `*.authenticatorlocalprod.com:8769` etc. — Okta Verify local agent ports

## `okta-jwt.js` Sign-In Widget Config Extraction

### Discovery
Login pages that embed the Okta Sign-In Widget include a script tag:
```html
<script type="text/javascript"
  src="/okta-jwt.js?v=bBneg4K-2QIyWag8pAMqCKVBZwjXkvRB4yMnGfji2ME"
  logo="/img/ttd-logo-bw.svg?v=..."
  brandName="The Trade Desk"
  language="en"
  codeChallenge="SDeLrX4Z3O62UNLzSqCFrW1bzVMqxAE2b-DUFE86WVs"
  codeChallengeMethod="S256"
  state="l0TBJldSx9AILO6npcqWsQ"
  clientId="0oahbc5fbqwwsNhQN356"
  redirectUri="https://auth.thetradedesk.com/Account/LoginCallback"
  baseUrl="https://thetradedesk.okta.com"
  issuer="https://thetradedesk.okta.com/oauth2/ausn7e4mbTyJUOMZR356"
  returnUrl="/connect/authorize/callback?client_id=ttd-dev-portal&scope=openid%20profile%20email%20offline_access%20applications%20ttdapi%20manage_api_tokens%20ttdui_refresh%20ttd-dev-portal.access&response_type=code&redirect_uri=https%3A%2F%2Fpartner.thetradedesk.com%2Fsignin-gw"
  errorMessage=""
  isMixedModeEnabled="False">
</script>
```

### Extraction command
```bash
curl -sk "https://<target-app>/login" | grep -oE 'src="/okta-jwt.js[^"]*"[^>]+'
```

### What each attribute reveals
| Attribute | Value | Use |
|---|---|---|
| `clientId` | Okta OIDC client_id | Use in authorize/token calls |
| `baseUrl` | Okta tenant URL | Confirms tenant |
| `issuer` | Okta authorization server | Full issuer URL with auth server ID |
| `redirectUri` | Registered callback | Must match for valid OAuth flow |
| `codeChallenge` / `codeChallengeMethod` | PKCE params | Confirms PKCE is enforced (S256) |
| `state` | OAuth state | CSRF token (per-session) |
| `returnUrl` | **Downstream IdP authorize URL** | Contains client_id, scope, redirect_uri, response_type for the calling app |
| `brandName` | Branding | Confirms target org |
| `isMixedModeEnabled` | Mixed-mode flag | If True, mixed auth modes may allow bypass |

### The `returnUrl` goldmine
The `returnUrl` attribute typically contains the full IdentityServer/Duende authorize URL with all OAuth parameters for the calling application. This reveals:
- Additional `client_id` values (e.g. `ttd-dev-portal`, `pubdesk`)
- Full scope sets per client (e.g. `openid profile email offline_access applications ttdapi manage_api_tokens ttdui_refresh ttd-dev-portal.access`)
- Registered `redirect_uri` values
- `response_type` (confirms code vs implicit)
- `code_challenge` (confirms PKCE requirement)

This means you can enumerate all OAuth clients and their configurations **without ever logging in** — just visit login pages for different apps and parse the `returnUrl`.

## Dual-layer IdP chain pattern

The Trade Desk uses a dual-layer IdP architecture:

```
Partner Portal SPA
  → auth.thetradedesk.com (IdentityServer/Duende on Kestrel/.NET)
    → thetradedesk.okta.com (Okta Sign-In Widget, PKCE S256)
```

### Why this matters for pentesting
1. **Two OIDC discovery documents** — test both independently:
   - `auth.thetradedesk.com/.well-known/openid-configuration` — IdentityServer config (10+ grant types, 95+ scopes, `plain` PKCE support)
   - `thetradedesk.okta.com/.well-known/openid-configuration` — Okta config (tighter, S256 only)
2. **redirect_uri validation tested at both layers** — IdentityServer validates first, then Okta. Both must pass.
3. **Different client configurations at each layer** — `ttd-dev-portal` is a client on IdentityServer; `0oahbc5fbqwwsNhQN356` is the Okta widget client. Test redirect_uri tampering against both.
4. **Scope sets differ per client** — `ttd-dev-portal` gets `ttdapi manage_api_tokens ttd-dev-portal.access`; `pubdesk` gets `openpath`. The `returnUrl` in okta-jwt.js reveals which scopes each downstream client requests.

## Confirmed secure (negative results)

- redirect_uri validation: strict at both IdentityServer and Okta layers (all bypass attempts → /home/error)
- response_type: only `code` accepted for `ttd-dev-portal`; implicit/hybrid rejected
- ROPC (password grant): `invalid_client` for public clients
- Device code: `invalid_client` for public clients
- Okta DCR: requires valid session (`Invalid session` error)
- Okta user enumeration via `/api/v1/authn`: hardened (uniform `E0000004`)
- Self-registration: not available on Okta or partner portal
