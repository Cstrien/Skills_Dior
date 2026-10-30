# ForgeRock Access Management (OpenAM) — unauthenticated fingerprinting & IdP recon

Use when a login host sets `amprdus_encrypt` / `loginprdus_encrypt` cookies, redirects to
`/openam/…` or `/openam/XUI/#login/`, or is a central `login.*` / `sso.*` IdP with an
OIDC/`.well-known` surface. ForgeRock AM is the crown-jewel SSO of many enterprises —
recon + disclosure only unless you have an explicit engagement; blast radius is enormous.

## Cookie / path fingerprint

- `Set-Cookie: amprdus_encrypt=…` + `loginprdus_encrypt=…` (plus `JSESSIONID`) == ForgeRock AM.
- `/` 302 → `/openam`; `/openam/login` 302 → `/openam/XUI/#login/`.
- Error pages carry `Copyright 2012-2018 ForgeRock AS.` (or later years) in the OAuth2
  authorize HTML — free positive ID even when version is hidden.

## Unauthenticated endpoints (verified 200)

| Endpoint | What it leaks |
|---|---|
| `/openam/json/serverinfo/*` | `realm` (e.g. `/pwc`), `_rev`, config flags (secureCookie, selfRegistration, forgotPassword, kbaEnabled) |
| `/openam/oauth2/.well-known/openid-configuration` | full OIDC config AND `scopes_supported` |
| `/openam/oauth2/connect/jwk_uri` | JWKS (signing keys: EC/RSA, kid, x5c) |
| `/openam/isAlive.jsp` | 200 "Server is ALIVE" (a.k.a. health probe / active-host check) |
| `/openam/XUI/` | 200 UI shell |

### `scopes_supported` = directory schema blueprint (high-value disclosure)

The OIDC `scopes_supported` list is NOT generic (`openid profile email`) on real
ForgeRock AM installs — it enumerates the org's **identity attribute model**, e.g.
`employeeNumber, staffnumber, PwChrGivenName, PwChrFamilyName, pwcGlobalGradeName,
pwcGlobalGradeAbbreviatedName, pwcIdentityAssuranceLevel, PwCLegacyEmployeeNumber,
pwcPartyID, PwCStaffClass, PwCemployeeStatus, businessunit, LOS, pwcLocalLOSLevel1-4,
costcenter, windowsaccountname, cloudEmail, upwcjobtitle, pwcbudesc`.
Treat this as: (1) exact field names a legit IdP-issued token carries, (2) a map of the
HR/identity directory, (3) material info-disclosure finding on its own.

## Auth-locked (don't waste time)

`/openam/json/realms/root/authenticate` (POST), `/openam/json/…/sessions`,
`/openam/json/realms/root` → 401 `{"code":401,"reason":"Unauthorized","message":"Access Denied"}`.
`/openam/json/serverinfo/version` → 403 "No session for request".

## Version + CVE mapping

- No clean unauth version endpoint. `/openam/json/version`, `/ccserver/version`,
  `/openam/Version` → 404. Version is inferred from XUI/cookie generation + patch posture.
- Key CVEs by generation (all apply to the widely-deployed 6.5/7.x line):
  - **CVE-2021-35464** — unauth Java deserialization RCE via `jato.pageSession`
    (`/ccversion/*` requests), AM < 7.0.
  - **CVE-2021-4201** — missing access control, unauth session hijack (incl. admin),
    AM ≤ 7.1.0 (fixed 7.1.1 / 6.5.4).
  - **CVE-2022-3748** — auth bypass, AM 6.5.0 → 7.2.0.
  - CVE-2021-37153 / 37154 — auth-bypass (AD identity store) / SAML XML injection, < 7.0.2.
- Reality check: on hardened targets these request paths are behind a WAF/Imperva and get
  403, and version can't be pinned from the outside — so treat these CVEs as
  *candidates*, never fire blind.

## SAML AuthnRequest decode (SP-initiated flow)

When the IdP is external (MS Entra, Okta) and you capture the `SAMLRequest` query param,
decode it to recover SP entityID + ACS + IdP tenant:

```python
import base64, zlib, urllib.parse, xml.dom.minidom
s = urllib.parse.unquote(saml_request_str)     # e.g. from the redirect URL
raw = base64.b64decode(s)
d = zlib.decompressobj(-15)                     # RAW DEFLATE, no zlib header
out = (d.decompress(raw) + d.flush()).decode()
print(xml.dom.minidom.parseString(out).toprettyxml())
```

Gotchas (both bit on real targets):
- Use `wbits=-15` (raw deflate). Default `zlib.decompress(raw)` fails `invalid distance
  too far back` / `incorrect header check` — SAMLRequest is deflate-without-zlib-header.
- URL-decode first: the `SAMLRequest` in the browser URL is `%3D…`-encoded; the
  `+`/`%2B` signs must be decoded before base64.

The XML gives you: `AssertionConsumerServiceURL` (SP's SAML response sink),
`Destination` (IdP URL, incl. the MS tenant GUID `login.microsoftonline.com/<guid>/saml2`),
`Issuer` (SP entityID), `ForceAuthn`, `ProtocolBinding` (usually HTTP-POST).

## Azure AD tenant / user-enum

- Tenant GUID from the SAML `Destination` (or from any `login.microsoftonline.com/<guid>/`
  redirect). Confirm with `/common/GetCredentialType` (JSON POST `{"Username":"x@domain"}`).
- `GetCredentialType` returns `{"IfExistsResult":…,"ThrottleStatus":…}`; when it comes back
  `ThrottleStatus:1` for every probe you are rate-limited — back off, don't enumerate.

## Cert SAN enumeration (general, huge on CDN/WAF-fronted hosts)

```bash
echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed 's/^ *DNS://'
```

On Imperva/Akamai-fronted hosts the served cert is a **wildcard multi-tenant SAN cert**
listing the org's entire edge surface (one PwC cert enumerated ~150 hostnames:
`*.internal.*`, `*.qa.*`, `*.uat.*`, project codenames, `kibana-*`, `mdm.*`, `*.pwc.co.uk`,
`*.pwc.fr`, dozen country TLDs). This is free, passive, and yields more attack surface
than a full subfinder run. Save the list, then resolve/pivot.

## Enterprise SSO caution

`login.*` / ForgeRock AM fronts the whole org's identity. Enumerate and document, but do
not run RCE / session-hijack payloads against an unidentified central IdP without an
engagement — the finding value is the disclosure (scopes, JWKS, serverinfo, cert SAN),
which is already High on crown-jewel assets.