---
name: enterprise-platform-fingerprinting
description: Use when fingerprinting JFrog/ForgeRock/SAML IdPs unauth.
---

# Enterprise Platform Fingerprinting (unauthenticated)

How to identify and enumerate enterprise identity/artifact platforms **without auth**,
then turn the version + metadata leak into a CVE decision tree. Verified live against
JFrog (Artifactory 7.x + X-Ray + Access + Mission Control) and ForgeRock Access
Management (OpenAM) behind Imperva Incapsula.

## The shared primitive

Enterprise platforms leak an enormous amount from **version / health / metadata
endpoints that require no authentication** — even when every business endpoint is
locked behind `401 Authentication required`. The single highest-value first move on this
class of host is: hit `/system/version` + `/system/ping` + `/.well-known/*` + read the
`x-jfrog-version` / `x-environment` style headers. You usually get the exact build, which
culls 90% of the CVE list before you spend a payload.

## When to use (triggers)

- Host named `artifacts.*`, `artifactory.*`, `jfrog.*`, `registry.*`, `repo.*`
- Login redirects to `/openam/…` or `/openam/XUI/#login/`, or sets `amprdus_encrypt` /
  `loginprdus_encrypt` cookies
- Any redirect to `login.microsoftonline.com/<guid>/saml2` (SP-initiated SAML → MS Entra)
- A CDN/WAF-fronted host where you want fast passive attack-surface (use cert SAN)

## Reference files (read these for the full tables + gotchas)

- `references/jfrog-artifactory-recon.md` — exact unauth version endpoints per product,
  the `x-jfrog-version` header trick, anon-off 401 sweep list, CVE-decision-tree, Imperva
  handling.
- `references/forgerock-openam-recon.md` — ForgeRock AM cookie/endpoint fingerprint,
  OIDC `scopes_supported` = identity-schema leak, version→CVE map (CVE-2021-35464 /
  4201 / 3748), SAML AuthnRequest decode (with the two decode gotchas), cert-SAN
  enumeration, Azure AD tenant + `GetCredentialType`.
- `references/forgerock-openidm-recon.md` — ForgeRock IDM (OpenIDM/PingIDM) layer:
  SPA-config extraction (`OPENIDM_HOST`/`OPENIDM_HOST_BULK` = internal prod IAM hosts),
  the `X-OpenIDM-Username/Password: anonymous` unlock (and which header sets FAIL),
  validated unauth user-enumeration via custom `endpoint/*?_action=` scripts,
  password-policy leak, email-trigger bombing vector, enum-confirmation sampling
  discipline, endpoint taxonomy + hardened negatives.
- `references/dex-oidc-registry-recon.md` — Terraform registries (Terrakube) + Dex OIDC:
  `.well-known/terraform.json` → API-host + OIDC client disclosure, device-code flow
  probing (initiation is unauth by design; token poll gating is the check), connector
  detection via auth redirects, Spring actuator triage, hardened negatives.

## Quick hit-list (condensed)

JFrog — version leaks unauth:
```bash
curl -sD - https://TARGET/artifactory/api/auth/current          # body: anonymous user; header x-jfrog-version: Artifactory/7.x.y <build>
curl -sD - https://TARGET/access/api/v1/system/version          # 401 body; header x-jfrog-version: JFrog Access/7.x.y
curl -sk https://TARGET/xray/api/v1/system/version              # {"xray_version":"3.x.y"}
curl -sk https://TARGET/evidence/api/v1/system/version          # raw number, unauth
curl -sk https://TARGET/mc/api/v1/system/ping                   # Mission Control (EOL) reachable
```

ForgeRock AM — fingerprint unauth:
```bash
curl -sk https://TARGET/openam/json/serverinfo/*                # realm, _rev, config flags
curl -sk https://TARGET/openam/oauth2/.well-known/openid-configuration   # scopes_supported = PII schema
curl -sk https://TARGET/openam/oauth2/connect/jwk_uri            # JWKS signing key
curl -sk https://TARGET/openam/isAlive.jsp                      # "Server is ALIVE"
```

Cert SAN (fast passive surface map on any CDN/WAF host):
```bash
echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed 's/^ *DNS://'
```

## Iron rule on crown-jewel SSO targets

ForgeRock AM / `login.*` / central IdPs front the whole org's identity. Enumerate and
document (the disclosures are already High), but do **not** run RCE / session-hijack
payloads against an unidentified central IdP without an engagement — blast radius is
org-wide. RCE/auth-bypass CVEs (JATO `CVE-2021-35464`, session-hijack `CVE-2021-4201`)
are behind WAF/Imperva on hardened targets and are *candidates*, never fire blind.

## Related skills

- `web2-recon` (umbrella for subdomain/URL/JS pipeline) — complements this; it owns the
  crawl, this owns the platform fingerprinting once you land on a host.
- `oauth-pentest` / `saml-attacks` — for ACTIVE OAuth/SAML flow testing once
  fingerprinting confirms the IdP and an engagement is in hand.