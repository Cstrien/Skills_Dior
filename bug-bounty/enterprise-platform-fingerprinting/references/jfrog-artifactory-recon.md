# JFrog Platform (Artifactory / X-Ray / Access / MC) — unauthenticated fingerprinting

Use when a target exposes `artifacts.*`, `artifactory.*`, `jfrog.*` hosts, or any host
redirecting `/` → `/ui/`. JFrog self-managed clusters leak far more unauthenticated
than the API docs suggest, and the version you get is enough to cut the whole CVE
decision tree before committing time.

## Version disclosure (all verified 200 / header leaks, no auth)

| Endpoint | What it returns | Auth |
|---|---|---|
| `/artifactory/api/auth/current` | 200 `{"name":"anonymous","anonAccessEnabled":false,...}` AND header `x-jfrog-version: Artifactory/7.161.36 86136900` | none |
| `/access/api/v1/system/version` | 401 body, but header `x-jfrog-version: JFrog Access/7.191.20` | header leaks |
| `/xray/api/v1/system/version` | 200 `{"xray_version":"3.150.46","xray_revision":"..."}` | none |
| `/evidence/api/v1/system/version` | 200 `7.1225.271` (raw) | none |
| `/mc/api/v1/system/ping` | 200 `{"code":"OK"}` (Mission Control, EOL but reachable) | none |
| `/ui/api/v1/system/version` | 200 `<ui-version>` | none |
| `/artifactory/api/system/ping` | 200 `OK` | none |

- The `x-jfrog-version` header appears on Artifactory + Access endpoints even when the
  body is 401. Always `curl -sI` (or `-D -`) the *auth/current* and *access/system/version*
  paths first — that alone pins Artifactory + Access build exactly.
- `/ui/api/v1/system/version` (UI/UX bundle version) is NOT the Artifactory server
  version — don't conflate `1.652.86` with the product version.

## Product-surface enumeration (one JS file)

`/ui/js/chunk-vendors.<hash>.js` (multi-MB) enumerates every deployed product via
`/ui/api/v1/<product>/webapp/*/app.umd.js` references: `distribution`, `insight`, `mc`,
`pipe`, `xray`, `evidence`, `wingman`, `xsc`, `catalog`, `grid`, `unifiedpolicy`,
`pfed`, `runtime`, `onemodel`, `worker`, `bridge-client/server`, `fastci`, `event`, …
Then probe `/<product>/api/v1/system/version` (and `/system/ping`) per product:
- 200 → unauth (e.g. `xray`, `evidence`)
- 401 with `{"errors":[{"type":"Authentication",...}]}` → product present, auth-locked (e.g. `mc`)
- 404 `404 page not found` → not deployed (e.g. `wingman`, `xsc`, `catalog`)

## Every `/artifactory/api/*` returns 401 when anonymous access is off

When `anonAccessEnabled=false`, none of the classic unauthenticated reads work:
`/api/repositories`, `/api/search/*`, `/api/storage`, `/api/storageinfo`, `/api/build`,
`/api/system/version`, `/api/security/users`, Docker `v2/_catalog`, package indexes
(nuget `/api/nuget/v3/index.json`, npm `/api/npm/*`, pypi `/api/pypi/*`, go, maven).
All return 401 `{"errors":[{"status":401,"message":"Authentication is required"}]}`.
If you see this across the board, the artifact server is locked — pivot to SSO or
neighbouring non-JFrog repos rather than burning time on payloads.

## Internal login (no user enum)

`POST /artifactory/api/auth/login` JSON `{"user":..,"password":..}` (and the `/ui` form)
returns the identical string `"Login has failed.\nDue to Incorrect username/password or
locked user."` for admin AND for non-existent users. No message/timing diff → no enum.
Note: Artifactory rejects `curl -u user:pass` cleartext against this build with
`"Artifactory configured to accept only encrypted passwords..."` — the UI POSTs an
encrypted credential, another reason not to bother with raw basic-auth brute force.

## CVE decision tree (version → list fast)

1. Artifactory self-managed branches: patch versions cluster per branch
   (`7.161.0 → 7.161.20` was the Aug-2026 security-fix ceiling; `7.161.36` released
   26 Oct 2026 = latest 7.161). A host on the *latest* build of its branch has every
   published CVE ≤ its branch ceiling patched.
2. NVD: `keywordSearch=JFrog%20Artifactory` returns the CVE list with one-line impact.
   Cross-ref **CISA KEV** (`known_exploited_vulnerabilities.json`) — `CVE-2026-82329`
   (auth-bypass→admin, CVSS 9.8) is KEV-listed; treat KEV entries as the must-check list.
3. JFrog's own table (`docs.jfrog.com/releases/docs/jfrog-security-advisories`) is the
   authoritative version-range source (extract it; the page JSON is huge but grep-able).
   X-Ray "Security Fixes" releases usually cite only generic "version upgrades" +
   Golang/Traefik/PostgreSQL-driver container bumps — not remote unauth RCE — so a
   lagging X-Ray minor (e.g. 3.150.46 vs 3.157 latest) is usually NOT exploitable remote.

## Imperva Incapsula in front (typical for JFrog at enterprises)

- Fingerprint: `x-cdn: Imperva`, `x-iinfo: …` header, cookies `visid_incap_*` /
  `incap_ses_*`, bot page `/ _Incapsula_Resource?SWJIYLWA=…`.
- Plain `curl` on bot-protected hosts gets SSL `unexpected eof` (TLS fingerprint denied)
  or 403 bot pages. Load the origin via `browser_navigate` once to solve the challenge,
  then use `browser_console` for JS extraction; keep plain `curl` for API paths that
  the WAF allows (most `/artifactory/api/…` and product `/system/version` paths pass).