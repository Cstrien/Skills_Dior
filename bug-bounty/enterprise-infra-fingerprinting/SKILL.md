---
name: enterprise-infra-fingerprinting
description: Unauth probes to fingerprint corp infra during wide recon.
---

# Enterprise Infrastructure Fingerprinting

Use when a wide recon pass (subfinder → dnsx → httpx) against a large enterprise has
produced hundreds/thousands of live hosts and you need to quickly separate high-value
infra (artifact repos, VPN portals, bare function hosts, unconfigured origins) from
content sites — BEFORE sinking time into any single app.

Everything here assumes an edge WAF in front (Imperva `x-cdn`/`visid_incap_*`/`incap_ses`,
Akamai `bm_s`/`bm_so`). Probes go THROUGH the WAF: a 403/404 means the WAF/route filtered
the path, not that the backend lacks it. Pair every "leak" with a junk-path control
(see `recon-scope-triage` soft-404 rule) before trusting it.

## The workflow: categorize the httpx dump, don't eyeball it

A 3k+ host probe emits 600KB+; the terminal only surfaces head+tail ("full output saved to
cache"). Always `httpx -o out.txt`, then parse the file in one Python (`execute_code`) pass:

- count status codes (200 vs 403 vs 302 vs 503 …) → tells you how locked-down the estate is
- count tech stack (Imperva, IIS, Google Cloud CDN, envoy, Kestrel, Drupal, Blazor …)
- regex-extract **signal titles**: `Welcome to nginx!`, `Your Azure Function App is up and
  running`, `Access is denied.`, custom `Login.` pages
- regex-extract **env hosts**: `\.(dev|stage|staging|qa|uat|test|sandpit|sandbox|preview)\.`
- route each signal to its fingerprint probe (below), then to the matching `hunt-*` skill.

Never re-run httpx or grep by eye to "find the interesting ones" — the file is on disk and
categorization is one Python pass. See `scripts/categorize_httpx.py`.

## Fingerprint table (unauth endpoints)

| Infra | Detect | Unauth probe → expected | Attack goal |
|---|---|---|---|
| JFrog Artifactory | JS references `jfrog-ui-essentials`, `/ui/webapp/`, `systemjs-importmap`, 302→`/ui/` + `<title>Loading</title>` | `/artifactory/api/system/ping` → `OK` (200 always); `/artifactory/api/system/version` → 401 `Authentication is required`; 401 header `www-authenticate: Basic realm="Artifactory Realm"` | anonymous repos (`/api/repositories`), default creds, CVE. Large tenants use SSO → anonymous read is the realistic find |
| GlobalProtect / PAN-OS | `/global-protect/login.esp` 200, `<title>GlobalProtect Portal</title>`, `SESSID` cookie | `/global-protect/getsoftwareversion.esp` → version (if unlocked); `/ssl-vpn/login.esp` → 503 vs portal 200 distinguishes gateway/portal wiring. A bare non-PAN 404 on one path + real portal on another = mixed config | PAN-OS CVE map (CVE-2024-3400 GP command injection etc.) |
| Azure Function App (default) | Landing `Your Azure Function App is up and running.` | `/admin/host/ping` → 200; `/admin/host/status` → 401; `/admin/functions` → 401 | enumerate `/api/<fn>` — often unauthenticated or JWT-mintable |
| nginx default behind mesh | `Welcome to nginx!` + `server: istio-envoy` / `x-envoy-upstream-service-time` | path fuzz + dir listing on the same origin | fresh deploy, upstream not wired → probe sibling routes |
| Google IAP | `Google Frontend` + `iap.googleapis.com` redirect | n/a (auth redirect itself) | find any unguarded path (`hunt-auth-bypass`) |
| ASP.NET forms-auth | 302→`/Login.aspx`, `Access is denied.` (IIS) | map postback params, viewstate | `hunt-auth-bypass`, `aspnet-dnn-pentest` |

## Tool-name collision (recurred on Kali)

`/usr/bin/httpx` on Debian/Kali is often the **Python HTTP-client CLI**, not projectdiscovery's
recon httpx. Symptom: `httpx -l` → `Error: No such option: -l`; `--help` shows the `HTTPX 🦋`
banner with `-m/--method`/`--cookies`. The recon tool takes `-l <file> -status-code -title
-tech-detect -web-server -content-length`.

Fix without root: download the pd binary under a non-colliding name and call it by full path:
```bash
curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip -o /tmp/hx.zip
unzip -o /tmp/hx.zip -d /tmp/hxdir && cp /tmp/hxdir/httpx ~/.local/bin/httpx-pd && chmod +x ~/.local/bin/httpx-pd
~/.local/bin/httpx-pd -version
```
Pin every recon tool to a distinct name when the generic name can be shadowed.

## Related skills

- `bb-methodology` — the orchestration umbrella this feeds (`recon-scope-triage` for the soft-404
  control; `hunt-spa-api` once an API host passes ownership).
- `aspnet-dnn-pentest`, `hunt-auth-bypass` — next step for forms-auth portals.