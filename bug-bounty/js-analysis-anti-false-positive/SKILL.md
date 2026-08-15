---
name: js-analysis-anti-false-positive
description: Discipline rules for analyzing client-side JavaScript (webpack bundles, minified JS, React SPA chunks) to extract secrets, API endpoints, and internal route maps WITHOUT producing false positives. Use whenever you grep/trawl JS bundles for secrets, endpoints, or sensitive strings — especially before writing them into a pentest report as findings.
---

# JS Analysis: Anti-False-Positive Discipline

Rules for extracting findings from client-side JavaScript without manufacturing false positives. The root cause of JS-analysis false positives is **context stripping** — grepping for a keyword, seeing a match, and classifying it before reading the surrounding code.

---

## THE CONTEXT GATE (mandatory before any JS finding is written)

Before classifying ANY string found in JavaScript as a secret, credential, API key, or internal code, you MUST extract and read **±500 characters of context** around the match. No exceptions.

### Why this exists

JS bundles are minified and webpack-packed. A grep for `password|secret|token|key` will match thousands of strings that are:
- CSS property names (`font-weight`, `keyframes`)
- React component props (`InputPassword`, `apiKey` as a config key name with empty value)
- Analytics event labels (`FORGOT_PASSWORD: "137EsqueciMinhaSenha"`)
- Library API parameters (`apiKey` in a Google Maps init call — the key is in a separate variable)
- Error messages and UI strings (`"Enter your password"`)

Without context, these all look like secrets. They are not.

### How to apply

```python
import re

with open('bundle.js', 'r', errors='replace') as f:
    content = f.read()

for match in re.finditer(r'your_pattern', content):
    start = max(0, match.start() - 500)
    end = min(len(content), match.end() + 500)
    snippet = content[start:end]
    print(f"\n--- MATCH at {match.start()} ---")
    print(snippet)
    print(f"--- END ---\n")
```

**Rule: if you cannot read and understand the ±500 char window, you cannot classify the finding.**

---

## THE 4-CHECK SECRET GATE

A string found in JS is a **confirmed secret** only if it meets **at least 2 of 4** criteria:

| # | Criterion | How to verify |
|---|-----------|---------------|
| 1 | **Variable name is explicitly a credential** | `apiKey`, `clientSecret`, `accessToken`, `privateKey`, `AWS_SECRET_ACCESS_KEY`, `Authorization` with a real value — NOT `InputPassword`, `FORGOT_PASSWORD`, `passwordField` |
| 2 | **Value format matches a real credential** | JWT (`eyJ...`), AWS key (`AKIA...`), OAuth token (long base64), GitHub PAT (`ghp_...`), private key (`-----BEGIN RSA...`) — NOT a Portuguese phrase, not a short string, not a number+word combo |
| 3 | **Used in an auth header or API call** | String appears in `Authorization: Bearer <value>`, `X-API-Key: <value>`, `fetch(url, {headers: {Authorization: <value>}})` — NOT just defined in a config object |
| 4 | **Endpoint accepts it and returns different response** | Send the value to the API → 200/JSON with data vs. 401/403 without it — NOT just "the endpoint exists" |

**Score < 2 → NOT a secret finding. Log as "artifact" or drop entirely.**

---

## THE 3-CHECK ENDPOINT GATE

An API route found in JS is a **confirmed finding** only if it meets **at least 2 of 3**:

| # | Criterion | How to verify |
|---|-----------|---------------|
| 1 | **Route name indicates sensitive business logic** | `/auth/v1/security/token`, `/orders-fixedincome-buy`, `/fortknox/v2/financialPosition` — NOT `/static/js/`, `/assets/`, `/favicon.ico` |
| 2 | **Access-control boundary is demonstrable** | Unauthenticated request → 401/403; authenticated request → 200 — NOT just "returns 401" (401 alone only proves the endpoint exists, not that it's vulnerable) |
| 3 | **Response differs between auth states or malformed input** | Send `Authorization: Bearer test` → different response than no header; send invalid ID → error with internal info — NOT just "returns 401 to everything" |

**Score < 2 → NOT an endpoint finding. Log as "route discovered" at most.**

---

## COMMON FALSE-POSITIVE PATTERNS IN JS BUNDLES

| Pattern | Looks like | Actually is | How to identify |
|---------|-----------|-------------|-----------------|
| Analytics event constant | `PASSWORD:"137EsqueciMinhaSenha"` | GTM/analytics tracking label | Check if it's in a `types` or `events` object with sibling keys like `INVEST:"116Investir"` |
| React component prop | `apiKey:undefined` | Config field name, no value | Check if value is `undefined`, `null`, `""`, or a variable reference |
| CSS/styled-components | `key:"transition"` | CSS property | Check if surrounding code is `styled-components` or CSS-in-JS |
| i18n string | `"Enter your password"` | UI text | Check if it's in a `messages` or `translations` object |
| Library config | `password:""` | Empty config for a library | Check if value is empty or a placeholder |
| Webpack module ID | `n(528)` | Module reference, not a secret | Check if it's inside `require()` or `n()` call |
| Route path | `"/autenticacao"` | Frontend route (React Router) | Check if it's in a `<Route path=...>` or `history.push()` — frontend routes are NOT API endpoints |
| Environment variable name | `process.env.API_KEY` | Variable reference, not the value | The actual value is NOT in the bundle; this just shows the var name |
| Base64-encoded font | `AAEAAAASAQAA...` | @font-face data URI | Check if it's inside `url(data:font/...;base64,...)` |
| Source map reference | `//# sourceMappingURL=...` | Build artifact, not a finding | Check if it's a comment at the end of the file |
| Server-injected key ref | `SEGMENT_WRITE_KEY: segmentKey` | Variable name, not the value | Check if the value comes from `props`, `context`, or `process.env` — key is injected at runtime, NOT in the bundle |
| Keycloakify kcContext property | `kcContext.properties.API_KEY` | Server-side property injection | Keycloak themes receive secrets via `kcContext.properties` — the defaults in `kc.gen.tsx` are always empty strings |
| Sanitized innerHTML | `dangerouslySetInnerHTML={{__html: kcSanitize(...)}}` | Not an XSS finding | If the value passes through `kcSanitize`, `DOMPurify.sanitize`, or equivalent, it is NOT a dangerouslySetInnerHTML finding |
| node_modules source in .map | `writeKey` in `@segment/analytics-next` | Library internal, not a secret | Source map `sourcesContent` includes third-party library source — `writeKey` in Segment SDK is a variable reference in library code, not a hardcoded key |
| SVG namespace URL | `http://www.w3.org/2000/svg` | XML namespace, not an endpoint | SVG icons embedded as React components contain `xmlns` URLs — filter `.svg?react` sources entirely |
| Sentry DSN in loader script | `738def56617076317147c60a8ea55dc6@o4509929172762624.ingest.us.sentry.io/4511230172266496` | Observability ingest endpoint, not a credential | Sentry's CDN loader (`js.sentry-cdn.com/{hash}.min.js`) embeds the DSN as a parameter in its IIFE call. Format: `{hash}@o{org_id}.ingest.{region}.sentry.io/{project_id}`. It is a public ingest endpoint for error reporting — anyone with the DSN can only SEND error reports, not read data. Severity: INFO at most. Do NOT report as a credential leak. Matches `offensive-osint` secret-patterns.md pattern 44 (Sentry DSN, LOW severity). |

---

## THE GREP-CONTEXT-CLASSIFY WORKFLOW

Follow this exact sequence when trawling JS bundles:

```
Step 1: GREP — Extract matches with pattern
Step 2: CONTEXT — Read ±500 chars around EACH match
Step 3: CLASSIFY — Apply the 4-Check Secret Gate or 3-Check Endpoint Gate
Step 4: VERIFY — If it passes the gate, test it against the live API
Step 5: REPORT — Only if verification returns differential response
```

**NEVER skip from Step 1 directly to Step 5.** This is the exact mistake that produces false positives.

---

## HARDCODED STRING CLASSIFICATION TREE

When you find a suspicious string in JS, follow this decision tree:

```
Is the string a variable VALUE (right side of = or :)?
├── NO → It's a key/name/prop → NOT a secret. Drop.
├── YES → Does the variable name contain credential keywords?
│   ├── NO → Check if it's used in an auth context (header, API call)
│   │   ├── NO → NOT a secret. Drop.
│   │   └── YES → Proceed to 4-Check Secret Gate
│   └── YES → Is the value empty/null/undefined?
│       ├── YES → NOT a secret (placeholder). Drop.
│       └── NO → Does the value format look like a credential?
│           ├── NO → Check surrounding context for analytics/config patterns
│           │   ├── Analytics event (types/events object) → NOT a secret. Drop.
│           │   ├── Config field (config/settings object) → NOT a secret. Drop.
│           │   └── Other → Proceed to 4-Check Secret Gate
│           └── YES → Proceed to 4-Check Secret Gate
```

---

## API ROUTE CLASSIFICATION TREE

```
Is the string a URL path starting with / ?
├── NO → Not a route. Drop.
├── YES → Is it inside a Route component or history.push()?
│   ├── YES → Frontend route. NOT an API endpoint finding. Log as route map only.
│   └── NO → Is it used in a fetch/axios/XMLHttpRequest call?
│       ├── NO → Check if it's a config constant. May still be useful but lower confidence.
│       └── YES → Proceed to 3-Check Endpoint Gate
```

---

## LESSON: THE "137EsqueciMinhaSenha" FALSE POSITIVE

**What happened:** Grep for `password|secret|token` in a 4.7MB webpack chunk matched `PASSWORD:"137EsqueciMinhaSenha"`. Without reading context, this was classified as MEDIUM "Password Recovery Code Leaked in JavaScript" in a pentest report.

**What it actually was:** A Google Tag Manager event tracking constant:
```javascript
var types = {
    FORGOT_PASSWORD: "137EsqueciMinhaSenha",   // event ID 137 + event name in Portuguese
    INVEST: "116Investir",
    REDEMPTION: "107Resgatar",
    ...
};
```

**Root cause:** Context stripping. The grep output showed `PASSWORD:"137EsqueciMinhaSenha"` (the key `FORGOT_` was not visible in the truncated output). The value "EsqueciMinhaSenha" (Portuguese for "I forgot my password") was misinterpreted as a password reset secret/code.

**How to prevent:** The Context Gate (±500 chars) would have revealed the full object structure: sibling keys `INVEST`, `REDEMPTION`, `ACCOUNT` with similar `<number><Portuguese-word>` format — clearly analytics tracking labels, not credentials.

**Impact:** False positive in a pentest report reduces credibility of ALL findings in the report. Triagers who see one false positive will scrutinize every other finding more aggressively.

---

## LESSON: INSTANA EUM KEY — WHEN IT IS A FINDING

**Scenario:** `ineum("key", "-nG3IyvhSVuNik7Urz8lpA")` found in page source.

**4-Check Secret Gate analysis:**

| # | Criterion | Met? | Evidence |
|---|-----------|------|----------|
| 1 | Variable name is credential | ✅ | `key` parameter to Instana SDK init |
| 2 | Value format matches credential | ✅ | 22-char base64-like string |
| 3 | Used in auth header/API call | ❌ | It's a monitoring SDK key, not used for auth |
| 4 | Endpoint accepts it with different response | ❓ | Not tested |

**Score: 2/4 → Borderline.** Classification: **Info/LOW** — monitoring key exposure, not a credential. Could allow injecting fake monitoring data. Not the same severity as an API key or auth token.

**Contrast with `137EsqueciMinhaSenha`:**

| # | Criterion | Met? | Evidence |
|---|-----------|------|----------|
| 1 | Variable name is credential | ❌ | `FORGOT_PASSWORD` is an event type name, not a credential |
| 2 | Value format matches credential | ❌ | "137EsqueciMinhaSenha" is `<number><Portuguese-phrase>`, not a credential format |
| 3 | Used in auth header/API call | ❌ | Used in `dataLayer.push()` for analytics |
| 4 | Endpoint accepts it | ❌ | It's a label, not sent to any endpoint as auth |

**Score: 0/4 → NOT a secret.** Correct classification: **artifact / analytics label.**

---

## INTEGRATION WITH TRIAGE-VALIDATION

This skill runs BEFORE `triage-validation`'s 7-Question Gate for JS-sourced findings. Specifically:

1. **Context Gate** (this skill) — extract ±500 chars, read context
2. **4-Check Secret Gate** or **3-Check Endpoint Gate** (this skill) — classify
3. **Q1 of 7Q Gate** (triage-validation) — "Can an attacker use this RIGHT NOW?"
4. **Q6 of 7Q Gate** (triage-validation) — "Can you prove impact beyond technically possible?"

If a JS-sourced finding fails step 1 or 2, it never reaches the 7Q gate. This prevents context-stripped false positives from entering the validation pipeline at all.

---

## TOOL COMMANDS

### Extract all matches with context (Python)

```python
import re, sys

pattern = sys.argv[1] if len(sys.argv) > 1 else r'api[_\-]?key|secret|token|password|client[_\-]?id|bearer|authorization'
context_size = 500

with open(sys.argv[2], 'r', errors='replace') as f:
    content = f.read()

for i, match in enumerate(re.finditer(pattern, content, re.IGNORECASE)):
    start = max(0, match.start() - context_size)
    end = min(len(content), match.end() + context_size)
    print(f"\n{'='*80}")
    print(f"MATCH #{i+1} at position {match.start()}")
    print(f"Matched: {match.group()}")
    print(f"{'='*80}")
    print(content[start:end])
    print(f"{'='*80}\n")
```

### Extract API routes from JS

```python
import re

with open('bundle.js', 'r', errors='replace') as f:
    content = f.read()

# Match quoted strings that look like API paths
routes = set(re.findall(r'["\'](/[a-zA-Z0-9_\-/]{3,80})["\']', content))

# Filter out static asset paths
api_routes = [r for r in routes if not re.match(r'/static/|/assets/|/img/|/css/|/js/|/favicon', r)]

for route in sorted(api_routes):
    print(route)
```

### Extract URLs from JS

```python
import re

with open('bundle.js', 'r', errors='replace') as f:
    content = f.read()

urls = set(re.findall(r'https?://[a-zA-Z0-9._\-/]+', content))
for url in sorted(urls):
    print(url)
```

---

## CHECKLIST BEFORE WRITING A JS-SOURCED FINDING INTO A REPORT

```
[ ] Context Gate: Read ±500 chars around the match
[ ] Classification: Applied 4-Check Secret Gate or 3-Check Endpoint Gate
[ ] Score: Meets minimum threshold (2/4 for secrets, 2/3 for endpoints)
[ ] Verification: Tested against live API (if applicable)
[ ] Differential: Response differs with/without the value (if applicable)
[ ] NOT analytics: Confirmed it's not a GTM/event tracking label
[ ] NOT i18n: Confirmed it's not a UI translation string
[ ] NOT placeholder: Confirmed value is not empty/null/undefined
[ ] NOT CSS: Confirmed it's not a CSS property or styled-components reference
[ ] NOT frontend route: Confirmed it's an API endpoint, not a React Router path
[ ] NOT server-injected: Confirmed the value is actually in the bundle, not a variable reference to a runtime-injected property (kcContext, process.env, props)
[ ] NOT node_modules noise: If from a source map, confirmed the match is in custom source code, not a third-party library's sourcesContent
[ ] NOT Sentry DSN: If the string matches `{hash}@o{id}.ingest.{region}.sentry.io/{id}`, confirmed it is a Sentry DSN (public ingest endpoint, INFO at most, not a credential)
```

If ANY checkbox is unchecked → do NOT write it as a finding. Log as artifact or drop.

---

## SOURCE MAP ANALYSIS — additional discipline

When analyzing `.js.map` files (not raw minified bundles), additional false-positive patterns emerge:

### Signal vs Noise: Source Paths

Source map `sources` array contains relative paths. **Custom application code is the signal; node_modules is noise.**

```
SIGNAL (read every file):
  ../../src/**           — application source
  ../../../analytics/**  — custom analytics wrappers
  ../../../glow/**       — custom UI library
  ../../../../../js/packages/** — shared internal packages

NOISE (skip or scan only for hardcoded values):
  **/node_modules/**     — third-party libraries (React, Segment SDK, PostHog, etc.)
  **/*.svg?react         — SVG icon components (only contain XML namespace URLs)
```

Filter by source path BEFORE grepping content. This reduces matches from thousands to dozens.

### Server-Injected Keys (COMMON in source maps)

Frameworks like Keycloakify inject analytics keys server-side via context properties:
```typescript
// kc.gen.tsx — defaults are ALWAYS empty
export const kcEnvDefaults = {
  GTM_ID: '',
  SEGMENT_WRITE_KEY_WEB_UI: '',
};
// KcPage.tsx — reads from runtime context
const { SEGMENT_WRITE_KEY_WEB_UI: segmentKey, GTM_ID: gtmKey } = kcContext.properties;
```
The actual key values are NEVER in the source map. Do NOT report `SEGMENT_WRITE_KEY_WEB_UI` as a hardcoded secret — it's a variable name for a server-injected value.

### Build-Time Constants

Look for `__IS_..._VARIANT__` or similar build-time constants. These reveal multi-tenant build configurations (e.g., a product built for both Neon and Databricks from the same codebase, controlled by `__IS_NEON_VARIANT__`).

### Source Path Leaks (Infrastructure Recon)

Source map `sources` paths can leak build infrastructure:
- `.databricks/cache/...` → builds run on Databricks workspace
- `yarn_node_modules/{N}/{hash}/` → dependency cache structure
- `lakebase/web/node_modules/` → internal project name

These paths are informative but NOT secrets. Report as INFO/LOW infrastructure exposure, not as a credential leak.

### Extraction Pitfalls

When extracting `sourcesContent` to files for grepping:
- **File name too long**: Source map paths can be 200+ chars. Truncate sanitized filenames to ~150 chars to avoid `OSError: [Errno 36] File name too long`.
- **Large source counts**: A single .map file can contain 500+ sources with 2MB+ of content. Use Python `json.load()` and iterate, not shell tools.

---

## Related Skills & Chains

- **`triage-validation`** — This skill's gates run BEFORE the 7-Question Gate for JS-sourced findings. A finding that fails the Context Gate or 4-Check Secret Gate never enters the 7Q pipeline.
- **`bb-methodology`** — This skill implements the "Context-Stripping Ban" discipline rule referenced in bb-methodology's PART 4 (Methodology Discipline).
- **`report-writing`** — Only JS findings that pass this skill's gates AND the 7Q gate reach the report-writing stage.
- **`hunt-source-leak`** — When the JS analysis is specifically about source code / source map leakage rather than secret extraction, use hunt-source-leak instead.
- **`security-arsenal`** — For secret-extraction tooling (jsluice, trufflehog, mantra) that produces raw matches this skill then filters.
