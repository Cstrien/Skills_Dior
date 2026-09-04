---
name: client-side-js-security-analysis
description: Use when grepping target JS for secrets and XSS.
---

# Client-Side JavaScript Security Analysis

Systematic workflow for downloading and analyzing all JavaScript on a target site — page scripts, third-party libraries, inline scripts, and analytics/tag-manager bundles — to find hidden endpoints, hardcoded credentials, debug flags, DOM XSS sinks, prototype pollution vectors, postMessage handlers, open redirects, and internal infrastructure references.

## When to Use

- User asks to "analyze all JS files" or "download and analyze JavaScript" from a target
- You need to find hidden API endpoints, secrets, or undocumented functionality in JS
- Target is a traditional multi-file site (jQuery, Handlebars, etc.) OR a modern SPA bundle
- You need to extract findings across multiple vulnerability classes from JS in one pass

## When NOT to Use (use these instead)

- **Extracting API schemas from a blocked SPA** → use `extracting-api-schemas-from-spa-bundles` (specialized for Vite/Next.js chunk analysis when browser won't render)
- **False-positive discipline for JS secret matches** → use `js-analysis-anti-false-positive` (4-Check Secret Gate, Context Gate)
- **Running SAST tools (semgrep, CodeQL, etc.)** → use `sast-code-review`
- **Source code / source map leakage specifically** → use `hunt-source-leak`

## Workflow

### Step 1: Download All JavaScript

```bash
# Download named JS files from target
for f in js/local/all.js js/jquery/cookieconsent.js; do
  curl -sk "https://target.com/${f}" -o "$(echo $f | tr '/' _)" -w "%{http_code} %{size_download}\n"
done

# Download main page and extract script srcs
curl -sk "https://target.com/" -o main_page.html

# Download all external script srcs
for url in $(grep -oP 'src=["\x27]\Khttps?://[^"\x27]+' main_page.html | sort -u); do
  fname=$(echo "$url" | sed 's|.*/||; s|?.*||')
  curl -sk "$url" -o "external_${fname}"
done

# Extract inline scripts
python3 -c "
import re
with open('main_page.html', 'r', errors='replace') as f:
    html = f.read()
inline = re.findall(r'<script(?![^>]*\ssrc)[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
for i, s in enumerate(inline):
    if len(s.strip()) > 10:
        with open(f'inline_{i+1}.js', 'w') as f:
            f.write(s)
"
```

### Step 2: Run the Pattern Grid

Run these grep patterns against ALL downloaded JS files:

| Pattern | Grep regex | Vulnerability class |
|---------|-----------|-------------------|
| API endpoints | `https?://[a-zA-Z0-9\-\._~:/?#]+` | Info disclosure |
| Fetch/XHR calls | `(fetch\|XMLHttpRequest\|\.ajax\|\.getJSON\|\.post\(\|\.get\()` | API discovery |
| Hardcoded creds | `(password\|secret\|api[_-]?key\|token\|auth)\s*[:=]\s*["'][^"']{3,}` | Credential leak |
| Debug flags | `(debug\|verbose\|logging\|trace)\s*[:=]\s*(true\|false\|1\|0)` | Config exposure |
| Proto pollution | `(__proto__\|prototype\|Object\.assign\|merge\|extend\|deepClone\|deepExtend)` | Prototype pollution |
| DOM XSS sinks | `(innerHTML\|outerHTML\|document\.write\|insertAdjacentHTML\|eval\(\|\.html\()` | DOM XSS |
| postMessage | `postMessage\|addEventListener\s*\(\s*["']message` | Cross-origin |
| Internal hosts | `(internal\|staging\|dev\|localhost\|127\.0\.0\.1\|10\.\d\|192\.168\|\.local\|\.internal\|\.corp)` | Infra disclosure |
| Suspicious paths | `/[a-zA-Z0-9_/.-]+\.(jsp\|do\|action\|cgi\|api\|json\|svc\|service)` | Endpoint discovery |
| Encoded strings | `(atob\|btoa\|base64\|decodeURIComponent\|escape\(\|unescape\()` | Obfuscation |
| Cookie manip | `(document\.cookie\|setCookie\|getCookie\|deleteCookie)` | Session issues |
| Open redirect | `(window\.location\s*=\|window\.open\s*\(\|location\.href\s*=)` | Open redirect |

### Step 3: Context-Strip Each Match (CRITICAL)

For every match, extract context BEFORE classifying. Use `grep -n -B5 -A10`. This is the **Context Gate** from `js-analysis-anti-false-positive` — skipping this is the #1 cause of false positives.

### Step 4: Classify with Anti-False-Positive Gates

**4-Check Secret Gate** (needs 2/4): (1) variable name is credential, (2) value format matches credential, (3) used in auth header/API call, (4) endpoint accepts with differential response.

**3-Check Endpoint Gate** (needs 2/3): (1) route indicates sensitive logic, (2) access-control boundary demonstrable, (3) response differs between auth states.

### Step 5: Apply False-Positive Filters

| Pattern | Looks like | Actually is | Correct classification |
|---------|-----------|-------------|----------------------|
| Commented-out example key | `// obviously, this is a fake key` then `api_key: 'vOgI...'` | Documentation example | INFO — service architecture, not credential |
| Parameterized btoa() auth | `btoa(\`${id}:${id}:SearchKey\`)` in fetch headers | Auth format exposed, creds are function params | INFO — auth scheme, not hardcoded credential |
| DOMPurify-wrapped innerHTML | `el.innerHTML = me(content)` where `me = DOMPurify.sanitize` | Sanitized sink | INFO — mitigated, not XSS |
| eval() in third-party lib | `eval(parsed)` in jquery.i18n.properties | Known vulnerable dependency | MEDIUM — needs attacker control of source |
| Analytics event constant | `PASSWORD: "137EsqueciMinhaSenha"` | GTM tracking label | NOT a secret |
| Dev report suite ID | `verisignincglobaldev` | Adobe Analytics tracking ID | NOT a credential |
| Sentry DSN | `{hash}@o{id}.ingest.sentry.io/{id}` | Public ingest endpoint | INFO at most |

### Step 6: Produce Severity-Ranked Report

```
HIGH:   eval() on fetched properties (RCE if source compromised)
HIGH:   Open redirect via user-controllable URL parameter
HIGH:   DOM XSS — server data → template → .html() without escaping
MEDIUM: Prototype pollution via deepExtend without __proto__ guard
MEDIUM: postMessage handler with "*" origin
LOW:    Analytics org ID / tracking server exposed
INFO:   Commented-out example API key revealing service architecture
```

## Traditional Site Patterns (jQuery + Handlebars + i18n)

| Pattern | What to look for | Where |
|---------|-----------------|-------|
| REST endpoints | `restPath = "rest/whois"`, `$.get(restPath, data)` | Main application JS |
| Auth path variants | `if (verifyAuth) { restPath = "../rest/whois" }` | Form processing JS |
| Handlebars template injection | `$(...).html(compiledResultTemplate({result: data}))` | Result rendering JS |
| i18n eval() | `eval(parsed)` in jquery.i18n.properties | jquery.i18n.properties-*.js |
| Cookie consent deepExtend | `util.deepExtend(target, source)` without `__proto__` guard | cookieconsent.js |
| URL param → location.href | `pipepath = args.ppath; window.location.href = page + "?ppath=" + pipepath` | Iframe/redirect JS |
| Deprecated unescape() | `args[argname] = unescape(value)` | URL param parsing |

## Modern Site Patterns (Vite/Webpack + Adobe DTM + OneTrust)

| Pattern | What to look for | Where |
|---------|-----------------|-------|
| Cludo/Search API auth | `btoa(\`${customerId}:${siteId}:SearchKey\`)` in fetch headers | Components bundle |
| SiteParams JSON endpoints | `window.SiteParams = {newsroom: "/path.json", ...}` | Inline script |
| Adobe DTM env IDs | `environment:{id:"EN...", stage:"production"}`, `...@AdobeOrg` | DTM launch script |
| Report suite IDs | dev vs prod variants | DTM launch script |
| OneTrust domain ID | `data-domain-script","UUID"` | Inline script |
| DOMPurify config | `me = t => DOMPurify.sanitize(t, {CUSTOM_ELEMENT_HANDLING:...})` | Components bundle |
| postMessage with "*" | `i.source.postMessage(..., "*")` in TCF/GPP handlers | OneTrust SDK |
| Version meta tag | `<meta property="version" content="{git_hash}" />` | HTML head |

## React SPA Webpack Patterns (Axios + MUI + reCAPTCHA)

When analyzing React SPA webpack chunks (common in enterprise apps — Verisign, financial services, B2B portals):

| Pattern | What to look for | Where |
|---------|-----------------|-------|
| Axios baseURL + CSRF | `axios.create({baseURL:"/app", headers:{[csrfHeader]:csrfToken}})` | Main app chunk (module IDs like 8611) |
| Template-literal API URLs | `` url: `/rest/accountproducts/${e}/keys` `` | App chunk — dynamic URL construction |
| Meta-tag CSRF extraction | `document.querySelector(\`meta[name='_csrf']\`).content` | App chunk — runtime config injection |
| reCAPTCHA site key | `<meta name="siteKey" content="6Ldr...">` | HTML head — server-injected |
| reCAPTCHA validate flag | `<meta name="recaptchaValidate" content="true">` | HTML head — controls client-side display |
| innerHTML error handler | `t.innerHTML = e.response.data` in catch block | App chunk — DOM-based XSS sink |
| OneTrust hostname check | `location.hostname != 'production.com'` → appends `-test` | thirdparty.js chunk — domain-based config switching |
| Webpack chunk structure | `webpackChunkreact_html.push([[14],{184(e,t,a){...}}])` | Multiple JS files sharing module registry |
| MUI nonce injection | `(0,i.A)("nonce")` passed to Emotion cache | Theme provider module |
| Axios version string | `axios/1.19.0` in vendor bundle | vendor.js — check for known CVEs |

### Analyzing webpack-chunked React SPAs

React SPA bundles are split into `runtime.js`, `vendor.js` (shared libs), `request.js` (page-specific), and `thirdparty.js` (cookie consent). Each chunk pushes into a shared `webpackChunkreact_html` array:

```javascript
// Module structure: webpackChunkreact_html.push([[chunkId], {moduleId(e,t,a){...}}])
// Module 8611 = axios config, Module 17 = page component, Module 453 = meta tag reader
```

**Key extraction steps for minified React SPA chunks:**
1. Beautify with regex: `content.replace(/;/g, ';\n').replace(/{/g, '{\n').replace(/}/g, '\n}\n')` — or use `npx js-beautify`
2. Search for `axios.create` to find the HTTP client configuration (baseURL, headers, CSRF)
3. Search for template-literal URL patterns: `` `/rest/${...}/...` `` for dynamic API routes
4. Search for `innerHTML` in catch blocks — DOM-based XSS sinks where error responses are rendered
5. Search for `document.querySelector('meta[name=...')` to find runtime config injection points
6. The `vendor.js` file is typically 1.5MB+ — use targeted grep, don't read the whole file
7. The page-specific chunk (e.g. `request.js`) is typically 15-20KB and contains all the business logic

### innerHTML error handler XSS sink pattern

Enterprise React apps often handle API errors by creating a DOM element and setting innerHTML:

```javascript
// Vulnerable pattern found in production code:
const t = document.createElement("html");
t.innerHTML = e.response.data;  // ← SINK: server error response injected as HTML
const n = t.querySelector('meta[name~="errorMessage"]');
const r = n ? n.getAttribute("content") : "fallback error message";
```

**Mitigation context**: If the app uses CSP with `script-src 'nonce-...' 'strict-dynamic'`, script tags in the injected HTML won't execute. However, non-script HTML injection (`<img>`, `<svg>`, CSS) may still work for data exfiltration or UI redressing. Classify as LOW if CSP is present, MEDIUM/HIGH if no CSP.

### reCAPTCHA client-side vs server-side validation

React SPAs using react-recaptcha typically:
1. Read site key from a meta tag: `getMetaContent("siteKey")`
2. Check if captcha should display: `"true" === getMetaContent("recaptchaValidate")`
3. Send the captcha token as a JSON field: `captchaResponse` in the POST body
4. Server validates the token server-side via Google's reCAPTCHA API

**Bypass testing matrix** (test all four — if all return 400, server-side validation is enforced):

| Test | Body value | Expected if server validates |
|------|-----------|------------------------------|
| Empty string | `"captchaResponse": ""` | 400 |
| Fake token | `"captchaResponse": "FAKE_TOKEN_12345"` | 400 |
| Null | `"captchaResponse": null` | 400 |
| Omitted | No captchaResponse field | 400 |

## Pitfalls

- **Do NOT report commented-out example keys as credential leaks.** If code says `// obviously, this is a fake key`, classify as INFO.
- **Do NOT report innerHTML wrapped by DOMPurify as DOM XSS.** Check if `sanitize()` wraps the sink.
- **Do NOT report eval() in third-party libraries as direct RCE.** jquery.i18n.properties `eval(parsed)` needs attacker control of the properties file source. Classify as MEDIUM.
- **Do NOT report btoa() auth construction as hardcoded credentials.** If credentials are function parameters, only the auth FORMAT is exposed.
- **Always check `window.SiteParams` inline script** — traditional sites often hardcode JSON API endpoint paths here.
- **Adobe DTM scripts are 300KB+ minified** — use targeted patterns and `head -N` to avoid output overflow.
- **Inline scripts are easy to miss** — always extract them from HTML and analyze for config objects and SDK init params.

## Related Skills

- **`js-analysis-anti-false-positive`** — Run its gates BEFORE writing any JS finding. Context Gate, 4-Check Secret Gate, 3-Check Endpoint Gate are mandatory.
- **`extracting-api-schemas-from-spa-bundles`** — When target is a modern SPA that won't render, use for chunk-download and API-schema extraction.
- **`hunt-source-leak`** — For source code / source map leakage specifically.
- **`triage-validation`** — After JS analysis findings are classified, run the 7-Question Gate before reporting.
- **`sast-code-review`** — For running automated SAST tools against downloaded JS.

## Verification Pitfalls

### Minified JS redaction: `***` is NOT the auth scheme

Minified JS often contains string literals that security tools or subagents redact as `***` in their output. When extracting auth header formats from minified bundles, **read the raw bytes** to determine the actual auth scheme:

```python
# WRONG — the subagent output shows "Authorization:*** ${btoa(...)}" 
# and you assume *** = "Basic "
# → API returns 401 because "Basic" is wrong

# CORRECT — read raw bytes from the downloaded JS file
with open('components_index.js', 'r') as f:
    content = f.read()
idx = content.find('Authorization:')
chunk = content[idx:idx+50]
# Print character-by-character to see the actual scheme
for c in chunk:
    print(f'{c} ({ord(c):x})', end=' | ')
# Reveals: A(41) u(75) t(74) h(68) ... : S(53) i(69) t(74) e(65) K(4b) e(65) y(79)
# → Auth scheme is "SiteKey", NOT "Basic"
```

**Lesson from verisign.com:** The Cludo Search API uses `Authorization: SiteKey ${btoa(customerId:siteId:SearchKey)}`. A subagent redacted `SiteKey ` as `***`, causing an initial 401 with `Basic` auth. Reading raw bytes revealed the correct scheme, and `SiteKey` auth returned full search results.

### Third-party search API credential verification

When JS analysis finds a third-party search API (Cludo, Algolia, Swiftype), verify the credentials work by calling the API directly:

```bash
# Cludo: auth = SiteKey + base64("customerId:siteId:SearchKey")
# Extract customer/site IDs from the CludoSearchResults() call in the page
AUTH=$(echo -n "10000064:10000072:SearchKey" | base64)
curl -sk "https://api-us1.cludo.com/api/v3/10000064/10000072/search" \
  -X POST \
  -H "Authorization: SiteKey $AUTH" \
  -H "Content-Type: application/json;charset=UTF-8" \
  -d '{"page":1,"query":"test"}'
# 200 + JSON results = credentials valid
# 401 = wrong auth scheme or invalid credentials
```

| Provider | Auth scheme | Where to find credentials |
|---|---|---|
| Cludo | `SiteKey base64(id:id:SearchKey)` | Inline script calling `CludoSearchResults(custId, siteId, ...)` |
| Algolia | `X-Algolia-Application-Id` + `X-Algolia-API-Key` | JS bundle, `algoliasearch()` init |
| Swiftype | `Authorization: Bearer` | JS bundle, `Swiftype.api_key` |

### Handlebars triple-stash `{{{}}}` ≠ exploitable XSS

When JS analysis finds `{{{result.query_string}}}` (Handlebars unescaped output) flowing into `.html()`, this is a DOM XSS sink ONLY if the server doesn't validate the input:

| Condition | Exploitable? | Why |
|---|---|---|
| Server validates `<` and `>` characters | **No** | The unescaped output never contains HTML — validation is charset-based, not pattern-based |
| Server reflects input without validation | **Yes** | `{{{query}}}` renders raw HTML into innerHTML |
| Server encodes `<` as `<` | **No** | Handlebars triple-stash outputs the encoded entity, browser renders it as text |

**Lesson from verisign.com:** The Whois REST API reflects the `q` parameter in JSON `query` field, and the Handlebars template uses `{{{result.query_string}}}` (triple-brace = unescaped). But server-side validation rejects any input containing `<` or `>`, regardless of encoding (double-encode, Unicode fullwidth, UTF-7, null byte — all rejected). The XSS sink exists but is unreachable.

### Spring Boot Actuator false positive behind SAML SSO

When a Spring Boot app (Thymeleaf) is behind SAML SSO, ALL paths return 200 with the SAML redirect page. This creates false positives for Actuator endpoint discovery:

```
/vac/actuator/health  → 200 (but body is SAML redirect form, not {"status":"UP"})
/vac/actuator/env     → 200 (same SAML redirect)
```

**Detection:** Check response body. If it contains `<form action="...SAML2/SSO/POST"`, it's the SAML catch-all, not real Actuator. Real API endpoints return JSON like `{"code":401,"error":"Unauthorized"}` — different size (~126 bytes for 401 JSON vs ~2970 bytes for SAML redirect page).

**Quick detector:** Compare response sizes for a known endpoint and a non-existent one. If both return the same size, it's the SAML catch-all:

```bash
SIZE1=$(curl -s -o /dev/null -w "%{size_download}" "https://$TARGET/actuator")
SIZE2=$(curl -s -o /dev/null -w "%{size_download}" "https://$TARGET/actuator/xyz-does-not-exist")
[ "$SIZE1" = "$SIZE2" ] && echo "SAML catch-all — actuator not exposed"
```

See `references/verisign-devhub-react-spa-case-study.md` for a full worked example including the SAML RelayState path reflection pattern found in Spring+Thymeleaf SAML SPs.

## References

- `references/verisign-js-analysis-case-study.md` — Real-world case study: full pattern grid results from analyzing Verisign WHOIS UI + main site JS
- `references/verisign-devhub-react-spa-case-study.md` — React SPA webpack chunk analysis: Axios config extraction, innerHTML error handler XSS sink, reCAPTCHA bypass testing, SAML RelayState reflection, SSO catch-all false positive pattern, unauthenticated API endpoint discovery
