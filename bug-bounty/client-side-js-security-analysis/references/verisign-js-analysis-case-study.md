# Verisign JS Analysis Case Study

Real-world results from analyzing Verisign WHOIS UI + main site JavaScript.

## Target

- WHOIS UI: `registrar.gslb.verisign.com/webwhois-ui/`
- Main site: `www.verisign.com`

## Files Analyzed

### WHOIS UI (4 files)
- `js/local/all.js` (30KB) — Main WHOIS application logic, jQuery 3.5.1
- `js/jquery/jquery.i18n.properties-1.2.7.js` (20KB) — i18n properties loader
- `js/handlebars/handlebars-v4.7.7.min.js` (80KB) — Handlebars template engine
- `js/jquery/cookieconsent.js` (54KB) — Cookie consent plugin

### Main Site (4 files + 9 inline scripts)
- `components_index.js` (70KB) — Site components bundle (Brightcove, DOMPurify, Cludo Search, Odometer)
- `adobedtm_launch-305389a5b097.min.js` (299KB) — Adobe DTM launch script
- `layouts_analytics.js` (123 bytes) — Analytics page bottom trigger
- `cookielaw_otSDKStub.js` (27KB) — OneTrust cookie consent SDK

## Findings by Class

### Hardcoded Credentials (cookieconsent.js)

Line 1003: API key for ipinfodb.com geolocation service:
```javascript
// obviously, this is a fake key
api_key: 'vOgI3748dnIytIrsJcxS7qsDf6kbJkE9lN4yEDrXAqXcKUNvjjZPox3ekXqmMMld'
```
**Classification: INFO** — commented-out example with explicit "fake key" annotation. The useful intel is the service URL pattern: `//api.ipinfodb.com/v3/ip-country/?key={api_key}&format=json&callback={callback}`.

### eval() RCE Vector (jquery.i18n.properties-1.2.7.js)

Lines 414, 432-433:
```javascript
eval(parsed);  // evaluates concatenated property assignments
eval('typeof ' + fullname + ' == "undefined"');
eval(fullname + '={};');
```
**Classification: MEDIUM** — eval() on fetched properties file content. Exploitable if properties source is attacker-controllable (MITM on HTTP fetch). The `$.ajax()` call at line 307 fetches the properties files.

### Open Redirect (all.js)

Line 895: `pipepath = args.ppath;` — the `ppath` URL parameter overrides `pipepath`
Line 904: `window.location.href = page + ".html?ppath=" + pipepath + "&language=" + language + "&" + qString;`
Line 918: `window.open(page + "?ppath=" + pipepath + ...)` 

The `getArgs()` function at line 884 uses deprecated `unescape()` to parse URL parameters.

**Classification: HIGH** — user-controllable `ppath` parameter flows into `window.location.href` and `window.open()`.

### DOM XSS Sinks (all.js)

10+ instances of `$(...).html()` rendering WHOIS API response data via Handlebars templates:
- Line 619: `$("#whois_results").html(compiledResultTemplate({result: whois_response}))`
- Line 642: `$("#epp-stat-data").html(compiledModalTemplate(result))`

WHOIS response (`textMsg`) from REST API → `splitResponse()` → Handlebars-compiled template → `.html()`.

**Classification: HIGH** — server-controlled WHOIS response data flows into innerHTML via Handlebars. While Handlebars escapes by default, `{{{triple-stash}}}` unescaped output in the template would be a direct XSS sink.

### Cludo Search API Auth (components_index.js)

```javascript
fetch(`https://api-us1.cludo.com/api/v3/${t}/${e}/search`, {
    method: "POST",
    headers: { Authorization: `*** ${btoa(`${t}:${e}:SearchKey`)}` }
})
```
**Classification: INFO** — auth FORMAT exposed (btoa of `customerId:siteId:SearchKey`), but actual credentials are function parameters passed at call-time, not hardcoded.

### Prototype Pollution (cookieconsent.js)

Lines 57-68: `deepExtend()` without `__proto__` blocking:
```javascript
deepExtend: function(target, source) {
    for (var prop in source) {
        if (source.hasOwnProperty(prop)) {
            if (prop in target && this.isPlainObject(target[prop]) && this.isPlainObject(source[prop])) {
                this.deepExtend(target[prop], source[prop]);
            } else {
                target[prop] = source[prop];
            }
        }
    }
}
```
**Classification: MEDIUM** — `hasOwnProperty` is checked but `__proto__`/`constructor` not explicitly blocked. `isPlainObject` may mitigate.

### DOM XSS — DOMPurify Mitigated (components_index.js)

Multiple `innerHTML`/`insertAdjacentHTML`/`outerHTML` calls, all wrapped by:
```javascript
var me = t => $n.sanitize(t, {CUSTOM_ELEMENT_HANDLING: {tagNameCheck: /^sc-/}});
```
**Classification: INFO** — DOMPurify v3.4.2 sanitizes all dynamic HTML. Mitigated unless a DOMPurify bypass CVE exists for this version.

### postMessage with "*" Origin (otSDKStub.js)

OneTrust TCF handler responds with `"*"` origin:
```javascript
i.source.postMessage(o ? JSON.stringify(t) : t, "*")
```
**Classification: MEDIUM** — consent data could leak to any parent frame if a malicious parent sends a crafted `__tcfapiCall` message.

### REST API Endpoints (all.js)

- `rest/whois` — Main WHOIS query (GET with q, tld, type, language params)
- `rest/epp/statuscode/{code}` — EPP status code lookup
- Auth path variant: `if (verifyAuth) { restPath = "../rest/whois" }` — `authpage` hidden input controls endpoint

**Classification: MEDIUM** — endpoint information disclosure, plus auth path variant is a potential auth bypass vector.

### Undocumented JSON Endpoints (inline_6.js — SiteParams)

```javascript
window.SiteParams = {
    newsroomDirectory: "/newsroom-feature",
    dnssecScoreboard: "/dnssec-scoreboard/scoreboard.json",
    newsArticleBase: "/news-article",
    newsroom: "/newsroom-feature/newsroom-data.json",
    latestNewsArticles: "/latest-news/latest-news-articles.json",
    newsReleases: "/news-list/news-list-data.json",
    zoneCounts: "/zone-domain-counts/zone_counts.json"
};
```
The `article` parameter in the news article fetcher is taken from `URLSearchParams` without validation.

### Adobe DTM Infrastructure (adobedtm launch)

- Environment ID: `EN44eb3bf742934b83a62ea81616b98798` (production)
- Marketing Cloud Org ID: `5B4E63710A495CB6@AdobeOrg`
- Tracking server: `verisign.sc.omtrdc.net`
- Report suites: `verisignincglobal` (prod), `verisignincglobaldev` (dev)
- Build date: `2026-08-20T13:40:44Z`

**Classification: LOW** — tracking infrastructure identifiers, not credentials.

### OneTrust Configuration

- Domain Script ID: `51830805-5d0b-4714-b341-130e1ef96d80`
- Geolocation endpoint: `https://geolocation.onetrust.com/cookieconsentpub/v1/geo/location`
- Implements `__tcfapi` (TCF v2), `__gpp` (GPP), IAB stub APIs

### Version Exposure

```html
<meta property="version" content="f47fe23c606853857408e10be872a1b03c693c96" />
```
Git commit hash exposed in meta tag, logged to console on page load.

## Pattern Grid Effectiveness

| Pattern | Matches in WHOIS UI | Matches in Main Site | Useful findings |
|---------|---------------------|--------------------|-----------------|
| Hardcoded creds | 1 (fake key) | 0 | 1 INFO |
| DOM XSS sinks | 15 | 8 | 2 HIGH (unmitigated), 1 INFO (DOMPurify) |
| Proto pollution | 5 | 3 | 1 MEDIUM |
| eval() | 3 | 0 | 1 MEDIUM |
| postMessage | 0 | 1 | 1 MEDIUM |
| Open redirect | 3 | 0 | 1 HIGH |
| API endpoints | 2 | 7 | 1 MEDIUM |
| Internal hosts | 0 | 0 | 0 |
| Cookie manip | 6 | 0 | 1 LOW |
| Debug flags | 1 | 0 | 0 |

The most productive patterns for this traditional site were DOM XSS sinks, open redirect, and API endpoints. The least productive were internal hostnames and debug flags.
