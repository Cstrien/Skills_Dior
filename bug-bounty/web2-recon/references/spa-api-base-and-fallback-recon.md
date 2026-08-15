# SPA API Base Discovery and Fallback False Positives

Session-derived recon pattern for React/Vite/CRA/Refine-style SPAs behind a reverse proxy. Use when every guessed API path returns the same small `index.html` body with HTTP 200, or when `.map` checks appear to succeed but the body is not a real source map.

## Key lesson

A `200` status is not proof of a real resource on SPA deployments. Many frontends route all unknown paths to `index.html`, including:

- `/robots.txt`, `/sitemap.xml`, `/security.txt`
- `/auth/me`, `/users`, `/api/*`
- `/assets/main.js.map`

Treat any uniform small HTML body as a frontend fallback until proven otherwise.

## 1. Detect SPA fallback before claiming hits

For each candidate path, record status, content-type, body size, title, and first bytes:

```bash
for p in /robots.txt /sitemap.xml /auth/me /api/me /assets/app.js.map; do
  curl -sk -D /tmp/h -o /tmp/b -w "$p -> %{http_code} %{size_download}\n" "https://$TARGET$p"
  ctype=$(grep -i '^content-type:' /tmp/h | tr -d '\r')
  prefix=$(head -c 80 /tmp/b | tr '\n' ' ')
  echo "  $ctype | $prefix"
done
```

Fallback signature:

- `Content-Type: text/html`
- body starts with `<!doctype html>`
- same exact byte size/ETag across unrelated paths
- same script/style asset references

Do not count those paths as real endpoints or exposed source maps.

## 2. Validate source map exposure by parsing JSON

Do not report `.js.map` on HTTP 200 alone. Download and parse it:

```bash
curl -sk -o /tmp/map "https://$TARGET/assets/main.js.map"
python3 - << 'PY'
import json
p='/tmp/map'
raw=open(p,'rb').read(200)
if raw.lstrip().startswith(b'<!doctype') or raw.lstrip().startswith(b'<html'):
    print('SPA fallback, not a source map')
else:
    data=json.load(open(p, errors='ignore'))
    print('real map sources=', len(data.get('sources', [])), 'has_sourcesContent=', bool(data.get('sourcesContent')))
PY
```

A real source map is JSON with fields such as `version`, `sources`, `mappings`, and often `sourcesContent`.

## 3. Extract the API base prefix from minified JS

If `/auth/me` or `/users` return SPA HTML, search the main bundle for axios/fetch base URL variables and endpoint calls. Vite/React bundles often minify a base constant (example pattern: `ase="/checkinapi"`) then call `ct.get('/auth/me')`.

```bash
curl -sk "https://$TARGET/" -o index.html
js=$(grep -oE 'src="[^"]+\.js"' index.html | sed 's/src="//;s/"//' | head -1)
case "$js" in http*) jsurl="$js";; /*) jsurl="https://$TARGET$js";; *) jsurl="https://$TARGET/$js";; esac
curl -sk "$jsurl" -o main.js

python3 - << 'PY'
import re
js=open('main.js', errors='ignore').read()
print('candidate baseURL constants:')
for m in re.finditer(r'\b[A-Za-z_$][\w$]{1,8}\s*=\s*["\'](/[^"\']*(?:api|backend|service|graphql|checkin)[^"\']*)["\']', js, re.I):
    print(' ', m.group(0)[:160])
print('\naxios/fetch endpoint calls:')
for pat in [r'\.(get|post|put|patch|delete)\(["\']([^"\']+)["\']', r'fetch\(["\']([^"\']+)["\']']:
    for m in sorted(set(re.findall(pat, js)))[:200]:
        print(' ', m)
PY
```

Then retest endpoints with the discovered prefix:

```bash
BASE=/checkinapi
for ep in / /auth/me /auth/login /users /settings; do
  curl -sk -D- -o /tmp/b -w "\n$BASE$ep -> %{http_code} %{size_download}\n" "https://$TARGET$BASE$ep" | head -30
  head -c 200 /tmp/b; echo
done
```

Real API responses usually have `application/json`, framework error shapes, auth errors (`401`), or service banners rather than the SPA HTML.

## 4. Same-IP alternate services are part of recon

After resolving the target, scan/probe non-standard ports on the IP. Admin/security consoles may be exposed on the same host even when the web app itself is hardened.

High-signal examples to recognize:

- `:8080` Kaspersky Security Center Web Console (`Kaspersky Security Center`, version in footer)
- `:3800/:3809` Splunk Web / splunkd (`Server: Splunkd`, Atom XML with `<generator version=...>`)
- `:9200` Elasticsearch (`security_exception`, `WWW-Authenticate: Basic/Bearer/ApiKey`)

These may be hygiene/exposure findings even when authenticated, and they guide follow-up CVE/default-credential/rate-limit testing if in scope.

## Pitfalls

- A frontend 200 with `index.html` is not a discovered API endpoint.
- A `.map` URL returning `index.html` is not source map exposure.
- API paths extracted from JS may be relative to a hidden base prefix. Test both raw paths and the discovered base prefix.
- CORS `Access-Control-Allow-Credentials: true` alone is not a finding; it needs an allowed/reflected `Access-Control-Allow-Origin` and browser-readable sensitive data.
