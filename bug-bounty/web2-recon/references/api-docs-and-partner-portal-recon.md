# API Docs / Developer / Partner Portal Recon

Session-derived technique for API-docs and partner/seller-portal subdomains
(e.g. `apidocs.*`, `partnerportal.*`, `partners.*`, `developer.*`).
These portals are high-yield because they expose internal API maps,
onboarding/upload flows, and backend service names — often with weaker auth
than the main app.

## Signals

- A subdomain named `apidocs`, `developer`, `docs`, `portal`, `partnerportal`, `seller`, or `partnersapi` is often higher-value than the marketing site.
- React/CRA/Redocly/OpenAPI portals may hide the real API map in JS bundles even when `/swagger.json` and `/openapi.json` are not directly exposed.
- Webpack Module Federation `boot.*.js` is a chunk manifest, not the app code. Real routes live in lazy chunks fetched from `assets/<chunk>.<hash>.js`.
- Partner/seller portals commonly use a separate API origin discovered only from bundles (example pattern: `partnerportal.example.com` frontend, `partnersapi.example-info.com` backend).

## 1. Download boot + lazy chunks

```python
import re, urllib.request, os, concurrent.futures
boot = open('boot.js', errors='ignore').read()
pairs = re.findall(
    r'"?([A-Za-z0-9_~@./\-]*(?:Register|Login|Dashboard|Partner|Seller|'
    r'Upload|Invoice|Payment|Claims|Manufacturing|Analytics|Admin|Order|'
    r'Auth)[A-Za-z0-9_~@./\-]*)"?\s*:\s*"([a-f0-9]{20})"',
    boot, re.I)
base = 'https://myntraspectrum.myntassets.com/spectrum-assets/spectrum/partners/assets/'
out  = 'chunks'; os.makedirs(out, exist_ok=True)
def fetch(p):
    n, h = p
    url = base + n + '.' + h + '.js'
    try:
        data = urllib.request.urlopen(url, timeout=10).read()
        open(os.path.join(out, n.replace('/', '_') + '.js'), 'wb').write(data)
        return f'OK {len(data)} {url}'
    except Exception:
        return None
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
    for r in ex.map(fetch, sorted(set(pairs))): pass
```

## 2. Run analyzer per app/host

```bash
python3 ~/.hermes/skills/bug-bounty/web2-recon/scripts/lightweight_js_analyzer.py chunks
```

Keep analyzer output per app/host (the tool overwrites `js_paths.txt` etc.
in the cwd). Rename outputs to avoid clobbering:
`mv js_paths.txt partner_api_paths.txt`.

## 3. Triage extracted routes

High-value route families to grep for:

- `getServiceEndpointListingExternal` — unauthenticated API metadata leak
  (client_name, openapi_json filename, postman_collection filename, team_name).
- `onboardServiceByYamlUrl`, `getOpenApiJsonContent`, `uploadYamlFile`,
  `uploadFileToContainer` — SSRF candidates (server fetches a URL you supply).
- `file-manager/getDownloadUrl`, `file-manager/source?url=` — file/SSRF.
- `vendorService/contract/v2/partner/{id}/{type}/{subtype}` — IDOR/BOLA.
- `report/summary/next-payment`, `outstanding-payment`, `payment-history` —
  financial data.
- `seller-performance/dashboard`, `seller-activation` — seller PII.
- `terms/search/download/{id}` — file download IDOR.
- `gopi/verify/otp/{context}/send|resend|verify` — registration OTP flow.
- `gopi/user-creation/create-user` — account creation.

## 4. Probe the real backend, not the SPA host

SPA hosts can return index.html (200) for every `/api/*` path — that is a
fallback, NOT a real API response. Extract the backend host from JS or
response headers (`x-myntra-served-by`, `x-k8s-route-id`) and probe there:

```python
import urllib.request, ssl
ctx = ssl.create_default_context()
for p in partner_api_paths:
    url = 'https://partnersapi.example.com' + p
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0',
                                                   'Accept':'application/json'})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            body = r.read(800).decode('utf-8','ignore')
            if '<!doctype' not in body.lower():
                print(r.status, len(body), p, body[:200])
    except Exception:
        pass
```

## 5. Method-override and path-confusion

Test `X-HTTP-Method-Override`, `GET` vs `POST` vs `OPTIONS`/`HEAD` on
backend endpoints. Some endpoints return unauthenticated stack traces on
`GET` but 401 on `POST`; the stack trace leaks internal file paths, K8s
pod names, and service names.

## 6. Extract registration flow from JS

When the browser tool can't trigger the SPA route (click does nothing,
direct URL returns empty), extract the registration API from JS chunks:

- `/api/gopi/verify/otp/{onboardingPhone|onboardingEmail}/send`
- `/api/gopi/verify/otp/{context}/resend`
- `/api/gopi/verify/otp/{context}/verify`
- `/api/gopi/user-creation/create-user`

Payload shape often appears in JS reducers/actions:
```json
{
  "email": "EMAIL",
  "vob": {
    "basicInformation": {
      "email": "EMAIL",
      "primaryContactEmail": "EMAIL",
      "name": {"firstName": "FN", "lastName": "LN"},
      "phone": {"isd": "+91", "number": "10-digit"}
    }
  },
  "password": "PASSWORD",
  "showV2": true
}
```

Do not send OTP to numbers/emails you do not control. Stop at the send
step and hand off to the operator for OTP entry.

## 7. Pitfalls

- Direct filenames leaked by a listing endpoint may contain spaces; URL-encode them before testing direct access.
- A `200` on frontend `/api/...` may be just the SPA HTML fallback. Confirm `Content-Type` and body prefix before counting it as API access.
- Public API-doc metadata alone is usually Info/Low unless it reveals sensitive endpoints, working secrets, or unauthenticated data/actions.
- CORS `Access-Control-Allow-Credentials: true` is not exploitable if `Access-Control-Allow-Origin` is restricted to the legitimate origin and external origins are rejected.
