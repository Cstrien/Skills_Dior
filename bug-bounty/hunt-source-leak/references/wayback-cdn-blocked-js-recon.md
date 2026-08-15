# Wayback + Archived JS Recon When CDN/WAF Blocks Live Fetches

Use this when the live target is behind Akamai/Cloudflare/Fastly-style edge controls and normal recon cannot fetch HTML/API routes reliably, but passive mapping is still needed.

## Trigger signals

- TLS handshake succeeds and certificate/SAN data is readable.
- `curl --http2` returns HTTP/2 stream reset / protocol error.
- `curl --http1.1` connects but times out with 0 bytes received.
- Headless browser navigation fails with protocol error, while tiny static files like `/manifest.json` or `/sw.js` may still load.
- Direct API probes are noisy/blocked, but archived HTML/JS, service-worker manifests, or CDN-hosted static bundles are available.

Do **not** encode this as “browser tools are broken” or “curl cannot work.” Treat it as a target-edge transport problem and pivot to passive/static artefacts.

## Workflow

### 1. Confirm edge + cert context

```bash
dig +short www.target.com CNAME A
echo | openssl s_client -connect www.target.com:443 -servername www.target.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Record CDN CNAMEs and SAN sibling domains (`*.api`, `*.assets`, `*.info`, etc.) because JS often references them.

### 2. Check small static files first

When homepage/API routes hang, small static files may still be retrievable and can reveal the current frontend build:

```bash
curl --http1.1 -k -sS -D sw.hdr -o sw.js \
  --max-time 15 'https://www.target.com/sw.js' \
  -H 'User-Agent: Mozilla/5.0' \
  -H 'Accept-Encoding: identity'

curl --http1.1 -k -sS -D manifest.hdr -o manifest.json \
  --max-time 10 'https://www.target.com/manifest.json' \
  -H 'User-Agent: Mozilla/5.0'
```

Service workers are especially valuable for PWAs: they often contain a precache manifest listing hundreds of current JS/CSS chunks on an asset CDN even when the live HTML is blocked. Extract bundle URLs:

```python
import re
sw = open('sw.js', errors='ignore').read()
for u in sorted(set(re.findall(r'https://[^"\'`,\s\\]+/assets/js/[^"\'`,\s\\]+\.js', sw))):
    print(u)
```

Download selected chunks by name (`auth`, `login`, `forgot`, `address`, `cart`, `wishlist`, `checkout`, `payment`, `profile`, `order`) and grep for endpoints, redirect sinks, source-map refs, and environment/config strings. If chunks include `//# sourceMappingURL=...`, verify the `.map` URL: a `BlobNotFound`/404 means it is only a stale build annotation, not a source-map leak.

### 3. Pull archived homepage and extract JS bundles

```bash
curl -L -sS --max-time 45 \
  'https://web.archive.org/web/2024/https://www.target.com/' \
  -o archived_home.html

python3 - <<'PY'
import re
h=open('archived_home.html',errors='ignore').read()
for u in sorted(set(re.findall(r'src="(https?://[^"]+\.js[^"]*)"', h))):
    print(u)
PY
```

Wayback rewrites asset URLs as `https://web.archive.org/web/<timestamp>js_/https://asset-host/path/file.js`; download those archived JS URLs, not the live asset URL, when the live edge blocks.

### 4. Query CDX narrowly, not broadly

Broad CDX queries can be polluted with SEO/spam URLs. Prefer focused queries:

```bash
curl -L -sS --max-time 90 \
  'https://web.archive.org/cdx?url=www.target.com/api/*&output=json&fl=original,statuscode,mimetype,timestamp&filter=statuscode:200&collapse=urlkey&limit=1000' \
  -o api_cdx.json

curl -L -sS --max-time 90 \
  'https://web.archive.org/cdx?url=www.target.com/*.js&output=json&fl=original,statuscode,mimetype,timestamp&filter=statuscode:200&collapse=urlkey&limit=1000' \
  -o js_cdx.json
```

If `output=json` returns a single JSON array, parse it with `json.loads(raw)`; if using older line-oriented endpoints, parse line-by-line. Check first bytes before assuming JSONL. Use `-L` because CDX may 301 to the current endpoint.

### 5. Extract API config objects from JS

Archived or live Webpack/React bundles often contain JSON config maps with `root`, `clientRoot`, and `path` fields. Extract both URL strings and context around known hostnames:

```python
import re
js = open('main.js', errors='ignore').read()
for needle in ['api.target.com','gateway','/auth/','/v1/','/v2/','/checkout','/wishlist']:
    for m in list(re.finditer(re.escape(needle), js, re.I))[:5]:
        print(js[max(0,m.start()-300):m.end()+300].replace('\n',' ')[:900])

paths = sorted(set(re.findall(r'["\'](/(?:api|gateway|auth|v\d|checkout|my|user|cart|wishlist|address)[^"\']*)["\']', js, re.I)))
print('\n'.join(paths))
```

Write a surface map that preserves host + path + purpose, e.g. `api.target.com / v1/cart/default/summary`, not just `/summary`.

### 6. Validate safely

- Test only low-risk GET/read endpoints unauthenticated first.
- Treat `401 {"message":"Unauthorized"}` as useful evidence that an endpoint exists and has an auth gate; it is not a bug.
- Treat `403 Access Denied` from the CDN as a transport/WAF result, not app-level authorization proof unless a browser/session confirms it.
- Treat public feature-flag/config endpoints as recon leads unless they expose sensitive user data, working secrets, or auth bypass material.
- Archived PII/order IDs from Wayback are leads for IDOR shape, not proof of current exposure.

## Pitfalls

- Wayback responses may be wrapper HTML with `Wayback Machine` title, not the target JSON. Confirm body starts with `{`/`[` and content type when possible.
- CDX broad URL lists can be full of spam paths; narrow by `/api/*`, `*.js`, or known asset hosts.
- Firebase/Google/client IDs in frontend bundles are often public identifiers. Test current permissions before treating them as secrets.
- Do not report source maps, archived configs, public service-worker precache manifests, or client IDs alone unless a concrete current impact is demonstrated.
- A service worker with `service-worker-allowed: /` is useful recon, but not itself a vuln; look for cache poisoning, stale sensitive cache entries, or exposed privileged routes before reporting.
