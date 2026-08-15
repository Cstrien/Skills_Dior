# ReadMe.io / Hosted API Docs OpenAPI Recon

Use this when an API documentation site is hosted on ReadMe.io or another docs platform and common `/openapi.json` paths 404 or return HTML.

## Durable workflow

1. **Browse the docs first** to capture navigation categories and endpoint names.
   - ReadMe.io sites often redirect the root to `/reference` and expose endpoint groups in the left navigation.

2. **Try common spec paths, but do not stop on 404**:
   ```bash
   for path in "/openapi.json" "/api-spec/openapi.json" "/swagger.json" "/api-docs.json" "/reference/openapi.json" "/v2/openapi.json"; do
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOCS_HOST$path")
     echo "$path -> $code"
   done
   ```
   Note: ReadMe.io may return HTML 404 pages even with `Accept: application/json`.

3. **Parse the docs HTML for upstream spec URLs**.
   ReadMe.io pages can embed canonical API spec URLs in JSON/HTML state (often on the vendor’s main domain, not the docs subdomain):
   ```bash
   curl -sL "https://$DOCS_HOST/" |
     grep -oP 'https?://[^"'"'"' ]*(openapi|api_spec|swagger|spec)[^"'"'"' ]*' |
     sed 's/&quot;/"/g' | sort -u
   ```
   In one Neon case, `/openapi.json` 404ed, but the page embedded:
   `https://neon.com/api_spec/release/v2.json`.

4. **Download and validate the discovered spec**:
   ```bash
   curl -sL "$SPEC_URL" -o /tmp/openapi.json
   python3 - <<'PY'
   import json
   spec=json.load(open('/tmp/openapi.json'))
   print('openapi:', spec.get('openapi'))
   print('title:', spec.get('info',{}).get('title'))
   print('servers:', spec.get('servers'))
   print('paths:', len(spec.get('paths',{})))
   ops=sum(1 for p,i in spec.get('paths',{}).items() for m in i if m in ['get','post','put','patch','delete','head','options'])
   print('operations:', ops)
   PY
   ```

5. **Extract endpoint inventory by tag**:
   ```python
   import json
   spec=json.load(open('/tmp/openapi.json'))
   by_tag={}
   for path,item in sorted(spec['paths'].items()):
       for m in ['get','post','put','patch','delete','head','options']:
           if m not in item: continue
           op=item[m]
           for tag in op.get('tags',['untagged']):
               by_tag.setdefault(tag,[]).append((m.upper(), path, op.get('summary',''), op.get('operationId','')))
   for tag, eps in by_tag.items():
       print(f'\n## {tag} ({len(eps)})')
       for method,path,summary,opid in eps:
           print(f'{method:7s} {path} — {summary} [{opid}]')
   ```

6. **Extract auth exactly from OpenAPI**:
   - `components.securitySchemes` for scheme definitions.
   - top-level `security` for global requirements.
   - operation-level `security` for overrides.
   Report whether auth is `Authorization: Bearer`, API key header/query/cookie, OAuth2, mTLS, or session cookies.

7. **Search for SSRF / URL-controlled sinks**:
   ```python
   import json
   spec=json.load(open('/tmp/openapi.json'))
   terms=['url','uri','webhook','callback','jwks','issuer','endpoint','domain','host']
   for path,item in spec['paths'].items():
       for m,op in item.items():
           if m not in ['get','post','put','patch','delete']: continue
           blob=json.dumps(op).lower()
           if any(t in blob for t in terms):
               print(m.upper(), path, '-', op.get('summary',''))
   ```
   Then inspect referenced request schemas for fields such as `jwks_url`, `webhook_url`, SMTP `host`/`port`, redirect `domain`, identity-provider `issuer`, callback URLs, import URLs, or user-supplied endpoints.

8. **Search for operational/security metadata**:
   ```python
   for term in ['rate', 'limit', 'retry-after', 'x-ratelimit', 'webhook', 'signature', 'signing']:
       # recursively search keys and string values in the spec
       ...
   ```
   Explicitly note when rate-limit headers or webhook signature verification are **not documented**; do not claim they do not exist in implementation.

## Reporting checklist

Include:
- Spec URL and base server URL.
- OpenAPI version, API version, path count, operation count.
- Auth schemes and expected headers/cookies.
- All endpoint methods/paths grouped by tag/category.
- Deprecated/legacy endpoints.
- Endpoints handling API keys, orgs, billing, users, integrations, projects, branches, databases, roles, compute endpoints, operations.
- URL-controlled / SSRF-interesting endpoints ranked by risk.
- Whether rate-limit headers and webhook signatures are documented.
- Save the raw spec and a generated endpoint map when useful for follow-up testing.

## Pitfalls

- Do not assume `/openapi.json` 404 means no spec exists. Hosted docs often embed the real spec on a different domain.
- Count operations from methods, not only paths: one path may have GET/POST/PATCH/DELETE.
- ReadMe navigation may omit newer/preview tags; trust the spec for final inventory.
- If a field accepts a URL and docs say HTTPS is required, still record it as SSRF-relevant but note the documented constraint.
