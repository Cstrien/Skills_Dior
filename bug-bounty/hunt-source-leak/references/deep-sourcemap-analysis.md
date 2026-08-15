# Deep Source Map Analysis Workflow

Use this when source maps (`.js.map`) are already downloaded and the task is to extract endpoints, secrets, auth logic, infrastructure references, and custom configuration from `sourcesContent`.

This complements Phase 2 in `hunt-source-leak`: Phase 2 finds/downloads maps; this reference is for **deep analysis after download**.

---

## 1) Parse the `.map` JSON and extract `sourcesContent`

Source maps have:
- `sources`: original source paths
- `sourcesContent`: original file contents aligned by index

Use Python JSON parsing, not shell greps, so you can keep path/content context.

```python
#!/usr/bin/env python3
import json, os, re

def extract_sources(map_path, output_dir):
    data = json.load(open(map_path, 'r', errors='replace'))
    sources = data.get('sources', [])
    contents = data.get('sourcesContent', [])

    print(f"Source map: {map_path}")
    print(f"  sources: {len(sources)}")
    print(f"  sourcesContent: {len(contents)}")

    os.makedirs(output_dir, exist_ok=True)
    combined = open(os.path.join(output_dir, '_combined.txt'), 'w', errors='replace')

    for i, (src, content) in enumerate(zip(sources, contents)):
        if not content:
            continue

        # Important: source paths can be very long; truncate filenames to avoid Errno 36.
        safe = re.sub(r'[^a-zA-Z0-9._\-/]', '_', src).replace('/', '__')
        if len(safe) > 150:
            safe = safe[-150:]

        with open(os.path.join(output_dir, f'{i:04d}_{safe}'), 'w', errors='replace') as f:
            f.write(content)

        combined.write(f"\n{'='*80}\nSOURCE [{i}]: {src}\n{'='*80}\n")
        combined.write(content)
        combined.write(f"\n{'='*80}\n")

    combined.close()
```

---

## 2) Identify custom source files first

Before grepping every byte, separate **signal** from **library noise**.

```python
import json

data = json.load(open('bundle.js.map'))
for i, s in enumerate(data['sources']):
    if 'node_modules' not in s:
        print(f'[{i}] {s}')
```

High-signal paths:
- `../../src/**` — app-specific source
- `../../../analytics/**` — custom analytics wrappers
- `../../../glow/**` or similar design-system paths — custom shared UI
- `../../../../../js/packages/**` — internal shared packages

Low-signal paths:
- `**/node_modules/**` — library internals. Scan for hardcoded values only, but do not over-report variable names like `writeKey` in SDKs.
- `**/*.svg?react` — icons. Filter out entirely for URL endpoint scans; they are mostly `http://www.w3.org/2000/svg` namespace strings.

---

## 3) Use context-preserving pattern search

Every finding needs ±500 chars of context before classification.

```python
import json, re

data = json.load(open('bundle.js.map'))
sources = data['sources']
contents = data['sourcesContent']

patterns = {
    'api_fetch': [r'fetch\s*\(', r'axios\.', r'XMLHttpRequest', r'\.post\s*\(', r'\.get\s*\('],
    'urls': [r'https?://[^\s\'"`<>)]+' ],
    'secrets': [r'writeKey', r'apiKey', r'client[_-]?secret', r'Bearer\s+', r'Authorization'],
    'auth_flow': [r'oauth|oidc|openid', r'redirect_uri', r'client_id', r'response_type', r'grant_type', r'code_challenge'],
    'password_reset': [r'forgot[_-]?password', r'reset[_-]?password', r'reset-credentials'],
    '2fa': [r'webauthn', r'otp[_-]', r'totp', r'authenticator', r'passkey', r'fido'],
    'env': [r'staging', r'development', r'NODE_ENV', r'process\.env', r'__IS_.*_VARIANT__'],
    'postmessage_cors': [r'postMessage', r'addEventListener\s*\(\s*["\']message', r'origin\s*[:=]', r'crossOrigin'],
    'keycloak': [r'kcContext', r'pageId', r'realm', r'properties'],
}

for label, pats in patterns.items():
    print(f'\n## {label}')
    for i, (src, content) in enumerate(zip(sources, contents)):
        if not content:
            continue
        for pat in pats:
            for m in re.finditer(pat, content, re.I):
                start = max(0, m.start() - 500)
                end = min(len(content), m.end() + 500)
                print(f'\n--- [{i}] {src}\nMatched: {m.group()}\n')
                print(content[start:end])
```

---

## 4) Classify common source-map-specific artifacts correctly

### Server-injected keys are not hardcoded secrets

Example pattern (Keycloakify):

```typescript
export const kcEnvDefaults = {
  GTM_ID: '',
  SEGMENT_WRITE_KEY_WEB_UI: '',
};
const { SEGMENT_WRITE_KEY_WEB_UI: segmentKey, GTM_ID: gtmKey } = kcContext.properties;
```

Classification:
- This reveals **which properties exist**.
- It does **not** reveal values.
- Report as custom configuration, not a secret.

### SDK `writeKey` variables are not hardcoded Segment keys

`writeKey` in `@segment/analytics-next` sources is usually an SDK parameter or request-body field. Confirm whether the value is actually embedded. If the value comes from `settings.apiKey`, `props`, `context`, or a server-injected property, it is not a hardcoded key.

### Sanitized `dangerouslySetInnerHTML` is usually not XSS

If source has:
```tsx
dangerouslySetInnerHTML={{ __html: kcSanitize(message.summary) }}
```
then note it only if sanitizer is bypassable. Do not report `dangerouslySetInnerHTML` by itself.

---

## 5) What to extract in the final report

Use sections like:

1. **API endpoints / fetch / axios / URL patterns**
2. **Secrets and analytics keys** — include Secret Gate scoring; explicitly say when none are hardcoded
3. **Authentication flow logic** — OAuth/OIDC, Keycloak page flow, social/IDP providers
4. **Internal hostnames / packages / service names**
5. **Password reset flow details**
6. **2FA / OTP / WebAuthn implementation**
7. **Environment-specific config** — staging/dev flags, build-time constants
8. **Build path leaks** — source path infrastructure details
9. **postMessage / CORS / cross-origin behavior**
10. **Non-standard realm/custom configuration**

---

## 6) Databricks/Lakebase path-leak pattern

A source path like:

```text
../../../../.../.databricks/cache/yarn_node_modules/8/<sha1>/yarn_install_node_modules/lakebase/web/node_modules/...
```

reveals:
- Build platform: Databricks workspace (`.databricks/cache`)
- Dependency cache: `yarn_node_modules/<shard>/<sha1>`
- Internal project name: `lakebase/web`
- Monorepo/shared packages if present (`@databricks/web-shared/*`, `@neondatabase/*`)

Classify as INFO/LOW infrastructure exposure unless it includes credentials or reachable internal hosts.

---

## 7) Verification checklist

Before writing findings:

- [ ] Parsed JSON and confirmed `sourcesContent` count aligns with `sources`
- [ ] Listed non-`node_modules` sources and read custom app files first
- [ ] Extracted ±500 chars context for every suspicious string
- [ ] Applied 4-Check Secret Gate to keys/tokens
- [ ] Applied 3-Check Endpoint Gate to API routes
- [ ] Distinguished server-injected config from hardcoded values
- [ ] Filtered SVG namespace URLs and third-party SDK internals
- [ ] Reported source paths/build infrastructure as exposure, not secrets
