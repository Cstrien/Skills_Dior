# Craft CMS Attack Surface Reference

Session-derived recon for targets running Craft CMS (detected via `X-Powered-By: Blitz` header, `/cpresources/` in robots.txt, or `actions/` path convention). Craft CMS is a PHP-based CMS less commonly covered by pentesting skills than WordPress/Drupal.

## Fingerprinting Signals

| Signal | Where | Meaning |
|--------|-------|---------|
| `X-Powered-By: Blitz` | HTTP response header | Blitz static-page caching plugin for Craft CMS |
| `Disallow: /cpresources/` | robots.txt | Craft control-panel resources |
| `Disallow: /vendor/` | robots.txt | Composer vendor dir (Craft is PHP/Composer-based) |
| `Disallow: /.env` | robots.txt | Craft uses .env files for config |
| `Disallow: /cache/` | robots.txt | Craft/Blitz cache directory |
| `/actions/` path convention | URL structure | Craft's action controller routing (`actions/<controller>/<method>`) |
| `sitemap-articles-N.xml` | sitemap index | Craft SEO plugin sitemap naming pattern |
| Vite build system | JS bundles (`/dist/main-<hash>.js`) | Craft frontend build tool |

## Attack Surface Map

### Admin / Control Panel
Craft's admin panel is NOT at `/admin` by default (returns 404 on many Craft sites). The control panel URL is configurable and often hidden. Test:

```bash
# Common Craft CP paths (configurable, try all)
/admin
/cp
/index.php?p=admin
/index.php/admin
/actions/users/login
/admin/login
```

If CP returns 404, the admin URL may have been renamed. Check:
- JS bundles for references to the CP path
- `window.Craft` global object
- Source maps for PHP route definitions

### GraphQL API
Craft CMS has a built-in GraphQL API (Craft Pro feature). Endpoints:

```bash
# Craft GraphQL endpoint patterns
/actions/graphql/graphql
/actions/graphql/api
/graphql
/api/graphql
```

Test for:
- Introspection enabled: `{ __schema { types { name } } }`
- Missing field-level authz (Craft's GraphQL layer may not enforce per-field permissions)
- Query depth/complexity limits (DoS)
- Mutation IDOR via `node()` / `entry()` queries

### Action Controller Endpoints
Craft routes all dynamic requests through `index.php` with `actions/` prefix:

```bash
# Craft action endpoints to probe
/actions/users/login
/actions/users/logout
/actions/users/save-user
/actions/users/forgot-password
/actions/entries/save-entry
/actions/entries/delete-entry
/actions/blitz/cache/refresh    # Blitz plugin
```

### .env File Exposure
Craft uses `.env` files extensively. The robots.txt `Disallow: /.env` confirms presence. Test:

```bash
curl -sS https://target/.env          # Often 403 (WAF) — try bypasses
curl -sS https://target/.env.local
curl -sS https://target/.env.production
curl -sS https://target/.env.backup
```

Craft `.env` typically contains: `DB_PASSWORD`, `DB_DATABASE`, `DB_USER`, `SECURITY_KEY`, `CP_TRIGGER`, `SITE_URL`.

### S3 Asset Buckets
Craft sites commonly store assets on S3 (via AWS/volume plugin):

```bash
# assets.thecurrent.com pattern — check for S3 bucket
curl -sS -I https://assets.<target>/
# Look for x-amz-bucket-region header (leaks region even on AccessDenied)
# x-amz-request-id, x-amz-id-2 headers confirm S3 backend
```

Test for:
- Bucket listing (`?list-type=2`)
- Public object read (try common paths: `/images/`, `/uploads/`, `/backups/`)
- Write access (PUT test file — requires signed request, but test ACL)

### Sentry DSN (Observability)
Craft sites often expose Sentry DSN in loader scripts. Format: `{hash}@o{org}.ingest.{region}.sentry.io/{project}`. This is a **public ingest endpoint** — INFO at most, NOT a credential. Anyone with the DSN can only SEND error reports, not read data. See `js-analysis-anti-false-positive` for the Sentry DSN false-positive pattern.

### Blitz Cache Plugin
Blitz generates static cached pages. Test for:
- Cache poisoning via unkeyed headers (`X-Forwarded-Host`, `X-Forwarded-Proto`)
- Cache deception (request authenticated page with cacheable extension)
- Stale cache after content change (race condition)
- `actions/blitz/cache/refresh` endpoint exposure

## Cloudflare + Craft CMS Interaction

When Craft is behind Cloudflare (common for Blitz-cached sites):

1. **Sitemap subpaths may trigger CF challenge** — `sitemap.xml` index loads fine but individual `sitemap-articles-1.xml`, `sitemap-pages-1.xml` etc. trigger Cloudflare "Just a moment..." challenge. Use the browser (not curl) to fetch these.

2. **Rate limiting (429) on directory probes** — Cloudflare may rate-limit probes to `/vendor/`, `/cpresources/`, `/cache/`, `.git/`, `package.json`, `composer.json`. Space out requests or use browser.

3. **Admin paths blocked by CF WAF** — `index.php?p=admin` triggered a Cloudflare "Sorry, you have been blocked" page. The WAF detects SQL-like patterns in query params. Browser navigation to the same URL may also be blocked.

4. **CF challenge bypass for content enumeration** — The homepage and article pages load fine in browser (CF challenge solved once), while curl gets challenged on sitemap subpaths. Use browser_navigate + browser_console for JS extraction when CF challenge is active.

## JS Bundle Analysis for Craft Sites

Craft frontends are often built with Vite. The main bundle (`/dist/main-<hash>.js`) is typically 200KB-500KB and contains:

- Alpine.js or Vue.js framework code (not Craft-specific)
- Video player libraries (vidstack — not an attack surface)
- Share button URLs (social media, not interesting)
- Analytics SDK configs (Marketo, LinkedIn, Facebook Pixel, Trade Desk, ZoomInfo)

**Low yield for secret extraction** — Craft sites are content-publishing platforms, not SaaS apps. The JS bundle rarely contains API keys or internal endpoints. Focus instead on:
- Craft action endpoints (PHP backend)
- GraphQL API (if Pro license)
- S3 asset bucket misconfig
- Admin panel discovery
- .env file exposure
- Blitz cache poisoning
