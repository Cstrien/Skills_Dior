# CMS Fingerprints & Probe Paths

> Reference content for the `offensive-osint` skill. CMS detection via headers, robots.txt, and probe paths — covering Craft CMS, WordPress, Drupal, Joomla, Ghost, ExpressionEngine, Statamic, October CMS, Bolt, and other PHP/Node CMS platforms.

## When to use

After initial recon identifies a CMS (via headers, robots.txt, or HTML signatures), use these fingerprints to:
1. Confirm the CMS and version
2. Identify CMS-specific attack surface (admin panels, API endpoints, config files)
3. Map known CVEs to the detected version
4. Target CMS-specific probe paths not covered by generic webapp checks

---

## CMS Detection Signatures

### Craft CMS

**Header signatures:**
- `X-Powered-By: Blitz` (Blitz is the most common Craft CMS caching plugin)
- `Set-Cookie: CraftSessionId=...`
- `Set-Cookie: CRAFT_CSRF_TOKEN=...`

**robots.txt patterns (high-confidence fingerprint):**
```
Disallow: /cpresources/
Disallow: /vendor/
Disallow: /.env
Disallow: /cache/
```
The combination of `cpresources` + `vendor` + `cache` Disallow rules is definitive for Craft CMS.

**Probe paths:**
```
/admin                    → Craft admin login (may be renamed)
/actions                  → Craft controller action router
/actions/graphql/graphql  → Craft GraphQL endpoint
/actions/graphql/api       → Craft GraphQL alt endpoint
/index.php/admin           → Admin via index.php
/index.php?p=admin         → Admin via query param
/cpresources/              → CMS resources (JS/CSS for control panel)
/vendor/                   → Composer vendor dir (should be blocked)
/cache/                    → Cache directory
/storage/                  → Runtime storage
/config/                   → Config directory
/composer.json             → Composer config
/composer.lock             → Locked dependencies
/.env                      → Environment file (CRITICAL if exposed)
```

**Craft GraphQL endpoint:** `actions/graphql/graphql` (if GraphQL plugin installed). Test for introspection — Craft's GraphQL implementation can expose all entry types, fields, and sections.

**Craft CMS attack surface:**
- Admin login at `/admin` (or custom path set in `config/general.php`)
- If `allowAdminChanges` is true in production → admin can modify schema, install plugins, write templates
- CSRF token in forms — check for missing validation on custom forms
- Craft's `Element API` plugin → custom REST endpoints at `/actions/element-api/...`
- Blitz cache → cache poisoning via Host header (Blitz serves cached pages by Host)
- Craft Commerce → e-commerce endpoints, payment processing

**Known CVEs (Craft CMS core + plugins):**
- CVE-2023-41992 — Craft CMS admin auth bypass (versions < 4.4.0)
- CVE-2021-41224 — Craft CMS CSRF on file upload → RCE chain
- Blitz plugin — cache poisoning via Host header injection

---

### WordPress

**Header signatures:**
- `X-Powered-By: WordPress` (sometimes)
- `Link: <https://example.com/wp-json/>; rel="https://api.w.org/"` (REST API link header)
- `Set-Cookie: wordpress_logged_in_...`, `wp-settings-*`

**robots.txt patterns:**
```
Disallow: /wp-admin/
Disallow: /wp-content/
Disallow: /wp-includes/
```

**HTML signatures:**
- `<meta name="generator" content="WordPress X.Y.Z">`
- `<link rel='stylesheet' href='...wp-content/themes/...'>`
- `wp-json` in script src URLs

**Probe paths:**
```
/wp-admin/                 → Admin dashboard
/wp-login.php              → Login page
/wp-json/wp/v2/            → REST API (posts, users, media)
/wp-json/wp/v2/users       → User enumeration (unless disabled)
/wp-json/                  → REST API root
/xmlrpc.php                → XML-RPC interface (pingback DDoS, brute-force)
/wp-content/uploads/       → Upload directory
/wp-content/plugins/       → Plugin directory
/wp-content/themes/        → Theme directory
/wp-content/debug.log      → Debug log (if WP_DEBUG_LOG enabled)
/wp-config.php             → Config file (should never be readable)
/wp-config.php.bak         → Backup config
/.wp-config.php.swp        → Vim swap file
/wp-content/backup-db/     → Backup databases
/wp-content/uploads/backupbuddy/  → BackupBuddy backups
/readme.html               → WordPress version readme
/license.txt               → License file (version info)
```

**WordPress user enumeration:**
- `GET /wp-json/wp/v2/users` — REST API (modern)
- `GET /?author=1` through `/?author=10` — author ID enumeration (redirects to `/author/username/`)
- `GET /wp-json/wp/v2/users/1` — individual user

**Known high-impact areas:**
- `xmlrpc.php` — pingback amplification, brute-force via `system.multicall`
- Plugin/theme vulnerabilities — check `/wp-content/plugins/` for known plugin slugs
- `wp-config.php` exposure — CRITICAL (DB credentials, auth keys)

---

### Drupal

**Header signatures:**
- `X-Generator: Drupal X (https://www.drupal.org)`
- `X-Drupal-Cache: HIT/MISS`
- `Set-Cookie: SSESS...` (session cookie with SSESS prefix)

**robots.txt patterns:**
```
Disallow: /core/
Disallow: /modules/
Disallow: /profiles/
Disallow: /sites/
Disallow: /themes/
```

**Probe paths:**
```
/user/login               → Login page
/admin                    → Admin dashboard
/node                     → Content listing
/?q=user                  → Clean URL disabled variant
/?q=admin                 → Admin (clean URL disabled)
/sites/default/settings.php  → Config (DB credentials if exposed)
/sites/default/files/     → File uploads
/core/install.php         → Install page (should be removed post-install)
/update.php               → Update script (should be auth-gated)
/modules/                 → Module directory
/themes/                  → Theme directory
```

**Known CVEs:**
- CVE-2018-7600 (Drupalgeddon2) — RCE via `/?q=user/password&name[#]` rendering
- CVE-2019-6340 (Drupalgeddon3) — REST module RCE
- CVE-2021-32610 — XSS via block content

---

### Joomla

**Header signatures:**
- `X-Powered-By: Joomla! X.Y.Z`
- `Set-Cookie: joomla_...`

**Probe paths:**
```
/administrator/           → Admin panel
/index.php?option=com_users&view=registration  → Registration
/index.php?option=com_users&view=login         → Login
/components/              → Components directory
/modules/                 → Modules directory
/plugins/                 → Plugins directory
/templates/               → Templates directory
/configuration.php         → Config file (DB credentials if exposed)
/installation/            → Installer (should be removed)
/api/                     → Joomla 4+ API
```

---

### Ghost

**Header signatures:**
- `X-Ghost-Cache-Status: HIT`
- `X-Forwarded-Host` echoed in headers
- `Set-Cookie: ghost_admin_...`

**Probe paths:**
```
/ghost/                   → Admin panel (Ghost admin SPA)
/ghost/api/v3/admin/      → Admin API
/ghost/api/v3/content/    → Content API (posts, pages, tags, authors)
/ghost/api/canary/        → Canary API (sometimes exposed)
/members/                 → Members area
/.ghost/                  → Ghost internal
```

**Ghost attack surface:**
- Admin API can sometimes be accessed without auth if misconfigured
- Content API with `key` param — sometimes the key is leaked in JS

---

### ExpressionEngine

**Probe paths:**
```
/admin.php               → Control panel
/index.php/admin          → Admin
/system/                  → System directory
/themes/                  → Themes
/.env                     → Environment (if EE6+)
```

---

### Statamic

**Probe paths:**
```
/cp                       → Control panel
/cp/auth/login            → Login
/cp/addons                → Addons
/cp/utilities            → Utilities
```

---

### October CMS

**Probe paths:**
```
/backend                  → Backend admin
/backend/auth/signin      → Sign in
/cms                      → CMS area
/backend/auth/recover     → Password recovery
```

---

## Cloudflare Challenge Bypass for CMS Recon

When a CMS site is behind Cloudflare with "Under Attack" mode or challenge pages on specific paths (e.g., sitemap subpaths, admin paths), curl will receive the CF challenge HTML instead of the real content.

**Technique: Use browser tools to bypass CF challenge, then extract data via browser_console.**

```bash
# curl gets CF challenge on sitemap-pages-1.xml:
curl -sS https://target.com/sitemap-pages-1.xml  # → CF challenge HTML

# browser_navigate bypasses the challenge (headless browser solves it):
# Then use browser_console to extract content:
#   browser_navigate(url="https://target.com/sitemap-pages-1.xml")
#   browser_console(expression="document.documentElement.outerHTML")
```

**When this applies:**
- CF managed challenge on sitemap subpaths (sitemap-articles-1.xml, etc.)
- CF challenge on `/admin` or `/wp-admin` paths
- CF challenge on API endpoints (`/wp-json/`, `/actions/`)
- Any path where curl gets "Just a moment..." HTML but the main domain loads in browser

**Pattern observed (this engagement):**
- `curl https://www.thecurrent.com/sitemap.xml` → 200 with sitemap index (main domain cached/whitelisted)
- `curl https://www.thecurrent.com/sitemap-pages-1.xml` → CF challenge HTML (subpath challenged)
- `browser_navigate` to the same URL → real XML content (browser solves JS challenge)

---

## S3 Bucket Discovery via CMS Asset Subdomains

CMS sites often use a dedicated assets subdomain (e.g., `assets.thecurrent.com`) for images, CSS, and JS. This subdomain is frequently an S3 bucket behind Cloudflare.

**Detection:**
```bash
# DNS resolution reveals the chain
dig +short assets.thecurrent.com
# → assets.thecurrent.com.cdn.cloudflare.net
# → 104.20.18.72  (Cloudflare IP)

# Direct S3 access (bypassing Cloudflare) reveals the bucket
curl -sS https://assets.thecurrent.com/
# → <?xml version="1.0" encoding="UTF-8"?>
# → <Error><Code>AccessDenied</Code><Message>Access Denied</Message>
# → <RequestId>TEFNT33DHGEN9XMR</RequestId>
# → <HostId>...</HostId></Error>

# Headers reveal S3 region
curl -sS -I https://assets.thecurrent.com/
# → x-amz-bucket-region: us-west-2
# → x-amz-request-id: ...
```

**What this tells you:**
- The bucket exists (AccessDenied, not NoSuchBucket)
- The region (us-west-2)
- The bucket name is likely `assets.thecurrent.com` or similar
- If Cloudflare CDN image transforms are in use (`/cdn-cgi/image/...`), the S3 bucket is the origin

**Next steps after S3 bucket discovery:**
- Test for anonymous listing: `curl https://assets.thecurrent.com.s3.us-west-2.amazonaws.com/?list-type=2`
- Test for individual object access: `curl https://assets.thecurrent.com.s3.us-west-2.amazonaws.com/images/`
- Check for bucket policy misconfiguration (public read, public write)
- Look for `.env`, `config.json`, backup files in the bucket
- Test PUT/DELETE for write access (if policy allows)

---

## CMS-to-Cloud-Asset Pivot Table

| CMS fingerprint | Cloud asset commonly found | How to discover |
|---|---|---|
| Craft CMS (Blitz) | S3 bucket for `assets.*` subdomain | DNS resolve assets subdomain → S3 XML error |
| WordPress | S3/Google Cloud for `wp-content/uploads/` | Check upload URLs for S3/GCS patterns |
| Ghost | S3 for image CDN | Check image src URLs for S3 patterns |
| Drupal | S3 for `sites/default/files/` | Check file URLs for S3 patterns |
| Any CMS | CloudFront distribution | Check `X-Amz-Cf-*` headers on asset responses |

---

## Integration with existing offensive-osint references

- **`probes-and-wordlists.md` §16.5** — Always-on HTTP checks (run these first; CMS-specific paths are additional)
- **`probes-and-wordlists.md` §16.9** — JS guess-paths (add `/dist/main-*.js` for Craft CMS Vite builds)
- **`secret-patterns.md`** — Sentry DSN (pattern 44) found in CMS JS bundles
- **`hunt-source-leak` skill** — Source maps, `.env` exposure, `.git` exposure (all CMS types)
- **`hunt-cloud-misconfig` skill** — S3 bucket exploitation after discovery
