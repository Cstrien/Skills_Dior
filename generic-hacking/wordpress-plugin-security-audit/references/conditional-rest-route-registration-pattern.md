# Conditional REST Route Registration — Permission Callback Red Herring

When `register_rest_route` is called inside a `rest_api_init` hook that is
gated by a capability check, `permission_callback => '__return_true'` is a
**red herring** — the route is never registered for unauthenticated users.

## The Pattern

```php
add_action('rest_api_init', function () {
    if (current_user_can('manage_options')) {  // ← per-request gate
        register_rest_route('v1', '/fm/backup/...', array(
            'methods' => 'GET',
            'callback' => 'fm_download_backup',
            'permission_callback' => '__return_true',  // ← looks vulnerable!
        ));
    }
});
```

## Why It's Not Exploitable Unauthenticated

WordPress `rest_api_init` fires fresh on **every** REST API request. The
closure runs during that request's bootstrap. For an unauthenticated request:

1. `rest_api_init` fires → plugin's closure executes
2. `current_user_can('manage_options')` → `false` (no auth cookies)
3. `register_rest_route()` is **never called** → route not in the route table
4. REST API dispatcher finds no matching route → **404 response**

The `permission_callback => '__return_true'` never executes because the route
doesn't exist for that request. This is fundamentally different from a route
registered unconditionally with `__return_true`, where the permission callback
runs and always returns `true`.

## Detection

```bash
# Find register_rest_route calls, then check if they're inside a conditional
grep -n 'register_rest_route\|current_user_can\|is_admin\|if.*user_can' --include="*.php" <plugin_path>
```

Key patterns to check:
- `register_rest_route` inside `if (current_user_can(...))` → conditional registration
- `register_rest_route` inside `if (is_admin())` → admin-only registration (same effect)
- `register_rest_route` at top level with `__return_true` → genuinely vulnerable

**Critical:** Always read the **surrounding context** of `register_rest_route`.
A bare grep for `permission_callback.*__return_true` will produce false positives
when the registration is conditionally gated.

## Secondary Defense: Static Key Validation

Some plugins add a second layer: the callback validates a static key that is
only exposed to authenticated admins. Example from WP File Manager v8.0.4:

```php
// Key = base64(site_url() . get_option('fm_key'))
// fm_key is a 25-char random string stored in wp_options
// Only exposed in admin-only HTML (data-token attribute behind is_admin())
if (base64_encode(site_url() . $fmkey) === $params['key']) {
    // ... download backup file ...
}
```

Even if route registration were unconditional, this key check would block
unauthenticated access because `fm_key` is never exposed to unauthenticated
users (not via `wp_localize_script`, REST API, shortcode, or public page).

**Audit check:** When a callback has a custom key/token validation, trace where
the key is stored and whether it's exposed to unauthenticated users:
```bash
grep -rn "wp_localize_script\|wp_create_nonce\|get_option.*key\|data-token" --include="*.php" --include="*.js" <plugin_path>
```

## Worked Example: WP File Manager v8.0.4 (1M+ installs)

**Plugin:** WP File Manager v8.0.4 (`file_folder_manager.php`)
**Routes:** `/v1/fm/backup/<id>/<type>/<key>` and `/v1/fm/backupall/...`
**Result:** NOT exploitable unauthenticated (two independent defense layers)

### Layer 1: Conditional Registration (`file_folder_manager.php:53-67`)
Route registration wrapped in `if(current_user_can('manage_options'))` inside
`rest_api_init` hook. Unauthenticated REST requests → routes not registered → 404.

### Layer 2: Static Key Validation (`file_folder_manager.php:1380`)
Callback validates `base64_encode(site_url().$fmkey) === $params['key']`.
`fm_key` (25-char random) only exposed in `inc/backup.php:230` as a `data-token`
HTML attribute, which is behind `is_admin()` (line 815).

### Path Traversal in `type` Parameter (moot)
```php
// file_folder_manager.php:1391-1393
$directory_separators = ['../', './','..\\', '.\\\\', '..'];
$type = str_replace($directory_separators, '', $type);
$bkpName = $backup.'-'.$type.'.zip';
```
Blacklist filter is bypassable (`....//` → `..`), but blocked by the key gate.
Would be exploitable only if the key were leaked (e.g., via a separate info
disclosure vulnerability exposing `wp_options` contents).

### All AJAX Handlers: Authenticated Only
All 10 AJAX handlers registered with `wp_ajax_*` only — no `wp_ajax_nopriv_*`.
Three handlers (`mk_fm_close_fm_help`, `mk_filemanager_verify_email`,
`verify_filemanager_email`) lack capability checks but are still
authenticated-only. Low-severity authenticated BAC, not Patchstack-qualifying.

### No Nonce/Key Exposure to Unauthenticated Users
All `wp_localize_script` and `wp_create_nonce` calls are behind
`admin_enqueue_scripts` or `is_admin()` checks. No front-end shortcode or
`wp_enqueue_scripts` hooks exist in the free version.

## Methodology Update

Add this check to Phase 2 (REST API route audit) of the audit workflow:

**Before** analyzing a `__return_true` REST callback, verify the route
registration is **unconditional**:
1. Read the lines **above** `register_rest_route` in the same hook closure
2. Check for `if (current_user_can(...))`, `if (is_admin())`, `if (!is_user_logged_in())`
3. If conditionally gated → the route is not registered for unauth users → skip
4. If unconditionally registered → proceed with callback analysis as normal

This prevents wasted time tracing callbacks that are unreachable unauthenticated.

## Sibling Pattern: Registrar Wrapper with requires_admin Semantics (2026-09-17, wb4wp)

Inline `current_user_can()` gates are one variant. The second major variant is a
**registrar wrapper class** with per-route admin flags:

```php
// Wrapper (class-api-manager.php) — the gate lives in register_route(), NOT in the route arrays:
private function register_route( array $route ) {
    $is_admin = current_user_can( 'administrator' );
    if ( ! $is_admin && $requires_admin ) {
        return;   // ← route registration SKIPPED for anon → 404 rest_no_route
    }
    $arguments = array(
        ...
        self::ROUTE_PERMISSION_CALLBACK => function () use ( $no_cache_response ) {
            if ( $no_cache_response ) { nocache_headers(); }
            return true;   // ← wrapper DEFAULT: always-true permission
        },
    );
    if ( array_key_exists( self::ROUTE_PERMISSION_CALLBACK, $route ) ) {
        $arguments[ self::ROUTE_PERMISSION_CALLBACK ] = $route[ self::ROUTE_PERMISSION_CALLBACK ];
    }
    register_rest_route( self::API_NAMESPACE, $path, $arguments );
}
```

Rules:
- Wrapper default permission `return true` → every route WITHOUT an explicit
  permission key is public **when it gets registered**.
- The explicit `requires_admin=false` key is the ONLY thing that makes those
  routes registered for anon. Routes without the key default admin=true →
  never registered for anon → `rest_no_route` 404 → NOT findings, no matter how
  dangerous the handler (leak options, SSO JWT, publish pages).
- Read route arrays alone → wrong route list in BOTH directions. Audit the
  wrapper's defaults + flag semantics, then live-verify on an installed lab copy:
  `GET /wp-json/` shows exactly what the current (anon) request can see.

**Worked example (wb4wp / Bluehost Website Builder v1.0-2781, exact production zip
from `wp-versions.builderservices.io/content/bluehost-version.json`):** confirmed
live-unauth (requires_admin=false + no perm cb): `POST /save_site` (overwrites the
whole site model, writes attacker data into `wp_options.wb4wp_api_keys`, removes
`wp_filter_post_kses` so arbitrary HTML enters post_content, `file_put_contents`
JSON to uploads), `GET /wp_posts` (full post content leak), `GET /wc_products`,
`POST /posts/{id}/publish_autosave`, `POST /posts/{id}/discard_autosave`,
`POST /disable-plugin`. Look-alike routes without the false flag (`/drafts`,
`/description`, `/sso`, `/provision`, `/publish`, `/plugin-state`) → 404 for anon.
First-pass source read that assumed "no explicit admin flag = registered for
everyone" was wrong; the lab run corrected the list. See also
`wp-plugin-lab-validation.md` for the vendor-zip → lab pipeline and
`scripts/audit_rest_routes.php` for the layer-1 scanner. The full 3-request
exploit chain built on these routes (published-page overwrite → unauth
publish_autosave → stored XSS rendered to every visitor) is documented in
`references/wb4wp-v1.0-2781-full-chain.md`.
