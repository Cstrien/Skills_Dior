# WP All Import v4.1.1 Audit (100K installs)

**Date:** 2026-08-15
**Result:** No unauthenticated or subscriber-level vulnerabilities found.

## Plugin Architecture

### AJAX Handler Auto-Registration (Glob Pattern)

WP All Import uses a **file-name-based auto-registration** pattern for WordPress actions:

```php
// plugin.php:289-300
if (is_dir(self::ROOT_DIR . '/actions')) foreach (PMXI_Helper::safe_glob(self::ROOT_DIR . '/actions/*.php', PMXI_Helper::GLOB_RECURSE | PMXI_Helper::GLOB_PATH) as $filePath) {
    require_once $filePath;
    $function = $actionName = basename($filePath, '.php');
    // ... priority parsing ...
    add_action($actionName, self::PREFIX . str_replace('-', '_', $function), $priority, 99);
}
```

**Key characteristics:**
- Every `.php` file in `/actions/` is auto-registered as a WordPress action
- The **filename IS the action name** (e.g., `wp_ajax_test_images.php` → action `wp_ajax_test_images`, function `pmxi_wp_ajax_test_images`)
- The function prefix (`pmxi_`) comes from `self::PREFIX`
- `wp_ajax_*` files become `wp_ajax` actions (authenticated); no `wp_ajax_nopriv_*` files exist

**Audit approach for this pattern:**
1. `find /actions/ -name "wp_ajax_*" -o -name "wp_ajax_nopriv_*"` to enumerate all AJAX handlers
2. Read each file — the function body is the handler logic
3. No `wp_ajax_nopriv_*` files = zero unauthenticated AJAX surface

### Capability System

```php
// plugin.php:125
public static $capabilities = 'setup_network';  // default

// plugin.php:249-251
if (defined('WPAI_WPAE_ALLOW_INSECURE_MULTISITE') && 1 === WPAI_WPAE_ALLOW_INSECURE_MULTISITE) {
    self::$capabilities = 'manage_options';
}
```

All capability checks use `PMXI_Plugin::$capabilities`. Default is `setup_network` (super admin equivalent on multisite, admin on single site). Both `setup_network` and `manage_options` are admin-level.

### Controller Auth Gate

```php
// controllers/controller.php:68
if (!get_current_user_id() or !current_user_can(PMXI_Plugin::$capabilities)) {
    die('Security check');
}

// plugin.php:630 (admin dispatcher)
if (!get_current_user_id() or !current_user_can(self::$capabilities)) {
    die('Security check');
}
```

Every controller method (including AJAX-dispatched ones) goes through this gate.

## Findings by Category

### 1. AJAX Handlers — ALL PROPERLY PROTECTED

8 AJAX handler files in `/actions/`, all with both `check_ajax_referer('wp_all_import_secure', 'security', false)` AND `current_user_can(PMXI_Plugin::$capabilities)`:

| File | Nonce Check | Cap Check |
|------|-------------|-----------|
| `wp_ajax_auto_detect_cf.php` | Line 5 | Line 9 |
| `wp_ajax_auto_detect_sf.php` | Line 5 | Line 9 |
| `wp_ajax_delete_import.php` | Line 5 | Line 9 |
| `wp_ajax_dismiss_notifications.php` | Line 5 | Line 9 |
| `wp_ajax_import_failed.php` | Line 5 | Line 9 |
| `wp_ajax_test_images.php` | Line 6 | Line 10 |
| `wp_ajax_wpai_dismiss_review_modal.php` | Line 6 | Line 10 |
| `wp_ajax_wpai_send_feedback.php` | Line 6 | Line 10 |

Settings controller AJAX methods (`settings.php:389,400,411,422,433,471`) also have nonce checks.
Import controller methods (`import.php:567,762,873,1018,1153,1300,2685`) also have nonce checks.
**Zero `wp_ajax_nopriv_` registrations.**

### 2. PHP Object Injection — NOT EXPLOITABLE

**Custom safe unserializer:**
```php
// helpers/functions.php:549-558
function pmxi_maybe_unserialize($value) {
    if (is_serialized($value)) {
        $value = @unserialize(trim($value), ['allowed_classes' => false]);  // SAFE
    }
    return $value;
}
```

**Unsafe unserialize call (NOT exploitable):**
```php
// classes/handler.php:81
$session_clear = \maybe_unserialize(base64_decode($session));
```
- Uses WP core `maybe_unserialize()` which calls `@unserialize(trim($data))` WITHOUT `allowed_classes => false`
- BUT: session data is written by `save_data()` → `base64_encode(serialize($this->_data))` — the plugin itself, not user input
- `_import_id` comes from `$_GET['id']` (defaults to 'new') — controls which option key is read, but cannot inject serialized data
- An attacker would need write access to `wp_options` table to exploit this

**Updater (authenticated, MITM vector):**
```php
// addon-api/classes/updater.php:372,376
$request->banners = maybe_unserialize($request->banners);  // from remote API response
$request->sections = maybe_unserialize($request->sections);
```
- Data comes from addon update API response, not direct user input
- Requires MITM on the update API endpoint

### 3. SSRF — AUTHENTICATED ONLY (admin-level)

**Protected path (`get_file_curl`):**
```php
// helpers/get_file_curl.php:8
if (!preg_match('%^(http|ftp)s?://%i', $url) || pmxi_is_private_ip($url)) {
    return false;
}
```
- `pmxi_is_private_ip()` checks: 10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x
- Also checks redirect target: `pmxi_is_private_ip($finalUrl)` at line 146

**Bypassed path (`wp_all_import_get_url`):**
```php
// helpers/wp_all_import_get_url.php:30
$file = @fopen($filePath, "rb");  // PHP fopen wrapper — no pmxi_is_private_ip check
```
- `fopen()` with URL wrapper reads from any URL including internal IPs
- Caller (`upload.php:292`) validates `preg_match('%^https?://%i')` — ensures http(s) scheme but not IP range
- Entire flow requires `manage_options`/`setup_network` capability — authenticated only

**`wp_all_import_get_feed_type` (no SSRF protection):**
```php
// helpers/wp_all_import_get_feed_type.php:19
$headers = @get_headers($url, 1);  // no pmxi_is_private_ip check
```
- Also uses `wp_remote_get($url)` as fallback — also no IP restriction
- Same admin-gated import flow

**`test_images` AJAX handler (authenticated SSRF):**
```php
// actions/wp_ajax_test_images.php:147
@file_get_contents($img, false, $get_ctx)  // fallback bypasses pmxi_is_private_ip
```
- Has nonce + cap checks, so authenticated only
- `get_file_curl($url, $image_filepath)` at line 143 IS protected by `pmxi_is_private_ip()`
- The `file_get_contents` fallback at line 147 is NOT protected

### 4. SQLi — NOT EXPLOITABLE

- All AJAX handlers use `$wpdb->prepare()` for user input
- `buildWhere()` (`models/model.php:124-150`) uses `$wpdb->prepare()` with `%s` placeholders
- `models/import/record.php:2199`: Direct string interpolation `"$slug"` in SQL, but `$slug` is from `intval()` — not user-controllable
- `classes/handler.php:179`: `$wpdb->query("DELETE FROM $wpdb->options WHERE option_name IN ('$option_names')")` — values come from DB option names
- `plugin.php:1019`: `$wpdb->get_results("SELECT * FROM information_schema.user_privileges WHERE grantee LIKE \"'" . DB_USER . "'%\"")` — `DB_USER` is a constant from `wp-config.php`

### 5. File Upload — PROPERLY PROTECTED

- Upload handler (`settings.php:471`) has nonce check, `sanitize_file_name()`, extension whitelist
- ZIP extraction deletes PHP files (`upload.php:75-77`): `if (preg_match('%\W(php)$%i', ...)) wp_delete_file(...)`
- ZIP extraction uses whitelist restrictions: `WPAI_PCLZIP_OPT_EXTRACT_WHITELIST_RESTRICTIONS`
- `PMXI_Download` class uses `readfile()` but paths are constructed internally

### 6. Settings Change — PROTECTED

```php
// actions/wp_ajax_dismiss_notifications.php:14
update_option(sanitize_key($_POST['addon']) . '_notice_ignore', 'true', false);
```
- Has nonce + cap checks
- `sanitize_key()` limits option name to `[a-z0-9_-]`

### 7. LFI/RFI — NOT PRESENT

All `include_once` calls use hardcoded paths: `PMXI_Plugin::ROOT_DIR.'/libraries/...'`

## Patterns to Recognize as Safe

### Custom `maybe_unserialize` with `allowed_classes => false`

When a plugin defines its own `maybe_unserialize` wrapper that passes `['allowed_classes' => false]` to `unserialize()`, treat ALL calls to that wrapper as SAFE for PHP Object Injection. This is a strong security practice.

```php
// Safe pattern (plugin's own wrapper)
function pmxi_maybe_unserialize($value) {
    if (is_serialized($value)) {
        $value = @unserialize(trim($value), ['allowed_classes' => false]);
    }
    return $value;
}
```

Search for custom wrappers: `grep -rn "allowed_classes.*false" <plugin_path>`. If found, verify which unserialize calls use the wrapper vs. direct `unserialize()` or WP core `maybe_unserialize()`.

### `pmxi_is_private_ip()` SSRF Protection Pattern

Import plugins that fetch URLs should implement SSRF protection. Check for:
1. A custom IP range checker function
2. Whether ALL URL-fetching paths use it (fopen, file_get_contents, get_headers, wp_remote_get)
3. Whether the check also covers redirect targets (`CURLINFO_EFFECTIVE_URL`)

```php
// Good: checks both initial URL and redirect target
if (pmxi_is_private_ip($url)) return false;
// ... curl follows redirect ...
$finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
if (pmxi_is_private_ip($finalUrl)) return false;
```

**Common bypass:** `fopen($url)` and `file_get_contents($url)` with stream context bypass the IP check entirely. These are often used as fallbacks when curl/wp_remote_get fails. Check if fallback paths have the same protection.

## Conclusion

WP All Import v4.1.1 is well-secured against unauthenticated attacks:
- All AJAX handlers have nonce + capability checks
- Custom `pmxi_maybe_unserialize` uses `allowed_classes => false`
- SSRF protection via `pmxi_is_private_ip()` (authenticated only, with `fopen` bypass)
- All SQL uses `$wpdb->prepare()` or `intval()` on user input
- Controller base class gates all methods with capability checks
- File upload validates extensions, ZIP extraction blocks PHP files

No Patchstack-reportable vulnerabilities.
