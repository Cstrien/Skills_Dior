# Download Manager v3.3.67 — Full Audit (100K installs)

**Plugin:** download-manager v3.3.67, ~100,000 installs
**Audit date:** 2026-08-15
**Result: No Patchstack-accepted vulnerabilities found.**

## Plugin Architecture

- Main file: `download-manager.php` — defines constants (NONCE_KEY, WPDM_PUB_NONCE,
  WPDM_PRI_NONCE, WPDMAM_NONCE_KEY, WPDM_ENC_KEY), registers post type `wpdmpro`
- Core classes in `src/` namespace `WPDM\`
- Custom encryption via `Crypt` class (OpenSSL AES-128-CBC / Sodium / PHP fallback)
- Custom query var system: `wpdm_query_var()` → `__::query_var()` → `__::sanitize_var()`
- File operations centralized in `FileSystem::downloadFile()` and `FileSystem::absPath()`

## Nopriv Handler Inventory (6 total)

| # | Action | File:Line | Nonce | Cap | Impact |
|---|--------|-----------|-------|-----|--------|
| 1 | `showLockOptions` | Apply.php:493 | NO | NO | Returns download link HTML (id cast to int) |
| 2 | `wpdm_verify_file_pass` | Apply.php:377 | NO | NO | Returns expirable download link if password matches |
| 3 | `wpdm_media_pass` | MediaAccessControl.php:53 | YES (NONCE_KEY) | NO | Returns media download key if password matches |
| 4 | `wpdm_get_profile_menu_content` | PublicProfile.php:38 | NO | NO | call_user_func dispatch to pre-registered callbacks |
| 5 | `updatePassword` | Login.php:258 | YES (user-specific) | NO | Password reset via check_password_reset_key |
| 6 | `resetPassword` | Login.php:219 | NO | NO | Sends password reset email (60s rate limit) |

## Key Security Patterns Verified

### 1. Encrypted Path Containment (AssetManager::root())

AssetManager encrypts all file paths with `Crypt::encrypt()` and decrypts on use.
The `root()` method provides the containment check:

```php
// AssetManager.php:38-66
$userRootExt = preg_replace(array('/\.\.\//', '/\.\//', '/\/\.\.$/'), "", $userRootExt);
$realUserRootExt = realpath($userRootExt);
if(substr_count($userRootExt, $userRoot) == 0 || !$realUserRootExt ||
   substr_count($realUserRootExt, $userRoot) === 0) return "[INVALID_PATH]";
```

**Pattern:** Download-manager plugins that encrypt path parameters are harder to
audit because you can't just send `../../../etc/passwd` — the path must decrypt
correctly first. The containment check uses `realpath()` + prefix match. This is
correct but depends on the encryption key being secret (stored in `wp_options`
as `__wpdm_enc_key` or defined in `wp-config.php`).

**Audit approach:** Don't try to forge encrypted paths. Instead:
1. Find handlers that accept paths WITHOUT encryption (e.g., `FileSystem::absPath()`
   accepts raw relative paths from post meta)
2. Check if post meta (`__wpdm_files`) can be controlled by subscribers
3. Look for paths that bypass the `root()` containment (e.g., direct `$_GET['file']`)

### 2. Custom Sanitization Chain (wpdm_query_var → sanitize_var)

The plugin's custom sanitization system has a critical weakness:

```php
// __.php:320-322
case 'escs':
    $value = wpdm_escs($value);
    // wpdm_escs = preg_replace('#<script(.*?)>(.*?)</script>#is', '', $html)
    // ONLY strips <script> tags — does NOT escape SQL, HTML, or path traversal

// __.php:348-349 (default case, when no validate type specified)
default:
    $value = esc_sql(esc_attr($value));
```

**Critical finding:** When `wpdm_query_var('term')` is called WITHOUT a validation
type (as in Stats.php:42), it falls through to the default case which does
`esc_sql(esc_attr($value))`. While `esc_sql` escapes quotes for SQL, this is NOT
the same as `$wpdb->prepare()` and is considered insufficient by WordPress
coding standards. However, for Patchstack purposes, `esc_sql` does prevent
SQL injection in simple string interpolation contexts.

**The `escs` type is dangerous if used for SQL contexts** — it only strips
`<script>` tags and provides zero SQL escaping. In download-manager, `escs`
is used for `filepass` in `checkFilePassword()` but the password value is
only compared with `==`, never used in SQL, so it's safe there.

### 3. call_user_func Dispatch (PublicProfile::menuContent)

```php
// PublicProfile.php:38-41
function menuContent(){
    call_user_func($this->profile_menu[wpdm_query_var('__pmenu')]['content']);
    die();
}
```

No nonce, no auth. Uses `call_user_func` with user-controlled key into
`$this->profile_menu` array. **Not exploitable** because:
- The array only contains pre-registered callbacks (`downloads`, `favourites`)
- User can only select WHICH registered callback runs, not inject arbitrary functions
- `apply_filters("wpdm_user_profile_menu", ...)` could theoretically add callbacks
  from other plugins, but that requires plugin code, not user input

**Pattern:** `call_user_func` with user-controlled ARRAY KEY (not function name)
is safe if the array is server-controlled. Only dangerous if user controls the
function name string directly.

### 4. FileSystem::downloadFile() Path Traversal Check

```php
// FileSystem.php:44
if (substr_count($filepath, "../") > 0) {
    Messages::error("Please, no funny business, however, good try though!", 1);
}
```

Simple `../` check. Does NOT check for:
- URL-encoded `..%2F` (but PHP decodes this before reaching the function)
- Null bytes (PHP 5.3.4+ is immune)
- Symlinks (but `realpath()` is called in `absPath()` before this)

**Pattern:** A simple `../` string check in `downloadFile()` is a defense-in-depth
layer but should NOT be the only check. The real protection comes from
`absPath()` which uses `realpath()` + upload dir containment.

### 5. Raw SQL Without prepare() (All Admin-Only)

Found ~20 `$wpdb->query/get_results/get_var` calls without `prepare()`:
- `Stats.php:45,66` — `$term` from `wpdm_query_var('term')` (default sanitize =
  `esc_sql(esc_attr())`), behind `manage_options` + nonce
- `wpdm-functions.php:819-825` — `$uid`/`$pid` interpolated, called from
  `wpdm_total_downloads()` (admin dashboard widget only)
- `Asset.php:52,279` — `$path_or_id` interpolated, called from admin AJAX only
- `PackageController.php:1018` — `$ID` is from `(int)` cast, safe

**None reachable from nopriv handlers.** All behind `manage_options` capability.

### 6. checkFilePassword Loose Comparison

```php
// Apply.php:389
if ($filepass !== '' && $password == $filepass ||
    substr_count($password, "[{$filepass}]") > 0)
```

Uses loose `==` comparison. Could theoretically be bypassed with type juggling
if `$password` is stored as a non-string type, but `get_post_meta()` returns
strings for stored string values. The `[$filepass]` pattern allows multi-password
lists (e.g., password stored as `[pass1][pass2]`). Not exploitable.

## Audit Checklist for Download-Manager-Style Plugins

1. **Find ALL `wp_ajax_nopriv_` registrations** — grep for the pattern
2. **Trace each callback** — check for nonce, capability, and dangerous sinks
3. **Check `FileSystem::downloadFile()` callers** — verify path source and
   `../` check effectiveness
4. **Check `FileSystem::absPath()` callers** — verify `realpath()` containment
5. **Check `Crypt::decrypt()` usage** — encrypted paths are containment, not
   a barrier; find handlers that accept raw (non-encrypted) paths
6. **Check `wpdm_query_var()` without validation type** — defaults to
   `esc_sql(esc_attr())`, not `prepare()`
7. **Check `escs` sanitization type** — only strips `<script>`, NOT SQL-safe
8. **Check `call_user_func` with array key dispatch** — safe if array is
   server-controlled
9. **Trace `$_FILES` handling** — upload handlers are admin-only in this plugin
10. **Check `update_option()` in nopriv handlers** — none found without
    capability checks

## Version Info

- Plugin version: 3.3.67
- PHP requirement: 7.2+ (uses random_bytes, sodium functions)
- Download: Already at /var/www/html/wordpress/wp-content/plugins/download-manager/
