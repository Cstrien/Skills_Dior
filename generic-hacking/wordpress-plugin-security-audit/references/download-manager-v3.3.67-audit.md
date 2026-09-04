# Download Manager v3.3.67 — Full Audit (100K installs)

**Plugin:** download-manager v3.3.67, ~100,000 installs
**Audit date:** 2026-08-15 (REST API audit: 2026-08-29)
**Result: No Patchstack-accepted vulnerabilities found.**

## Plugin Architecture

- Main file: `download-manager.php` — defines constants (NONCE_KEY, WPDM_PUB_NONCE,
  WPDM_PRI_NONCE, WPDMAM_NONCE_KEY, WPDM_ENC_KEY), registers post type `wpdmpro`
- Core classes in `src/` namespace `WPDM\`
- Custom encryption via `Crypt` class (OpenSSL AES-128-CBC / Sodium / PHP fallback)
- Custom query var system: `wpdm_query_var()` → `__::query_var()` → `__::sanitize_var()`
- File operations centralized in `FileSystem::downloadFile()` and `FileSystem::absPath()`

## REST API Routes (src/Package/RestAPI.php)

Three routes registered with `permission_callback => '__return_true'`:

| Route | Method | Callback | Nonce | Result |
|-------|--------|----------|-------|--------|
| `wpdm/validate-captcha` | POST | `PackageLocks::validateCaptcha` | N/A | Safe — reCAPTCHA Enterprise API verification |
| `wpdm/validate-password` | POST | `PackageLocks::validatePassword` | N/A | **Loose `==` comparison** (see below) |
| `wpdm/search` | GET | `PackageController::search` | N/A | Safe — uses WP_Query (parameterized) |

### validatePassword — Loose Comparison (PackageLocks.php:81)

```php
$password = isset($_REQUEST['password']) ? sanitize_text_field($_REQUEST['password']) : null;
$packageID = wpdm_query_var('__wpdm_ID', ['validate' => 'int']);
$passwords = WPDM()->package->isPasswordProtected($packageID); // returns string or false

// Line 81 — LOOSE comparison (!=)
if ($passwords && $password != $passwords && substr_count($passwords, "[$password]") < 1) {
    // password is WRONG
} else {
    // password accepted → returns expirable download link
}
```

**Auth check status:** NONE — `permission_callback => '__return_true'`, no nonce, no capability.
**curl PoC:** `curl -X POST "https://target.com/wp-json/wpdm/validate-password" -d "__wpdm_ID=123&password=0e1"`
**Exploitability: LOW.** Requires the stored password to be exactly `"0"` (or another
PHP type-juggling equivalent). If password is `"0"` and attacker sends `"0e1"`, PHP
evaluates `"0" != "0e1"` as `0 != 0` → `FALSE` → password accepted. On PHP 8, only
numeric-equivalent strings match (e.g., `"0" == "0e1"` is TRUE but `"0" == "abc"` is FALSE).
The bracket-format check `substr_count($passwords, "[$password]")` provides a second
comparison path but uses the same loose string semantics.

**Not Patchstack-qualifiable** because:
1. The admin must have set the password to a type-juggling-vulnerable value (e.g., `"0"`)
2. The bypass only works for that specific value, not arbitrary passwords
3. Most admins set alphanumeric passwords, not `"0"`

### validateCaptcha — Safe (PackageLocks.php:37)

Calls `wpdm_recaptcha_enterprise_verify()` which checks Google reCAPTCHA Enterprise API.
If reCAPTCHA not configured (`_wpdm_recaptcha_secret_key` empty), returns `['success' => false]`.
No bypass possible without valid reCAPTCHA token.

### search — Safe (PackageController.php:2642)

Uses `WP_Query` (parameterized, no raw SQL). Query class defaults to `post_type='wpdmpro'`,
no `post_status` override (defaults to `publish` — only published packages returned).
Response includes `ID`, `post_title`, `post_content` — all publicly visible content.
No SQLi, no auth bypass, no sensitive data exposure.

## Nopriv Handler Inventory (6 total)

| # | Action | File:Line | Nonce | Cap | Impact |
|---|--------|-----------|-------|-----|--------|
| 1 | `showLockOptions` | Apply.php:493 | NO | NO | Returns download link HTML (id cast to int) |
| 2 | `wpdm_verify_file_pass` | Apply.php:377 | NO | NO | Returns expirable download link if password matches |
| 3 | `wpdm_media_pass` | MediaAccessControl.php:53 | YES (NONCE_KEY) | NO | Returns media download key if password matches |
| 4 | `wpdm_get_profile_menu_content` | PublicProfile.php:38 | NO | NO | call_user_func dispatch to pre-registered callbacks |
| 5 | `updatePassword` | Login.php:258 | YES (user-specific) | NO | Password reset via check_password_reset_key |
| 6 | `resetPassword` | Login.php:219 | NO | NO | Sends password reset email (60s rate limit) |

### showLockOptions (Apply.php:493) — Low severity info disclosure

Nopriv, no auth. Calls `WPDM()->package->downloadLink($id, 1)` which returns HTML
UI (lock form/buttons). Does NOT expose the actual download URL for locked packages
— URL is only generated after password validation. Low severity: information
disclosure of lock configuration only.

### wpdm_verify_file_pass / checkFilePassword (Apply.php:377) — Loose comparison + no rate limit

```php
$fileid = wpdm_query_var('wpdmfileid', 'int');
$filepass = wpdm_query_var('filepass', 'escs');
$password = ...; // from post meta
if ($filepass !== '' && $password == $filepass || substr_count($password, "[{$filepass}]") > 0)
```

Same loose `==` comparison as validatePassword. Also: **no nonce check, no rate
limiting** — unauthenticated brute force on individual file passwords is possible.
Exploitability: Low-Medium. The loose comparison requires specific stored password
values. No rate limit enables brute force but passwords may be complex.

### wpdm_media_pass / makeMediaPass (MediaAccessControl.php:53) — Patched, safe

Uses `wp_verify_nonce(wpdm_query_var('__xnonce'), NONCE_KEY)` — NONCE_KEY is a
hardcoded constant but WP nonces are time-limited. Media ID is `Crypt::decrypt`-ed.
Password comparison uses strict `===` (patched): `(string)$password === (string)wpdm_query_var('__pswd')`.
Requires `$private` flag + non-empty password + exact match. NOT exploitable.

### updatePassword / resetPassword (Login.php:258, 219) — Standard WP reset flow

**updatePassword:** Requires valid `check_password_reset_key()` (from email),
user-specific nonce (`wpdm_password_reset_{$user->ID}`), blocks admin resets by
default. Sets auth cookie after reset — intended behavior. NOT a vulnerability.
**resetPassword:** Nopriv, triggers reset email, 60s session rate-limit. Key goes
to user's email. NOT a vulnerability.

### wpdm_get_profile_menu_content (PublicProfile.php:38) — Low IDOR

Nopriv, no auth. `call_user_func` only invokes registered menu callbacks (not
arbitrary functions — no RCE). The `favourites` callback uses
`wpdm_query_var('__pu', 'int')` as user ID — IDOR allowing any user's favorites
list to be viewed. `__scp` must be `Crypt::decrypt`-ed (craftable with known key,
or capturable from page). Low severity — favorites list is typically non-sensitive.

## Key Security Patterns Verified

### 1. Encrypted Path Containment (AssetManager::root())

AssetManager encrypts all file paths with `Crypt::encrypt()` and decrypts on use.
The `root()` method provides the containment check using `realpath()` + prefix match.

**Audit approach:** Don't try to forge encrypted paths. Instead:
1. Find handlers that accept paths WITHOUT encryption
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

**Critical:** When `wpdm_query_var('term')` is called WITHOUT a validation type,
it falls through to default which does `esc_sql(esc_attr($value))`. While `esc_sql`
escapes quotes for SQL, this is NOT the same as `$wpdb->prepare()`.

**The `escs` type is dangerous if used for SQL contexts** — it only strips
`<script>` tags and provides zero SQL escaping. In download-manager, `escs`
is used for `filepass` in `checkFilePassword()` but the password value is
only compared with `==`, never used in SQL, so it's safe there.

### 3. call_user_func Dispatch (PublicProfile::menuContent)

No nonce, no auth. Uses `call_user_func` with user-controlled key into
`$this->profile_menu` array. **Not exploitable** because the array only contains
pre-registered callbacks. User can only select WHICH registered callback runs,
not inject arbitrary functions.

**Pattern:** `call_user_func` with user-controlled ARRAY KEY (not function name)
is safe if the array is server-controlled.

### 4. Raw SQL Without prepare() (All Admin-Only)

Found ~20 `$wpdb->query/get_results/get_var` calls without `prepare()`.
None reachable from nopriv handlers. All behind `manage_options` capability.

### 5. SQLi Pattern: ahm_asset_links (Asset.php)

```php
// Asset.php:74 — $key pre-sanitized with esc_sql(esc_attr($key))
$asset_link = $wpdb->get_row("select * from {$wpdb->prefix}ahm_asset_links where asset_key='$key'");
// Asset.php:114 — $this->ID from database, not user input
$links = $wpdb->get_results("select * from {$wpdb->prefix}ahm_asset_links where asset_ID = '{$this->ID}'");
// Asset.php:125 — called only from getLinkDetails() with nonce + access_server_browser cap
$link = $wpdb->get_row("select * from {$wpdb->prefix}ahm_asset_links where ID = '{$ID}'");
```

All three SQL queries use string interpolation. The first is safe because
`esc_sql()` escapes quotes. The second uses `$this->ID` from DB (not user
input). The third is only called from admin AJAX with nonce + capability.
**Not exploitable from unauthenticated context.**

## Version Info

- Plugin version: 3.3.67 (confirmed latest as of 2026-08-29)
- PHP requirement: 7.2+ (uses random_bytes, sodium functions)
- Download: Already at /var/www/html/wordpress/wp-content/plugins/download-manager/
