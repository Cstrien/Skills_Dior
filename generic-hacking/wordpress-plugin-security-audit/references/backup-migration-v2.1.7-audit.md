# Backup Migration (backup-backup) v2.1.7 — Audit

**Plugin:** Backup Migration (slug: `backup-backup`) v2.1.7 (80k+ installs)
**Date:** August 2026
**Outcome:** No Patchstack-submittable unauthenticated vulnerabilities found.
Plugin is significantly hardened; all nopriv handlers use M2M secret key auth.

## Plugin Architecture

Large plugin (~200 PHP files). Key files for security audit:

| File | Role |
|------|------|
| `includes/offline.php` | Registers nopriv AJAX handlers, M2M auth verification |
| `includes/ajax_offline.php` | Nopriv AJAX handler logic (cloud upload processing) |
| `includes/ajax.php` (6265 lines) | Main authenticated AJAX handler (nonce-gated) |
| `includes/initializer.php` | Hooks `handle_downloading` on `wp_loaded` (all visitors) |
| `includes/backup-process.php` | Backup heart/heartbeat — curl-based batch processing |
| `includes/htaccess/.autologin.php` | MU-plugin template for staging passwordless login |
| `includes/staging/controller.php` | Staging site creation, copies autologin script |
| `includes/uploader/chunks.php` | Chunked file upload handler (nonce-gated) |
| `includes/config_v2.php` | Config storage in WP options, generates REQUEST:SECRET |
| `includes/check/system_info.php` | System info array — includes `cron_sk` (the M2M SK) |

## Nopriv Attack Surface

Only two `wp_ajax_nopriv` hooks exist (both in `offline.php`):

```php
add_action('wp_ajax_nopriv_bmip_keepalive', [&$this, 'initializeOfflineAjax']);
add_action('wp_ajax_nopriv_bmip_auth_handshake', [&$this, 'bmip_handle_handshake_request']);
```

No REST API routes registered. No other unauthenticated entry points.

### `bmip_keepalive` → `initializeOfflineAjax()`

**Auth:** Dual-track — either admin nonce OR M2M SK via `verify_ping_server_request()`.

```php
$is_admin = current_user_can('manage_options') && check_ajax_referer('backup-migration-ajax', 'nonce', false);
$is_ping_server = $this->verify_ping_server_request();
if (!$is_admin && !$is_ping_server) {
    wp_send_json_error('Unauthorized access', 403);
    return;
}
```

M2M verification (`offline.php:136-161`):
- Requires `Content-Type: application/json`
- Reads `php://input`, JSON-decodes, extracts `sk` field
- Compares against `get_option('bmi_sk_keepalive')` via `hash_equals()` (timing-safe)
- SK is 32-char `wp_generate_password(32, false)`, shared only with `backupbliss.com` ping server

**What it does:** Triggers `keepAliveUnAuthorizedRefresh()` → processes pending cloud
backup uploads (BackupBliss, Dropbox, GDrive, FTP, S3, Wasabi). Returns only
`{'status': 'success'}` or `{'status': 'no_tasks'}`.

**Sensitive data:** None exposed. Comment in code: "DO NOT RESPONSE WITH ANY
SENSITIVE DATA, ONLY SUCCESS OR FAIL".

**Assessment:** Not exploitable. SK is not exposed to unauthenticated users.

### `bmip_auth_handshake` → `bmip_handle_handshake_request()`

**Auth:** Requires `$_POST['sk']` matching `bmi_sk_keepalive` via `hash_equals()`.

```php
if (!empty($stored_sk) && !empty($incoming_sk) && hash_equals($stored_sk, $incoming_sk)) {
    header('Content-Type: text/plain');
    echo esc_html($challenge);  // echoes back the challenge param
    exit;
}
```

**Assessment:** Challenge-response handshake. No auth bypass, no password
extraction. Not exploitable without the SK.

## Backup Download (`handle_downloading` on `wp_loaded`)

Hooked on `wp_loaded` — runs for ALL visitors, unauthenticated included.
Requires `?backup-migration={type}&bmi-id={id}&sk={secret_key}`.

**Auth gate (`initializer.php:1311-1316`):**
```php
$is_valid_secret = ($secret_key === Dashboard\bmi_get_config('REQUEST:SECRET')) && $get_bmi === 'CURL_BACKUP';
$is_valid_nonce = wp_verify_nonce($secret_key, 'bmi_download_nonce');
$is_valid_token = ($secret_key === get_transient('bmi_download_token'));
```

- `REQUEST:SECRET`: 16-char random string in WP options, used only for CURL_BACKUP type
- `bmi_download_nonce`: WP nonce, created via `wp_create_nonce('bmi_download_nonce')` in admin dashboard only
- `bmi_download_token`: 32-char transient, rendered in admin dashboard DOM (`translations.php:351`)

All three are admin-only. No unauthenticated path to obtain any of them.

**BMI_BACKUP type** also checks: `STORAGE::DIRECT::URL === 'true' || current_user_can('administrator')`.
If DIRECT::URL is enabled (admin choice, default false), the `.htaccess` protecting
the backups directory is deleted — but the sk is still required.

**Assessment:** Not accessible without admin credentials.

## Backup Trigger Without Auth

- `handle_cron_backup()` is triggered by WP-Cron, not user requests
- `prepareAndMakeBackup()` is only via `wp_ajax_backup_migration` (nonce-gated)
- `bmip_keepalive` triggers cloud upload processing, NOT backup creation
- **Backup creation cannot be triggered by unauthenticated users.**

## Autologin Script (`htaccess/.autologin.php`)

MU-plugin template copied to staging sites for passwordless admin login.

**IP spoofing:** `getIpAddress()` trusts `HTTP_CLIENT_IP` and `HTTP_X_FORWARDED_FOR`.
The autologin checks `$ip != $this->userIP`, but the stored IP also comes from the
same spoofable function. An attacker controlling X-Forwarded-For could match.

**However:** Also requires `$_GET['secret']` (24-char random) matching
`$this->secretPassword` and `$_GET['user']` matching user ID. These are only
returned via `prepareLogin()` which is behind nonce auth. File self-destructs
after use (`unlink(__FILE__)`).

**Assessment:** Not exploitable without knowing the secret password.

## Dangerous Function Audit Summary

| Pattern | Count | Unauthenticated? | Notes |
|---------|-------|-------------------|-------|
| `unserialize()` | 33 | No | All on WP options, internal files, or backup contents. `maybe_unserialize` used. |
| `file_put_contents()` | 50 | No | All behind nonce auth. `chunks.php` is nonce-gated via `ajax.php:75`. |
| `exec()` | 5 | No | All in `ajax.php`, behind nonce. Backup name is server-generated. User inputs use `escapeshellarg()`. |
| `curl_exec()` | 11 | No | `downloadFile()` uses user URL but behind nonce. `backup-process.php` curls own site URL. |
| `$wpdb->query` | ~30 | No | Restore SQL from backup files (not user input). Search-replace uses `repository->escape()`. |
| `wp_ajax_nopriv` | 2 | Yes, but authed | Both require M2M SK via `hash_equals()`. |

## Key Security Patterns (Reusable)

### M2M Secret Key Authentication Pattern
The plugin uses a machine-to-machine auth model for its nopriv handlers:
1. Generate SK: `wp_generate_password(32, false)` → `update_option('bmi_sk_keepalive', $sk)`
2. Share SK with external ping server via `wp_remote_post()` to `backupbliss.com`
3. Verify: `hash_equals($stored_sk, $request_sk)` on incoming nopriv requests
4. SK is NOT exposed in any frontend-facing page or AJAX response

**When auditing:** If a nopriv handler uses `hash_equals()` against an option
that's never rendered to unauthenticated users, it's properly authenticated.
Check `system_info` / debug endpoints for SK leakage (this plugin exposes it
in `getSiteData()` but that's admin-only via nonce).

### `sanitize()` Custom Wrapper Pattern
`BMP::sanitize()` recursively applies `sanitize_text_field()` to all keys and
values. This strips tags and whitespace but does NOT escape SQL. Functions
relying solely on `sanitize()` for SQL safety are vulnerable — but in this
plugin, SQL operations use `escapeSQLIDentifier()` or `$wpdb->prepare()`.

### Config-as-PHP-Comment Pattern
Settings stored as `<?php //{json}` in `.php` files (e.g.,
`currentBackupConfig.php`, staging configs). Read via
`file_get_contents()` + `substr($content, 8)` + `json_decode()`. This
prevents direct web access from returning data (PHP exits on the comment).
**Not a vulnerability** but worth noting when tracing data flow.
