# Ultimate Member v2.12.1 — Nopriv AJAX Audit (200K installs)

**Plugin:** ultimate-member v2.12.1, ~200,000 installs, 9 prior CVEs
**Audit date:** 2026-08-15
**Result:** No Patchstack-accepted vulnerabilities found. One notable nonce-bypass pattern documented.

## Nopriv Handler Inventory

| Handler | File:Line | Nonce Check | Permission Check | Verdict |
|---------|-----------|-------------|------------------|---------|
| `um_fileupload` | class-files.php:660 | **Bypassed for anon** | Form/field validation | Nonce bypass, but no RCE (MIME-validated) |
| `um_imageupload` | class-files.php:458 | **Bypassed for anon** | Form/field validation | Nonce bypass, but no RCE (MIME-validated) |
| `um_resize_image` | class-files.php:319 | `check_ajax_nonce()` | Permission checks | Protected |
| `um_remove_file` | class-files.php:266 | `check_ajax_nonce()` | Temp file only | Protected |
| `um_get_members` | class-member-directory.php:2978 | `check_ajax_nonce()` | Directory visibility | Protected |
| `um_select_options` | class-form.php:116 | `check_ajax_nonce()` | Callback whitelist | Protected |
| `um_ajax_paginate_posts` | class-user-posts.php:105 | `check_ajax_nonce()` | Public posts only | Protected |
| `um_ajax_paginate_comments` | class-user-posts.php:157 | `check_ajax_nonce()` | Public comments only | Protected |
| `um_search_widget_request` | class-pages.php:108 | `check_ajax_referer()` | Public search | Protected |

## Key Finding: `&& is_user_logged_in()` Nonce Bypass Pattern

### The Bug

Both `ajax_file_upload()` and `ajax_image_upload()` register as `wp_ajax_nopriv_*` but gate nonce verification behind `is_user_logged_in()`:

```php
// class-files.php line ~691 (ajax_file_upload) and ~519 (ajax_image_upload)
$um_file_upload_nonce = apply_filters( 'um_file_upload_nonce', true );
if ( $um_file_upload_nonce ) {
    $nonce     = sanitize_text_field( $_POST['_wpnonce'] );
    $timestamp = absint( $_POST['timestamp'] );
    if ( ! wp_verify_nonce( $nonce, 'um_upload_nonce-' . $timestamp ) && is_user_logged_in() ) {
        // This nonce is not valid.
        $ret['error'] = esc_html__( 'Invalid nonce', 'ultimate-member' );
        wp_send_json_error( $ret );
    }
}
```

The `&& is_user_logged_in()` short-circuits the entire nonce check for unauthenticated users. An anonymous user can POST with `_wpnonce=invalid` and the nonce verification block is skipped entirely.

### Why It Doesn't Lead to RCE

Despite the nonce bypass:
1. `wp_handle_upload()` validates file MIME types against the form's configured `allowed_types` (e.g., pdf, jpg, png)
2. Filenames are randomized server-side (`file_{hash}.ext` or `stream_photo_{hash}.ext`)
3. Files go to `wp-content/uploads/ultimatemember/temp/` — no user-controlled path
4. PHP extensions are not in any form's allowed_types list
5. The form must exist, be published, and have the matching field key

**Assessment:** Real auth-bypass but does NOT meet Patchstack criteria (no arbitrary file upload with full path+ext control, no RCE).

### General Pattern to Watch For

```php
// DANGEROUS: nonce check short-circuited for unauthenticated users
if ( ! wp_verify_nonce( $nonce, $action ) && is_user_logged_in() ) {
    wp_send_json_error( 'Invalid nonce' );
}
// → Anonymous users bypass nonce entirely
```

This pattern appears when developers intend "only verify nonce for logged-in users" but inadvertently register the handler as `wp_ajax_nopriv_*`. The intent is usually "unauthenticated users are allowed for registration uploads" — but the nonce was supposed to prevent CSRF, not gate authentication.

**When you see `&& is_user_logged_in()` in a nonce check inside a nopriv handler, the nonce is effectively bypassed for unauthenticated users.** Trace what the handler does after the bypass — if it performs dangerous actions (settings change, arbitrary file write, user creation), it's exploitable. If it only allows constrained operations (MIME-validated uploads to temp dir), it may not meet impact thresholds.

## Other Areas Checked (All Clean)

### Registration Privilege Escalation — Well Protected
- `um-actions-register.php:490-530`: Role from `$args['role']` validated against `get_editable_user_roles()` which excludes admin-level roles
- `class-form.php:610-656`: Additional check against `custom_field_roles` + `exclude_roles`, `wp_die()` on violation
- Registration nonce verified via `Register::verify_nonce()` with `um_register_form` action

### SQL Injection — Not Found
- `class-member-directory.php:2940`: `implode("','", $custom_fields)` in SQL — but `$custom_fields` comes from server-side form config, not user input
- All `$wpdb` queries in member directory use `$wpdb->prepare()` or operate on server-generated values
- REST API parameters don't reach raw SQL queries

### PHP Object Injection — Not Found
- All `maybe_unserialize()` calls operate on `get_post_meta()`, `get_user_meta()`, or `$directory_data` — server-side data, not user input

### Path Traversal — Protected
- `class-files.php:179-261`: Download routing uses `validate_file()` + `wp_verify_nonce()` with user-specific nonce
- `um_is_temp_upload()`: Checks for `../` and `%` in path components
- File download requires valid nonce tied to `$user_id . $form_id . 'um-download-nonce'`

### Password Reset/Change — Protected
- `um-actions-account.php`: Password change requires `current_user_password` verification via `wp_check_password()`
- Only accessible to authenticated users (not nopriv)

### BAC on User Profile — Protected
- Profile form checks `UM()->roles()->um_current_user_can('edit', $user_id)` before allowing modifications
- Password hashes never exposed through AJAX handlers

### Settings Change — Not Found
- No `update_option()` calls reachable by unauthenticated users or subscribers
- Admin AJAX handlers require `manage_options` or are registered as `wp_ajax_*` only (not nopriv)

### REST API — No Endpoints
- No `register_rest_route` calls found in the plugin

## WP Lab Activation Issues

- Plugin activation via `wp plugin activate` failed with `in_array(): Argument #2 ($haystack) must be of type array, false given` — PHP 8.4 compatibility issue in WordPress core's `activate_plugin()`
- Workaround: update `active_plugins` option directly via `wp eval` or DB query
- The plugin's `Filesystem` class also requires `FS_METHOD=direct` in `wp-config.php` to avoid FTP credentials prompt
- Could not fully activate for dynamic testing due to filesystem credentials form blocking wp-cli commands
