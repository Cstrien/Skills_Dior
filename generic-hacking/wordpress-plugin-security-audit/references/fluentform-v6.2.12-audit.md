# FluentForm v6.2.12 — Nopriv & REST API Audit (700K installs)

**Plugin:** fluentform v6.2.12, ~700,000 installs, 5 existing CVEs
**Audit date:** 2026-08-15
**Result:** No new Patchstack-accepted vulnerabilities found.

## Plugin Architecture

- Uses **wpfluent framework** (custom WP framework in `vendor/wpfluent/`) — NOT standard WordPress patterns
- REST API routes defined in `app/Http/Routes/api.php` using `$router->get/post/delete()` with `withPolicy()` groups
- Policies in `app/Http/Policies/` — each checks `Acl::hasPermission()` or `Acl::verify()`
- AJAX handlers in `app/Hooks/Ajax.php` — admin handlers use `Acl::verify()`, nopriv handlers verified individually
- Form submission via `wp_ajax_nopriv_fluentform_submit` → `SubmissionHandler::submit()` → `SubmissionHandlerService::handleSubmission()`
- Background processing via `wp_ajax_nopriv_fluentform_background_process` with nonce verification
- Stripe SCA payment confirmation via nopriv AJAX with nonce + transaction status validation
- No `$_FILES` handling in core — file uploads handled by Pro addon
- No `wp_handle_upload`, `move_uploaded_file`, or direct file operations in core

## Nopriv Handler Summary

| # | Action | Callback | Nonce | Cap | Exploitable |
|---|--------|----------|-------|-----|-------------|
| 1 | `fluentform_submit` | SubmissionHandler::submit | By design (public form) | N/A | NO — inserts submission only, no state mutation |
| 2 | `fluentform_background_process` | FluentFormAsyncRequest::handleBackgroundCall | YES (wp_verify_nonce L85) | N/A | NO |
| 3 | `fluentform_generate_protection_token` | TokenBasedSpamProtection::ajaxGenerateToken | YES (wp_verify_nonce L48) | N/A | NO |
| 4 | `fluentform_sca_inline_confirm_payment` | StripeInlineProcessor::confirmScaPayment | YES (validateScaRequest L402-418) | N/A | NO |
| 5 | `fluentform_sca_inline_confirm_payment_setup_intents` | StripeInlineProcessor::confirmScaSetupIntentsPayment | YES (same validateScaRequest) | N/A | NO |
| 6 | WP_Async_Request (action-scheduler) | maybe_handle | YES (check_ajax_referer L172) | N/A | NO |

## REST API Route Protection (wpfluent framework)

All REST routes use `withPolicy('PolicyName')` either at the group level or per-route:

```php
$router->prefix('forms')->withPolicy('FormPolicy')->group(function ($router) { ... });
$router->post('form-submit', 'SubmissionHandlerController@submit')->withPolicy('SubmissionPolicy');
```

The framework's `Route::register()` (Route.php:750) always sets `permission_callback`:
```php
// Route.php:807-817
protected function getDefaultOptions() {
    return [[
        'methods' => $this->method,
        'callback' => [$this, 'callback'],
        'permission_callback' => [$this, 'permissionCallback'],  // always set
        'args' => [],
    ]];
}
```

**Pattern:** wpfluent's `withPolicy()` ensures every route has a `permission_callback`. Unlike raw `register_rest_route` calls where devs forget `permission_callback`, the framework enforces it. Check the policy class methods — they map to controller method names (e.g., `FormPolicy::index()` gates `FormController@index`).

## Key Patterns and Non-Findings

### 1. safeUnserialize() with allowed_classes => false (Safe POI pattern)

`Helper.php:1683-1689`:
```php
public static function safeUnserialize($data)
{
    if (is_serialized($data)) {
        return @unserialize(trim($data), ['allowed_classes' => false]);
    }
    return $data;
}
```

**Pattern:** `unserialize()` with `['allowed_classes' => false]` prevents PHP Object Injection. When auditing, this pattern is SAFE — no gadget chain can be triggered. The `is_serialized()` guard is defense-in-depth.

### 2. Acl::verify() always checks nonce + capability

`Acl.php:136-155`:
```php
public static function verify($permission, $formId = null, ...) {
    static::verifyNonce();  // checks wp_verify_nonce on AJAX
    $allowed = static::hasPermission($permission, $formId);  // checks current_user_can
    if (!$allowed) { wp_send_json_error(...); }
}
```

**Pattern:** All admin AJAX handlers use `Acl::verify('capability_name', $formId)`. This combines nonce + capability check in one call. When tracing, `Acl::verify()` = fully protected.

### 3. Payment webhook has signature verification (StripeListener.php)

`StripeListener.php:22-86`: The `verifyIPN()` method:
1. If `fluentform_stripe_webhook_secret` is set, verifies HMAC signature with 5-minute replay window
2. Re-fetches the event from Stripe API (defense-in-depth)
3. Only processes known event types

**Pattern:** Payment webhook listeners with signature verification + event re-fetch are not exploitable by unauthenticated attackers. If webhook secret is NOT configured, it still re-fetches from Stripe API using the event ID — an attacker would need a valid Stripe event ID.

### 4. IP resolution with trusted proxy validation (InteractsWithIPTrait.php)

The framework's `getIp()` method (InteractsWithIPTrait.php:38-101):
1. Starts with `$_SERVER['REMOTE_ADDR']`
2. Only trusts `X-Forwarded-For` / `CF-Connecting-IP` if `REMOTE_ADDR` is in configured trusted proxy CIDR ranges
3. Validates every IP with `FILTER_VALIDATE_IP`

**Pattern:** When a plugin's IP resolution validates trusted proxies before trusting forwarded headers, SSRF via IP spoofing in `wp_remote_get($url_with_ip)` is NOT exploitable. The IP always passes through `FILTER_VALIDATE_IP`.

### 5. include($file) with hardcoded FLUENTFORM_DIR_PATH prefix (Safe LFI)

`BaseProcessor.php:466-469`:
```php
$file = FLUENTFORM_DIR_PATH . 'app/Views/' . $view . '.php';
include($file);
```

`TransactionShortcodes.php:152-155`:
```php
$file = FLUENTFORM_DIR_PATH . 'app/Views/frameless/frameless_page_view.php';
include($file);
```

**Pattern:** `include()` with a hardcoded directory constant prefix and no user input in the path is safe. Even if `$view` is a class property, it's set internally, not from request data.

### 6. selectRaw() with prepared parameters (Safe SQL)

`ReportHelper.php:916`:
```php
$viewsQuery->selectRaw("FLOOR(DATEDIFF(DATE(created_at), ?) / 3) as group_num", [$minDate]);
```

**Pattern:** `selectRaw()` with `?` placeholders and bound parameters is equivalent to `$wpdb->prepare()` — safe from SQL injection. Check whether the bound values are user-controlled; here `$minDate` comes from a prior DB query result.

### 7. Form submission is by-design public (not a vulnerability)

The `fluentform_submit` nopriv handler accepts form data from any visitor, validates fields with `fluentFormSanitizer()` (type-aware sanitization), and inserts a submission record. It does NOT modify site settings, user accounts, or plugin configuration. This is expected behavior for a form plugin — not a vulnerability.

## Search Commands Used

```bash
# All nopriv handlers
grep -rn 'wp_ajax_nopriv' --include="*.php" <plugin>/

# REST API routes
grep -rn 'register_rest_route\|\$router->' --include="*.php" <plugin>/app/Http/

# SQL injection patterns
grep -rn '\$wpdb->(query|get_results|get_var|get_row|get_col)' --include="*.php" <plugin>/app/

# Unserialize
grep -rn '(unserialize|maybe_unserialize)' --include="*.php" <plugin>/app/

# File operations
grep -rn '(wp_handle_upload|move_uploaded_file|file_put_contents|\$_FILES)' --include="*.php" <plugin>/app/

# Settings changes
grep -rn '(update_option|delete_option)' --include="*.php" <plugin>/app/

# LFI/RFI
grep -rn '(include|require).*\$' --include="*.php" <plugin>/app/

# Command execution
grep -rn '\b(eval|system|exec|passthru|shell_exec|popen|proc_open)' --include="*.php" <plugin>/app/

# SSRF
grep -rn 'wp_remote_(get|post|request|head)' --include="*.php" <plugin>/app/
```

## Lessons

1. **Custom WP frameworks (wpfluent) can enforce security differently.** The `withPolicy()` pattern ensures `permission_callback` is always set on REST routes — unlike raw `register_rest_route` where devs forget it. Check the framework's `getDefaultOptions()` to confirm.
2. **`unserialize()` with `['allowed_classes' => false]` is safe.** Don't report it as PHP Object Injection. The option was added in PHP 7.0 specifically to prevent gadget chain instantiation.
3. **700K-install plugins with only 5 CVEs are often well-hardened.** Don't expect easy wins. The existing CVEs likely covered earlier weaknesses that are now patched.
4. **Payment webhooks with signature verification + API re-fetch are not exploitable.** Even without the secret, the re-fetch prevents forged events from being processed.
5. **When a plugin uses a query builder (wpFluent), check `selectRaw/whereRaw/orderByRaw`** for parameterized vs. raw string usage. Parameterized raw methods are safe.
