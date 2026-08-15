# SMS Alert v3.9.8 — Nopriv AJAX Handler Audit (3,000 installs)

## Overview

Deep audit of 9 nopriv AJAX handlers in the SMS Alert (sms-alert) WordPress plugin.
All 49 unprepared SQL queries in the codebase were traced; none reachable from
user input via nopriv handlers.

**Result: No Patchstack-accepted vulnerabilities found.**

## Plugin Architecture

- Main file: `SMSAlert-wc-order-sms.php`
- Helper files in `helper/` — each class self-registers in constructor
- No REST API routes (`register_rest_route` / `rest_api_init` — none found)
- No file upload handlers
- No RCE vectors (`eval`, `system`, `exec` — none found)
- All nopriv handlers gated by `is_user_authorised()` (admin API credentials configured)

## Nopriv Handler Summary

| # | Action | Callback | Nonce | Cap | SQL Sink | Exploitable |
|---|--------|----------|-------|-----|----------|-------------|
| 1 | check_cart_data | share-cart.php:96 checkCartIsEmpty | NO | NO | None (echoes WC cart total) | NO |
| 2 | save_cart_data | share-cart.php:297 saveShareCartData | YES (L299) | NO | L408/410 unprepared but $lastid from DB | NO |
| 3 | send_onboarding_data | feedback.php:337 sendOnboardingData | YES (L340) | NO | None (API call) | NO |
| 4 | skip_onboarding_popup | feedback.php:388 skipOnboardingPopup | NO | NO | None (update_option) | NO |
| 5 | process_campaign | class-smscampaign.php:155 processCampaign | YES (L157) | YES manage_options | wc_get_orders (WC API) | NO |
| 6 | save_subscribe | class-shortcode.php:146 saveSubscribeData | NO | NO | None (API call) | NO |
| 7 | save_data | class-abandonedcart.php:1897 saveUserData | YES (L1900) | NO | read_cart L2366 unprepared, $cart_session_id from WC session | NO |
| 8 | insert_exit_intent | class-abandonedcart.php:2628 displayExitIntentForm | NO | NO | $wpdb->prepare (safe) | NO |
| 9 | remove_exit_intent | class-abandonedcart.php:2651 removeExitIntentForm | NO | NO | None | NO |

## Key Findings and Patterns

### 1. Unprepared SQL with SELECT MAX(id) result (NOT injectable)

`share-cart.php:408-410`:
```php
$lastid = $wpdb->get_results('SELECT MAX(id) FROM ' . $table_name, ARRAY_A);
$data = $wpdb->get_results('SELECT * FROM ' . $table_name . ' WHERE id = ' . $lastid[0]['MAX(id)'], ARRAY_A);
```

`$table_name` is `$wpdb->prefix . SA_CART_TABLE_NAME` (constant). `$lastid[0]['MAX(id)']`
is an integer returned by the database from a prior query — NOT user input. Even though
the query at line 410 uses string concatenation without `prepare()`, the interpolated value
is a DB-internal integer, not attacker-controlled.

**Pattern:** DB-internal values (results of prior SELECT queries, auto-increment IDs,
aggregate function results like MAX/COUNT) used in unprepared SQL are NOT injectable
even without `prepare()`, as long as no user input flows into the prior query.

### 2. Unescaped output from external API response (NOT exploitable XSS)

`class-shortcode.php:155-156`:
```php
$error = !is_array($response['description']) ? $response['description'] : $response['description']['desc'];
echo '<div class="sastock_output" ...>'.$error.'</div>';
```

`$response` comes from `json_decode(SmsAlertcURLOTP::createContact(...), true)` — the
response of an HTTP API call to `https://www.smsalert.co.in/api/createcontactxml.json`.

The unescaped `echo` is a code quality issue but NOT exploitable because:
- The attacker cannot control the API response from a third-party service
- All inputs sent TO the API are sanitized with `sanitize_text_field()` (strips HTML tags)
- Even if the API reflected input back in an error message, the HTML tags would already be stripped
- `wp_remote_post` error messages (WP_Error) don't contain user input or HTML

**Pattern:** Unescaped output of data sourced from external API responses is not
exploitable XSS when the attacker cannot control the API response content. This is
distinct from unescaped output of user input (which IS exploitable).

### 3. $wpdb->prepare('%s', $wpdb->update(...)) misuse (NOT a security issue)

`share-cart.php:354-371` and `class-abandonedcart.php:1978-1999`:
```php
$updated_rows = $wpdb->prepare(
    '%s',
    $wpdb->update($table_name, array(...), array('session_id' => $cart_session_id), array(...), array(...))
);
```

This wraps the RESULT of `$wpdb->update()` (an integer row count) in a `prepare()` call.
This is incorrect usage — `$wpdb->update()` already handles escaping internally via its
own `prepare()` call. The outer `prepare('%s', ...)` is meaningless but NOT a security
issue. Don't be confused into thinking the update is unprotected.

### 4. WC session ID in unprepared SQL (NOT injectable)

`class-abandonedcart.php:2366`:
```php
$cart_session_id = WC()->session->get('cart_session_id');
$msg_sent = $wpdb->get_var('SELECT msg_sent, session_id FROM ' . $table_name . " WHERE session_id = '" . $cart_session_id . "'");
```

`$cart_session_id` is from `WC()->session->get()` — server-generated value (customer ID
or hash from `WC()->session->get_customer_id()`). All `WC()->session->set('cart_session_id', ...)`
calls use internally-generated values, never direct user input. NOT injectable.

This confirms the existing skill pattern: "WooCommerce `WC()->session` session IDs are
server-generated, not user-controlled."

### 5. Nonce only in admin_enqueue_scripts (nopriv users can't obtain)

`feedback.php:53` registers `wp_ajax_nopriv_send_onboarding_data`, but the nonce
`smsf_onboarding_nonce` is only created in `enqueueScripts()` hooked to
`admin_enqueue_scripts` (line 93). Frontend visitors can't obtain it. The nopriv
handler is effectively dead code from an unauthenticated attack perspective.

### 6. Entire handler body gated by manage_options + nonce (dead nopriv)

`class-smscampaign.php:155-200`: `processCampaign()` has ALL code inside:
```php
if(current_user_can('manage_options') && wp_verify_nonce($_POST['sacampaign_nonce'], 'sacampaign_wp_nonce'))
```
If the check fails, the function returns nothing. The nopriv registration is dead code.

### 7. Dead nopriv handler not called by plugin's own JS

`feedback.php:57`: `skipOnboardingPopup` is registered as nopriv but the plugin's JS
(`feedback-admin.js`) never makes an AJAX call to `skip_onboarding_popup`. The "skip"
button just calls a local JS function that hides the popup visually. An attacker could
manually call it via `admin-ajax.php`, but it only does `update_option('onboarding-data-skipped', time())`
— minimal impact, not Patchstack-accepted.

### 8. checkPhoneNos() custom sanitization (digits-only)

`curl.php:106-136`: `checkPhoneNos()` does `preg_replace('/[^0-9]/', '', $no)` which
strips everything except digits. This is equivalent to `intval()` for SQL injection
purposes — the result contains only numeric characters. SQL queries using
`checkPhoneNos()` output are safe even without `prepare()`.

### 9. Hardcoded CART_ENCRYPTION_KEY (not independently exploitable)

`SMSAlert-wc-order-sms.php:84`:
```php
define('CART_ENCRYPTION_KEY', 'SgVkYp3s6v9y$B&M)H+MbQeThWmZq4t9');
```

The key is hardcoded in source, but `restoreCart()` verifies:
```php
hash_hmac('md5', $row->email . $row->session_id, CART_ENCRYPTION_KEY)
```
An attacker needs the target cart's `email` + `session_id` (DB values) to forge a
valid hash. The hardcoded key alone is insufficient for exploitation.

### 10. Hash mismatch bug (logic bug, not security)

Share Cart `create_cart_url()` hashes `hash_hmac('md5', $session_id, key)` but
`restoreCart()` verifies `hash_hmac('md5', $email . $session_id, key)`. These never
match for share-cart URLs — the feature is broken. But this is a logic bug, not a
security vulnerability. The abandoned cart version (in `SA_Cart_Admin`) correctly
uses `email . session_id` in both create and verify.
