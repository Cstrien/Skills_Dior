# Audit: WooCommerce Jetpack v8.2.0 + GPT3 AI Content Generator v2.4.62

Date: 2026-08-12
Scope: Deep security audit of nopriv AJAX handlers, SQLi, XSS, file upload, SSRF.

## WooCommerce Jetpack (Booster for WooCommerce) v8.2.0 — 30,000 installs

### 16 Nopriv AJAX Handlers — ALL SAFE

All handlers use nonce verification. Nonces are exposed via `wp_localize_script()` (available to unauthenticated users who load the page), but the nonce action names are specific to each module, preventing cross-handler nonce reuse.

| Handler | File:Line | Nonce Action | Notes |
|---------|-----------|--------------|-------|
| `wcj_ajax_add_to_wishlist` | class-wcj-wishlist.php:208 | `wcj-wishlist` | Only modifies user_meta for logged-in users |
| `wcj_ajax_remove_from_wishlist` | class-wcj-wishlist.php:284 | `wcj-wishlist` | Safe |
| `wcj_ajax_add_to_cart_wishlist_pro` | class-wcj-wishlist.php:337 | `wcj-wishlist` | Uses WC cart API |
| `wcj_wishlist_table_products` | class-wcj-wishlist.php:490 | `wcj-wishlist` | Output via `wp_json_encode` |
| `wcj_track_users` | class-wcj-track-users.php:489 | `wcj-track-users` | `$wpdb->insert()` (prepared); `sanitize_text_field` on IP/referer |
| `wcj_sale_not_product_html_hpos` | class-wcj-sales-notifications.php:613 | `wcj_sales_notifications` | Output via `wp_json_encode` |
| `wcj_sale_not_product_html` | class-wcj-sales-notifications.php:111 | `wcj_sales_notifications` | Same |
| `price_change` (bookings) | class-wcj-product-bookings.php:124 | `wcj_product_bookings` | Output via `wp_kses_post` |
| `product_addons_price_change` | class-wcj-product-addons.php:416 | `wcj_product_addons` | Output via `wp_kses_post` |
| `woocommerce_get_customer` | class-wcj-price-by-user-role.php:104 | `wcj-order-users` | Nonce only exposed via `admin_enqueue_scripts` — nopriv users can't obtain it |
| `woocommerce_remove_customer` | class-wcj-price-by-user-role.php:119 | `wcj-order-users` | Same |
| `wcj_save_cart_abandonment_data` | class-wcj-cart-abandonment.php:215 | `woocommerce-process_checkout` | Standard WC checkout nonce; data stored via `$wpdb->insert()`/`update()` |
| `wcj_ajax_get_exchange_rates` | class-wcj-currency-exchange-rates.php:89 | `ajax-nonce` | Output via `esc_html` |
| `wcj_validate_eu_vat_number` | class-wcj-eu-vat-number.php:519 | `wcj_eu_vat_number_to_check` | Safe |
| `wcj_ajax_get_exchange_rates_average` | exchange-rates/class-wcj-exchange-rates.php:43 | `ajax-nonce` | Output via `esc_html` |

### SQLi: 19 Unprepared Queries — NONE Reachable via Nopriv

- `class-wcj-cart-abandonment.php:425`: `UPDATE ... WHERE session_id='$session_id'` — `$session_id` is server-generated MD5 hash from `WC()->session`, not user-controlled.
- `cart-abandonment/wcj_cart_abandonment_email_schedules.php:78`: Same — server-generated values.
- `class-wcj-track-users.php:368`: `SELECT * FROM table` — no user parameters.
- All other unprepared queries are admin-only with nonce protection.

### XSS: Sales Notifications str_replace Pattern

The sales notifications handler builds messages via `str_replace($msg, $msg_val, $wcj_sale_msg_msg)` where `$msg_val` includes customer billing data (first_name, city, country). However:
- WooCommerce applies `sanitize_text_field` to checkout fields at storage time (strips HTML tags)
- Output is via `wp_json_encode()` (JSON response), not raw HTML echo
- The admin-configured message template (`$wcj_sale_msg_msg`) is from `get_option()` — admin-controlled

**Verdict: Not exploitable by unauthenticated users.**

### Track Users Data Injection

`wcj_track_users` accepts `wcj_user_ip` and `wcj_http_referer` from POST. Both sanitized with `sanitize_text_field`. Stored via `$wpdb->insert()` (prepared). IP spoofing only affects analytics data. Admin display uses `esc_html()` and `wp_kses_post()`.

## GPT3 AI Content Generator (AI Power) v2.4.62 — 10,000 installs

### 19 Nopriv AJAX Handlers

All frontend handlers use `check_frontend_permissions()` which verifies `aipkit_frontend_chat_nonce` nonce. A dedicated nopriv endpoint (`aipkit_get_frontend_chat_nonce`) issues fresh nonces to unauthenticated users — this is by design for guest chatbot access (see "Nonce Faucet" pattern below).

### File Upload: `aipkit_frontend_chat_upload_file` — SAFE (with caveat)

**Caveat:** The actual handler class `ChatFileUploadAjaxDispatcher` is in a Pro addon NOT present in the free plugin codebase. Hook is conditionally registered only when the class exists AND Pro plan is active.

The AI Form file upload handler (`aipkit_ai_form_upload_and_parse_file`), which IS present, uses `AIPKit_Upload_Utils::validate_upload_file()` with robust validation:
- `is_uploaded_file()` check
- `wp_check_filetype_and_ext()` (WordPress core filetype detection)
- `mime_content_type()` (server-side content detection)
- Extension cross-check against allowed MIME types
- File size check
- Type mismatch rejection
- Allowed types: text/plain, text/csv, application/json, application/pdf, text/html, .docx — **PHP is NOT allowed**

**Cannot upload .php files through available handlers.**

### SQLi: 10+ Unprepared Queries — NONE Reachable via Nopriv

- `classes/chat/storage/reader/methods.php:160`: Uses `$wpdb->prepare()` via `build_conversation_query_parts()` — prepared.
- `classes/core/token-manager/pricing/class-aipkit-price-resolver.php`: Admin-only pricing management, not reachable from nopriv.
- `classes/core/class-aipkit-event-queue-store.php`: Queue worker uses nonce; items are system-generated.

### SSRF: NOT Exploitable

All AI API endpoint URLs constructed from `AIPKit_Providers::get_provider_data()` which reads from `get_option('aipkit_options')` — admin-configured settings. User-supplied prompts/queries go into request body, not URL components.

### Guest Session IDOR (Weak Pattern, Likely Not Patchstack-Qualifying)

`ajax_get_conversations_list` and `ajax_get_conversation_history` scope conversation access by `session_id` from POST. The `session_id` is a client-generated UUID stored in `localStorage`. An attacker who knows another guest's UUID could access their chat history. UUIDs are random (crypto.getRandomValues), making brute-force impractical. This is a weak design pattern but likely does not meet Patchstack's vulnerability threshold.
