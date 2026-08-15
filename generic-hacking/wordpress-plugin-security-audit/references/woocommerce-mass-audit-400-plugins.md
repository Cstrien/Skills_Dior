# WooCommerce Plugin Mass Audit — 400+ Plugins (2026-08-12)

## Scope

Mass audit of ~400 WooCommerce plugins (1,000–30,000 installs) from WordPress.org API
for Patchstack CVE submission. Scanned for nopriv AJAX handlers, REST routes with
`__return_true`, SQL without `prepare()`, file upload, and broken access control.

## Final Verified Finding (1 submittable)

### woo-refund-and-exchange-lite v4.6.3 (4,000 installs) — Unauth Arbitrary Settings Modification
- **Status:** SUBMITTABLE — no existing CVE, present in latest version
- **Handler:** `wp_ajax_nopriv_wps_standard_save_settings_filter`
- **Root cause:** nopriv registration + nonce-only check (no `current_user_can()`) + nonce exposed on public page
- **PoC verified on local lab:** unauthenticated curl → response `"yes"` → 10+ `update_option()` calls succeed
- **Uploaded to Notion:** [CVE Pending] woo-refund-and-exchange-lite v4.6.3
- **Exploit script:** `/tmp/exploit_woo_refund.sh` (auto-finds nonce, sends exploit, reports result)

## Findings Rejected by Patchstack Rules

| Plugin | Finding | Rejection Rule | Reason |
|--------|---------|----------------|--------|
| wp-full-stripe-free v8.5.3 | IDOR cancel subscription (no ownership check) | Rule 79 | Stripe sub ID is random non-guessable string |
| classified-listing v3.0.5 | Unauth listing deletion (`delete_temp_listing`) | Rule 58 + fixed | Fixed v6.0.0 + overlaps CVE-2025-58601 |
| advanced-form-integration v1.7.0 | SQLi via CF7 `form_id` without prepare() | Rule 54 (weak) | Fixed in v1.76.0 (latest v2.8.2) |
| woo-refund-and-exchange-lite | Guest order message IDOR (0===0) | Rule 58 | Duplicate of CVE-2025-12881 |
| woo-refund-and-exchange-lite | Cancel return request IDOR | Rule 58 | Duplicate of CVE-2025-12086 |

## Plugins Confirmed Safe (deep-dived, 25+)

| Plugin | Nopriv Count | Why Safe |
|--------|-------------|----------|
| mage-eventpress v5.4.1 | 16 | Nonce + server-side price validation |
| points-and-rewards v2.10.2 | — | Patched (CVE-2026-11782, added `manage_options`) |
| profilegrid | — | `WP_User_Query` prepared statements, `$sortby` switch-case sanitized |
| content-egg v11.5.0 | 2 | SSRF protected: nonce + Amazon domain allowlist + IP filter |
| wpfunnels v2.4.0 | 32 | Cart manipulation (no nonce) but requires shared session — limited impact |
| woo-gift-cards-lite v3.2.9 | 9 | Balance check nonce-only but Patchstack-weak (info disclosure) |
| salon-booking-system v10.31 | — | REST routes use `permissions_check()` with `current_user_can()` |
| ecab-taxi-booking-manager v2.0.8 | — | REST routes use `authorize_api_request()` (API keys), file upload has MIME whitelist |
| webba-booking-lite v6.4.19 | — | Unprepared SQL uses server-generated values (timestamps), not user input |
| wholesalex v3.0.1 | — | REST callbacks read options, no SQLi |
| product-blocks | — | REST `__return_true` but nonce exposed on frontend + WP_Query (safe) |
| woo-refund-and-exchange-lite (IDOR vectors) | 8 | Duplicate CVEs cover guest order IDOR findings |
| Amazon Pay | — | Nonce + absint |
| YITH gift cards | — | Nonce check present |
| WOCS | — | Safe |
| charitable | — | Safe |
| restrict-content | — | Safe |
| dokan-lite | — | Brute force only (Patchstack rejects) |
| sms-alert | — | DB-internal values in SQL, not user input |
| hashbar | — | Safe |
| woocommerce-jetpack | — | Session ID server-generated |
| gpt3-ai-content-generator | — | Nonce faucet pattern (by design) |
| wp-travel-engine | — | Safe |
| wp-event-manager | — | Safe |
| email-subscribers | — | Safe |
| PPOM | — | Safe |
| coupon-x | — | Safe |
| zero-bs-crm | — | Safe |
| login-with-ajax | — | Safe |

## Key Lessons

1. **REST API + SQL without prepare = highest priority** but empirically rare (0 found in 400 plugins)
2. **Nopriv settings modification** (nonce-only, no capability check) is the most reliable Patchstack-accepted pattern
3. **Rule 79 (non-guessable ID)** kills IDOR findings that require knowing random resource IDs (Stripe sub IDs, crypto UUIDs)
4. **Guest order IDOR (0===0)** is a real vuln but heavily CVE'd already — check NVD before investing time
5. **Fixed-in-latest findings** are weak under Rule 54 — always download latest version and verify
6. **WP lab rebuild** from scratch takes ~5 minutes when lab is local machine (wp-cli + direct DB access)
7. **Nonce page-location matters:** a plugin can expose different nonces on different pages — match the `check_ajax_referer()` action name to the correct `wp_create_nonce()` call, then find which page loads that script
