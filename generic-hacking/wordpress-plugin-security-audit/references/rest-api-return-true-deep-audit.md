# Deep REST API `__return_true` SQLi Audit — 4 Booking Plugins (2026-08-12)

Targeted audit of 4 WordPress booking plugins specifically hunting for SQLi via
REST routes with `__return_true` (or equivalent `return true()` permission callbacks).
REST API parameters bypass `wp_magic_quotes()`, so string-concatenated SQL with
`$request->get_param()` input is directly exploitable.

## Plugins Audited

| Plugin | Version | Installs | PHP files | `__return_true` routes | `return true()` routes | SQLi found |
|---|---|---|---|---|---|---|
| wholesalex | 3.0.1 | 2,000 | 117 | 2 | 0 | ❌ |
| webba-booking-lite | 6.4.19 | 2,000 | 1,697 | 2 | ~15 | ❌ |
| salon-booking-system | 10.31.0 | 2,000 | 1,400 | ~30 | 0 | ❌ |
| ecab-taxi-booking-manager | 2.0.8 | 2,000 | 89 | 1 | 0 | ❌ |

## Key Technique: Detecting `return true()` Permission Callbacks

webba-booking-lite uses **named functions** that return `true` instead of the
string `'__return_true'`:

```php
// This is NOT caught by grep '__return_true'
public function create_booking_permission( $request ) {
    return true;  // Public endpoint
}
```

**Detection grep:**
```bash
grep -rn 'function.*_permission' --include="*.php" <plugin_path>
# Then check each for unconditional `return true;`
```

## Key Technique: Tracing Through Model/Wrapper Classes

None of the `__return_true` callbacks in any of the 4 plugins used `$wpdb`
directly. All SQL was mediated through:
- `WP_User_Query` / `WP_Query` (WordPress core — parameterized)
- `$wpdb->insert()` / `$wpdb->update()` (parameterized by WP core)
- `$wpdb->prepare()` in model utility classes
- Plugin-internal handler classes (e.g., `SLN_Action_Ajax_CheckDate`)

**Efficient audit approach:** After finding `__return_true` routes, grep each
controller file for `$wpdb`. If zero hits, the callback uses WP API classes
or plugin wrappers — still trace one level deeper (model classes, repository
classes) but skip if the wrapper layer consistently uses `prepare()`.

## Notable Finding: salon-booking-system `get_stats()` — SQLi Code Smell, Not Exploitable

**File:** `src/SLB_API_Mobile/Controller/Bookings_Controller.php:318-336`
(and identical in `src/SLB_API/Controller/Bookings_Controller.php:415`)

```php
$sql_joins = "INNER JOIN {$wpdb->prefix}postmeta pm ON p.id = pm.post_id
    AND pm.meta_key='_sln_booking_date'
    AND DATE(pm.meta_value) >= '" . (new \SLN_DateTime($request->get_param('start_date')))->format('Y-m-d') . "'
    AND DATE(pm.meta_value) <= '" . (new \SLN_DateTime($request->get_param('end_date')))->format('Y-m-d') . "'";

$results = $wpdb->get_results("
    SELECT COUNT(DISTINCT p.ID) as bookings_count,
    DATE_FORMAT(pm.meta_value, '" . $format . "') as unit_value
    FROM {$wpdb->prefix}posts p {$sql_joins}
    WHERE p.post_type = '" . self::POST_TYPE . "'
    AND p.post_status <> 'trash'
    GROUP BY DATE_FORMAT(pm.meta_value, '" . $format . "')",
    OBJECT
);
```

**Why NOT exploitable (3 independent reasons):**

1. **Authenticated only**: Route uses `get_items_permissions_check` →
   `permissions_check('read')` → `current_user_can('edit_posts')`. NOT `__return_true`.

2. **Strict input validation**: `start_date` and `end_date` pass through
   `rest_validate_request_arg` with `'format' => 'YYYY-MM-DD'`:
   ```php
   if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) || !strtotime($value)) {
       return new WP_Error('rest_invalid_date', ...);
   }
   ```
   The regex `^\d{4}-\d{2}-\d{2}$` rejects anything containing `'`, `;`, `--`, etc.

3. **DateTime sanitization**: Input goes through `new \SLN_DateTime($input)->format('Y-m-d')`
   which produces a clean `Y-m-d` string regardless of input.

4. **`group_by` is enum-validated**: `'enum' => array('day', 'month', 'year')` →
   maps to `%e`, `%c`, or `%Y`. No user-controlled string reaches `$format`.

## Notable Finding: salon-booking-system `Customers_Controller::get_item()` — IDOR

**File:** `src/SLB_API_Mobile/Controller/Customers_Controller.php:488`

- `permission_callback => '__return_true'` — unauthenticated
- `get_item()` has NO internal `current_user_can()` check
- Accepts `GET /customers/(?P<id>[\d]+)` — sequential integer ID
- Returns: customer ID, first_name, last_name, email, phone, address, bookings, photos

**Contrast:** `get_items()` (list endpoint) in the same controller HAS
`if (!current_user_can('manage_salon')) { return rest_ensure_response(['status' => '403']); }`
at line 209. The developer added an internal check to `get_items()` but forgot it
in `get_item()`.

**Patchstack assessment:** Likely reportable as broken access control / info
disclosure (unauthenticated IDOR with sequential IDs), but user IDs may not
be considered sensitive enough for the standard program. Borderline.

## Notable Finding: salon-booking-system Duplicate API Directories

The plugin maintains TWO parallel API implementations:
- `src/SLB_API_Mobile/Controller/` — mobile app API
- `src/SLB_API/Controller/` — desktop/standard API

Both have near-identical code (same `get_stats()` SQL, same controller structure).
Both must be checked independently. The Mobile version may have different
permission callbacks or subtle differences in the non-Mobile version.

**Detection:**
```bash
find <plugin_path> -type d -name 'Controller' | sort
```

## Notable Finding: webba-booking-lite — 17+ Public Endpoints, All Safe

webba-booking-lite has approximately 17 endpoints with `return true` permission
callbacks (2 explicit `__return_true` + 15 named `return true()` functions).
Despite being a booking plugin with heavy database interaction (bookings,
coupons, payments, time slots), ALL SQL is mediated through:
- `WBK_Model_Utils::*` methods → all use `$wpdb->prepare()`
- `WBK_Booking_Factory` → uses `$wpdb->insert()` (parameterized)
- `WBK_Validator::check_coupon()` → uses `$wpdb->prepare()`
- Model `add_item()` / `update_item()` → `$wpdb->insert()` / `$wpdb->update()`

The plugin's wbkdata model layer consistently parameterizes, even though the
model class itself has some `$wpdb->get_results($sql)` without prepare for
admin-only listing operations (gated by `administrator` role check).

## Summary

After 444 plugins scanned cumulatively, the REST API + `__return_true` + raw SQL
pattern remains at **ZERO exploitable instances**. The WordPress ecosystem
consistently uses `$wpdb->prepare()` or WP API query classes even in public
endpoints. The main risk from `__return_true` routes is **IDOR / information
disclosure** (unauthenticated access to resources by sequential ID), not SQLi.
