# events-manager v7.4.2 — Unauthenticated Audit (No Findings)

**Plugin:** events-manager v7.4.2 (60k+ installs)
**Date:** August 2026
**Outcome:** No exploitable unauthenticated vulnerabilities found.
**Key technique:** WordPress `$wpdb->prepare()` quote-stripping makes `'%s'` patterns safe.

## Attack Surface

### Nopriv AJAX Handlers (em-actions.php)

| Handler | Line | Registration | Auth Check |
|---------|------|-------------|------------|
| `search_events` | 918 | `wp_ajax_nopriv_search_events` | None (nopriv) |
| `search_events_grouped` | 920 | `wp_ajax_nopriv_search_events_grouped` | None (nopriv) |
| `search_locations` | 922 | `wp_ajax_nopriv_search_locations` | None (nopriv) |
| `search_tags` | 924 | `wp_ajax_nopriv_search_tags` | None (nopriv) |
| `search_cats` | 926 | `wp_ajax_nopriv_search_cats` | None (nopriv) |
| `geocoding_search` | 954 | `wp_ajax_nopriv_geocoding_search` | **COMMENTED OUT** (lines 929-956) |
| `search_states` | 716 | Via `em_init_actions_start` (em_ajax flag) | None (nopriv) |
| `search_towns` | 744 | Via `em_init_actions_start` (em_ajax flag) | None (nopriv) |
| `search_regions` | 775 | Via `em_init_actions_start` (em_ajax flag) | None (nopriv) |
| `GlobalMapData` | 46 | Via `em_init_actions_start` (em_ajax flag) | None (nopriv) |
| `GlobalEventsMapData` | 55 | Via `em_init_actions_start` (em_ajax flag) | None (nopriv) |
| `ajaxCalendar` | 71 | Via `em_init_actions_start` (em_ajax flag) | None (nopriv) |

### WP_FullCalendar Handler (em-wpfc.php)

| Handler | Line | Registration | Auth Check |
|---------|------|-------------|------------|
| `wpfc_em_ajax` | 12 | `wp_ajax_nopriv_WP_FullCalendar` | None (nopriv) |

### REST API (em-api-rest.php)

All REST endpoints require authentication (`is_user_logged_in` or capability checks).
Upload endpoint has `__return_true` but requires nonce.

## SQL Injection Analysis — All Safe

### 1. `'%s'` Pattern in `$wpdb->prepare` — SAFE

Multiple locations use `$wpdb->prepare("... '%s' ...", $_REQUEST[...])`:
- em-actions.php:720 — `"(location_country = '%s' OR location_country IS NULL )"`
- em-actions.php:723 — `"( location_region = '%s' )"`
- em-actions.php:748, 751, 754, 778 — similar patterns

**Why safe:** WordPress `prepare()` strips quotes around `%s` before substitution
(see `wp-includes/class-wpdb.php` ~line 1485):
```php
$query = str_replace( "'%s'", '%s', $query ); // Strip any existing single quotes.
$query = str_replace( '"%s"', '%s', $query ); // Strip any existing double quotes.
```
Then `prepare()` adds its own escaped quotes. So `'%s'` → `%s` → `'escaped_value'`.

### 2. Scope Parameter — Raw Interpolation, Validated Upstream — SAFE

em-object.php lines 444-457 interpolate `$date_start`/`$date_end` directly:
```php
$conditions['scope'] = " $event_start_col >= CAST('$date_start' AS $cast)";
```

**Why safe:** `get_default_search()` validates scope at em-object.php:211-223:
- String scope matching `/^([0-9]{4}-[0-9]{1,2}-[0-9]{1,2})?,(...)$/` is split into array
- Each element validated against `/^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}$/`
- Invalid elements → empty string → falls to default scope

### 3. `post_id` Parameter — Raw Interpolation, Sanitized Upstream — SAFE

em-events.php:683 and em-locations.php:404:
```php
$conditions['post_id'] = "(".EM_EVENTS_TABLE.".post_id={$args['post_id']})";
```

**Why safe:** `clean_id_atts()` (em-object.php:114) sanitizes post_id:
- Numeric → cast to int
- `array_is_numeric` → kept as-is
- Matches `/^( ?[\-0-9] ?,?)+$/` → exploded
- **Otherwise → unset (removed)**
Non-numeric strings never reach the SQL.

### 4. Location Fields (country/town/state/region/postcode) — SAFE

em-object.php:592-616: All properly parameterized with `$wpdb->prepare()` and `%s` placeholders.

### 5. `blog` Parameter — SAFE

em-events.php:660-671 and em-locations.php:378-391: Protected by `is_numeric()` or regex `/^([\-0-9],?)+$/`.

### 6. `near` Parameter — SAFE

em-object.php:568-572: Requires `array_is_numeric()` check before interpolation.

### 7. `search` Parameter — SAFE

em-events.php:648-652 and em-locations.php:354-360: Uses `$wpdb->esc_like()` + `$wpdb->prepare()`.

### 8. Orderby Fields — SAFE

Validated against `$accepted_fields` whitelist in `build_sql_x_by_helper()` (em-object.php:1100-1120).

### 9. `event_slug` — SAFE

events-manager.php:409: Uses `$wpdb->prepare()` with `%s` and `%d`.

## WP_FullCalendar Private Event Exposure — SAFE

`wpfc_em_ajax` (em-wpfc.php:133) passes `array_merge($_REQUEST, $args)` to `EM_Calendar::get()`.
Since `$args` (second arg) overrides `$_REQUEST` (first arg), `status=>1` is enforced.

Private events filtered by `build_sql_conditions` (em-events.php:655):
```php
if( empty($args['private']) || !current_user_can('read_private_events') ){
    $conditions['private'] = "(`event_private`=0)";
}
```
Unauthenticated users can't `read_private_events` → private events always filtered.

## Status Exposure — SAFE

em-events.php:912-918 and em-locations.php:508-514:
```php
if ( !current_user_can('edit_others_events') && !in_array($args['status'], array(1, '1', true), true) ) {
    if ( is_user_logged_in() ) {
        if ( empty($args['owner']) ) $args['owner'] = get_current_user_id();
    } else {
        $args['status'] = 1;  // Force published for guests
    }
}
```

## Other Checks

- **File upload:** REST `/uploads` endpoint has `__return_true` permission but requires nonce (`X-EM-Nonce` header). Files are temp-only with image type validation.
- **SSRF via geocoding_search:** Function is **commented out** (lines 929-956). No risk.
- **LFI/RFI:** All includes use `EM_DIR` constant or `dirname(__FILE__)` — no variable paths.
- **Unauth event creation:** Requires nonce + capability checks.
- **Magic quotes:** AJAX goes through `wp_magic_quotes()`. `get_post_search()` calls `wp_unslash()`. REST API requires auth for search.

## Dynamic Nopriv Registration Pattern

`em_init_actions()` (em-actions.php:817-830) registers `em_init_actions_start` at priority 999999 for ALL nopriv/ajax actions:
```php
add_action('wp_ajax_nopriv_' . $_REQUEST['action'], 'em_init_actions_start', 999999);
add_action('wp_ajax_' . $_REQUEST['action'], 'em_init_actions_start', 999999);
```

This means `em_init_actions_start` runs AFTER the dedicated handler. During AJAX, `DOING_AJAX` is defined, so `$_REQUEST['em_ajax']` is auto-set to `true` (line 10), unlocking all `em_ajax`-gated functionality including `search_states`, `search_towns`, `GlobalMapData`, etc.

## Data Flow Summary

```
$_REQUEST → get_post_search() [merge + wp_unslash]
         → get_default_search() [validate scope, month, year, clean_id_atts]
         → build_sql_conditions() [parameterize with $wpdb->prepare()]
         → EM_Events::get() → $wpdb->get_results($sql)
```

The defense-in-depth is solid: `get_default_search()` acts as a centralized sanitizer
before any SQL construction. Even raw interpolation points only receive pre-validated values.
