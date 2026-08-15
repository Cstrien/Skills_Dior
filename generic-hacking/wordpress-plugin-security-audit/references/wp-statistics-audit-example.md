# WP Statistics v14.16.10 — Unauthenticated Audit Example

Worked example of the wordpress-plugin-security-audit methodology applied to
WP Statistics v14.16.10 at `/var/www/html/wordpress/wp-content/plugins/wp-statistics/`.

## Nopriv Attack Surface Identified

### Three nopriv registration mechanisms found:

1. **`WP_Async_Request::__construct()`** (`wp-async-request.php:64`) — registers `wp_ajax_nopriv_` for all `WP_Background_Process` subclasses. 6 subclasses found (IncompleteGeoIpUpdater, SourceChannelUpdater, CalculatePostWordsCount, SummaryTotalsDataMigration, VisitorColumnsMigrator via BaseBackgroundProcess). Protected by `check_ajax_referer()` in `maybe_handle()`.

2. **`Ajax::register()` with `$public=true` default** (`src/Components/Ajax.php:23`) — callers with default: `option_updater` (gated by `is_admin()`), `custom_event` (nonce-gated). All other callers explicitly pass `false`.

3. **Deprecated `Ajax` class with `public=>true`** (`class-wp-statistics-admin-ajax.php:85`) — only `hit_record` registered as public, and only when both `use_cache_plugin` and `bypass_ad_blockers` options are enabled. Protected by `wp_salt()`-based signature.

### REST API routes:

- `/wp-statistics/v2/hit` — `permission_callback` = `checkSignature()` (wp_salt-based). Not bypassable.
- `/wp-statistics/v2/metabox` — `permission_callback` checks `wp_get_current_user()` + `current_user_can()`. Not bypassable.
- `/wp-statistics/v2/import/(?P<driver>...)` — `permissionCallback` checks `User::Access('manage')`. Not bypassable.
- `/wp-statistics/v2/export/(?P<driver>...)` — `permissionCallback` checks `User::Access('read')`. Not bypassable.
- **`BaseRestAPI::permissionCallback()` returns `true`** (`src/Abstracts/BaseRestAPI.php:83`) — but both concrete subclasses override it. Latent risk only.

## Key Findings

### Finding 1: `getConditionSQL()` — SQL Injection (authenticated only)

**File:** `includes/class-wp-statistics-helper.php:774-807`

```php
public static function getConditionSQL($args = array())
{
    foreach ($condition as $params) {
        if ($params['compare'] == "BETWEEN") {
            $sql .= $params['key'] . " " . $params['compare'] . " " .
                (is_numeric($params['from']) ? $params['from'] : "'" . $params['from'] . "'") .
                " AND " . (is_numeric($params['to']) ? $params['to'] : "'" . $params['to'] . "'");
        } else {
            $sql .= $params['key'] . " " . $params['compare'] . " " .
                (is_numeric($params['value']) ? $params['value'] : "'" . $params['value'] . "'");
        }
    }
    return $sql;
}
```

Directly concatenates `$params['key']`, `$params['compare']`, `$params['value']` into SQL without `$wpdb->prepare()`. Non-numeric values only wrapped in single quotes (easily escaped).

**Called from:** `Visitor::Count()` at `class-wp-statistics-visitor.php:487-488`.

**Unauthenticated reachability:** NOT reachable. Callers are admin-page data providers requiring authentication. The `searchVisitors` method (nopriv-exposed via `search_visitors` handler) uses the `Query` builder which properly calls `prepare()`.

**Verdict:** SQL injection from authenticated context, but NOT exploitable unauthenticated.

### Finding 2: 22 `$wpdb->query/get_var/get_results` without `prepare()`

Found across the plugin. All use either:
- Static SQL strings (e.g., `'SET autocommit = 0'`)
- `$wpdb->prefix`-derived table names (server-side constant)
- `DB::table()` helper (returns prefixed table name from internal map)
- `$wpdb->esc_like()` + `$wpdb->prepare()` (in FilterManager)

None reachable from unauthenticated paths with user-controlled input.

### Finding 3: `maybe_unserialize()` in background processing

`wp-background-process.php:489` — unserializes option data. Data is server-generated via `update_site_option()`. Nopriv handler is nonce-protected. Not exploitable.

### No `eval()`, `system()`, `exec()`, or `include/require` with user input found.

## Method Notes

- The `search_files` tool timed out on this plugin (~500+ PHP files). Fell back to `grep -rn` via terminal which worked reliably.
- Used `execute_code` (Python) for batch SQL injection detection: iterated over all PHP files, matched `$wpdb->query/get_var/get_results` patterns, filtered out `prepare` usage, and collected file:line:code tuples. This was much more efficient than reading each file manually.
- The custom `Query` builder (`src/Utils/Query.php`) accumulates values in `$valuesToPrepare` and calls `$wpdb->prepare()` at execution time in `getVar()`, `getAll()`, `getRow()`, `execute()`. This is safe as long as callers don't bypass it with `whereRaw()` passing unprepared user input.
- `Request::get()` applies `sanitize_text_field()` by default, which strips tags but does NOT prevent SQL injection on its own. The protection comes from `$wpdb->prepare()` in the Query builder.
