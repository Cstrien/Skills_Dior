# WordPress `$wpdb->prepare('%s')` Quote-Stripping — Safe Pattern Reference

## The Pattern

Many WordPress plugins use `$wpdb->prepare()` with `'%s'` (placeholder wrapped in
single quotes) in their SQL:

```php
$wpdb->prepare("(location_country = '%s' OR location_country IS NULL )", $_REQUEST['country'])
$wpdb->prepare("( location_region = '%s' )", $_REQUEST['region'])
$wpdb->prepare("(location_state = '%s' )", $_REQUEST['state'])
```

## Why This Is SAFE

WordPress `wpdb::prepare()` strips quotes around `%s` placeholders BEFORE
substitution, then adds its own escaped quotes during the actual parameter binding.

**Source:** `wp-includes/class-wpdb.php` ~line 1485:

```php
/*
 * If a %s placeholder already has quotes around it, removing the existing quotes
 * and re-inserting them ensures the quotes are consistent.
 *
 * For backward compatibility, this is only applied to %s, and not to placeholders like %1$s,
 * which are frequently used in the middle of longer strings, or as table name placeholders.
 */
$query = str_replace( "'%s'", '%s', $query ); // Strip any existing single quotes.
$query = str_replace( '"%s"', '%s', $query ); // Strip any existing double quotes.
```

So the execution flow is:

1. `'%s'` in the query string → `%s` (quotes stripped by `str_replace`)
2. `%s` → `'escaped_value'` (prepare adds its own quotes with proper escaping)

Result: `(location_country = 'escaped_value' OR location_country IS NULL )`

## How to Verify

Check the WordPress source directly:

```bash
grep -n "str_replace.*'%s'" wp-includes/class-wpdb.php
```

Output (WordPress 6.x):
```
$query = str_replace( "'%s'", '%s', $query ); // Strip any existing single quotes.
$query = str_replace( '"%s"', '%s', $query ); // Strip any existing double quotes.
```

## What to Flag vs What NOT to Flag

| Pattern | Status | Action |
|---------|--------|--------|
| `$wpdb->prepare("... = '%s' ...", $user_input)` | **SAFE** | Do NOT flag as SQLi |
| `$wpdb->prepare("... = %s ...", $user_input)` | **SAFE** | Do NOT flag as SQLi |
| `"... = '{$user_input}' ..."` (no prepare) | **VULNERABLE** | Flag as SQLi |
| `"... = $user_input ..."` (no prepare) | **VULNERABLE** | Flag as SQLi |
| `$wpdb->prepare("... = %s ...", $_REQUEST['x'])` | **SAFE** | Do NOT flag |
| `"... '{$wpdb->esc_like($user_input)}' ..."` | **SAFE** | esc_like + prepare pattern |

## Important Caveat: `%1$s` and Numbered Placeholders

The quote-stripping ONLY applies to `%s` (unnumbered). Numbered placeholders
like `%1$s` are NOT stripped:

```php
// This DOES get quotes stripped:
$wpdb->prepare("WHERE x = '%s'", $val)

// This does NOT get quotes stripped (numbered placeholder):
$wpdb->prepare("WHERE x = '%1$s'", $val)
```

The WordPress source comment explicitly states this:
> For backward compatibility, this is only applied to %s, and not to placeholders
> like %1$s, which are frequently used in the middle of longer strings, or as
> table name placeholders.

So `'%1$s'` would become `''value''` (double quotes) — a SQL syntax error, not
injection. Still broken, but not exploitable.

## Real-World Example: events-manager v7.4.2

The events-manager plugin has 6+ instances of the `'%s'` pattern in
`em-actions.php`:

```php
// em-actions.php:720
$conds[] = $wpdb->prepare("(location_country = '%s' OR location_country IS NULL )", $_REQUEST['country']);
// em-actions.php:723
$conds[] = $wpdb->prepare("( location_region = '%s' )", $_REQUEST['region']);
// em-actions.php:748
$conds[] = $wpdb->prepare("(location_country = '%s' OR location_country IS NULL )", $_REQUEST['country']);
// em-actions.php:754
$conds[] = $wpdb->prepare("(location_state = '%s' )", $_REQUEST['state']);
// em-actions.php:778
$conds[] = $wpdb->prepare("(location_country = '%s' )", $_REQUEST['country']);
```

All are **SAFE** — these are nopriv-accessible AJAX handlers (`search_states`,
`search_towns`, `search_regions`) but the `'%s'` pattern is properly escaped
by WordPress's quote-stripping behavior.

## Common Misconception

Many automated SAST tools and manual auditors flag the `'%s'` pattern as SQL
injection because they see the placeholder inside quotes and assume the quotes
are literal. The WordPress `prepare()` method was specifically designed to
handle this pattern gracefully — it's a documented, supported usage.

**Key lesson:** When you see `$wpdb->prepare("... '%s' ...", $user_input)`,
verify the call IS going through `prepare()` (not just string concatenation
that looks like it). If it IS `prepare()`, the pattern is safe.
