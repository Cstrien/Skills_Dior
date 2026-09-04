# PHP Loose Comparison Password Bypass on Unauthenticated Endpoints

A recurring pattern in WordPress plugins: password validation on nopriv
endpoints uses loose `==` / `!=` comparison instead of strict `===` / `!==`,
enabling type-juggling bypasses when the stored password is a numeric string.

## The Vulnerability Pattern

```php
// VULNERABLE — loose comparison
$password = sanitize_text_field($_REQUEST['password']);  // user input
$stored   = get_post_meta($ID, '__wpdm_password', true); // string from DB

if ($password != $stored) {
    // reject — wrong password
} else {
    // accept — password correct
}
```

When `$stored` is `"0"` and attacker sends `"0e1"`:
- PHP evaluates `"0" != "0e1"` as `0 != 0` → `FALSE`
- The `!=` check passes → password accepted

## PHP Version Differences

### PHP 7.x (loose string comparison)
```
"0" == "0e1"    → TRUE  (both cast to int 0)
"0" == "0e123"  → TRUE  (both cast to int 0)
"0" == "abc"    → TRUE  (both non-numeric → cast to int 0)
"0" == ""       → FALSE (empty string special case)
"123" == "123"  → TRUE  (exact match)
"123" == "0e1"  → FALSE (123 != 0)
```

### PHP 8.x (string comparison with numeric-string awareness)
```
"0" == "0e1"    → TRUE  (both are numeric strings, compared as numbers: 0 == 0)
"0" == "0e123"  → TRUE  (both are numeric strings, compared as numbers: 0 == 0)
"0" == "abc"    → FALSE (non-numeric string, compared as strings: "0" != "abc")
"123" == "123"  → TRUE  (exact match)
"123" == "0e1"  → FALSE (123 != 0)
```

**Key difference:** PHP 8 no longer casts non-numeric strings to `0` for
comparison. So `"0" == "abc"` is `FALSE` in PHP 8 but `TRUE` in PHP 7.

## Exploitability Conditions

For this to be exploitable, ALL of these must be true:

1. **Unauthenticated endpoint** — nopriv AJAX handler or REST route with
   `permission_callback => '__return_true'`
2. **Loose comparison** — `==` or `!=` (not `===` / `!==`)
3. **Stored password is type-juggling-vulnerable** — must be `"0"`, `"0e..."`,
   or another value that PHP treats as `0` in numeric comparison
4. **No nonce check** or attacker can obtain a valid nonce from the page
5. **No rate limiting** — for brute-forcing the type-juggling value

## Bypass Payloads

When the stored password is `"0"`:

| Stored | Payload | PHP 7 | PHP 8 | Why |
|--------|---------|-------|-------|-----|
| `"0"` | `"0e1"` | ✅ | ✅ | 0 == 0 (scientific notation) |
| `"0"` | `"0e123456"` | ✅ | ✅ | 0 == 0 (scientific notation) |
| `"0"` | `"0.0"` | ✅ | ✅ | 0 == 0.0 (float comparison) |
| `"0"` | `"00"` | ✅ | ✅ | 0 == 0 (octal/leading zeros) |
| `"0"` | `"abc"` | ✅ | ❌ | PHP 7: both → int 0; PHP 8: string comparison |
| `"0"` | `"false"` | ✅ | ❌ | Same as above |

When the stored password is `"123"`:
| Stored | Payload | PHP 7 | PHP 8 | Why |
|--------|---------|-------|-------|-----|
| `"123"` | `"123"` | ✅ | ✅ | Exact match (no bypass needed) |
| `"123"` | `"0e1"` | ❌ | ❌ | 123 != 0 |
| `"123"` | `"1e2"` | ✅ | ✅ | 123 == 100? No → 123 != 100 |

**Only password `"0"` (and `"0e..."`) are exploitable** with type juggling.
Most real-world passwords are alphanumeric and not exploitable.

## Detection Grep

```bash
# Find loose comparison in password checks
grep -rn '\$password\s*[!=]=\s*\$' --include="*.php" <plugin_path>
grep -rn '\$pass\s*[!=]=\s*\$' --include="*.php" <plugin_path>
grep -rn '\$filepass\s*[!=]=\s*\$' --include="*.php" <plugin_path>
grep -rn 'password.*==\|!=.*password' --include="*.php" <plugin_path>
```

Then check each hit:
1. Is the comparison on an unauthenticated endpoint? (nopriv or `__return_true`)
2. Is the comparison loose (`==`/`!=`) not strict (`===`/`!==`)?
3. Can the stored password be a type-juggling-vulnerable value?

## Real-World Examples

### download-manager v3.3.67 (100K installs)

**File:** `src/Package/PackageLocks.php:81`
**Endpoint:** `POST /wp-json/wpdm/validate-password` (`permission_callback => '__return_true'`)
```php
if ($passwords && $password != $passwords && substr_count($passwords, "[$password]") < 1) {
    // wrong password
}
```
**Assessment:** Not Patchstack-qualifiable. Requires stored password = `"0"`.
Loose `!=` comparison, but bracket-format check provides second path.

**File:** `src/__/Apply.php:389` (nopriv AJAX `wpdm_verify_file_pass`)
```php
if ($filepass !== '' && $password == $filepass || substr_count($password, "[{$filepass}]") > 0)
```
**Assessment:** Same pattern. No nonce, no rate limit — brute force enabled.
Not Patchstack-qualifiable due to same type-juggling requirement.

## Why This Is Usually Not Reportable

1. **Requires specific password value** — admin must set password to `"0"`
2. **Not a general bypass** — doesn't work for arbitrary passwords
3. **Patchstack/programs consider it defense-in-depth** — the real fix is to
   use `hash_equals()` or `===`, but the vulnerability requires an unlikely
   pre-condition (admin setting password to `"0"`)
4. **No PII/RCE/data exposure** — the bypass only grants a download link for
   the specific package, same as knowing the password

## When It IS Reportable

If the loose comparison is combined with:
- **Password stored as integer `0`** (not string `"0"`) — more likely to trigger
- **No rate limiting + short numeric passwords** — brute force the value space
- **Stored password is a default value** (e.g., plugin defaults to `"0"` until
  admin changes it)
- **The bypass grants access to sensitive data** (not just a download link)

## Recommended Fix (for report recommendations)

```php
// Use hash_equals() for timing-safe, strict comparison
if (!hash_equals((string)$stored, (string)$user_input)) {
    // wrong password
}

// Or use strict === comparison
if ((string)$stored !== (string)$user_input) {
    // wrong password
}
```
