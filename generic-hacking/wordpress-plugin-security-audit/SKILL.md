---
name: wordpress-plugin-security-audit
description: Audit WordPress plugins for unauthenticated vulnerabilities.
version: 1.0.0
author: hermes-agent
license: MIT
tags: [wordpress, plugin, security, audit, nopriv, sqli, rest-api]
related_skills: [sast-code-review, web-vulnerability-methodology]
---

# WordPress Plugin Security Audit

A systematic methodology for auditing WordPress plugin source code for unauthenticated (nopriv) vulnerabilities.

## When to Use

- User asks to audit a WordPress plugin for vulnerabilities
- User provides a plugin path and asks for security review
- User mentions nopriv AJAX handlers, REST API routes, or `$wpdb` SQL injection in WordPress context
- User wants to find unauthenticated attack surface in a WordPress plugin
- **Plugin handles file uploads** — file upload plugins require a dedicated extension blocklist audit (see Phase 7)

## Audit Workflow

### Phase 1: Identify the Nopriv Attack Surface

WordPress plugins expose unauthenticated endpoints through three mechanisms. Find ALL of them before tracing callbacks.

#### 1a. Nopriv AJAX Handler Registration

Search for all three registration patterns:

```bash
# Pattern 1: Direct wp_ajax_nopriv action registration
grep -rn 'wp_ajax_nopriv' --include="*.php" <plugin_path>

# Pattern 2: Dynamic nopriv registration via helper methods
# Look for wrapper methods that accept a $public/isPublic flag
grep -rn 'Ajax::register\|add_action.*nopriv\|wp_ajax_nopriv' --include="*.php" <plugin_path>

# Pattern 3: Background processing libraries (delphics/wp-background-processing)
# These register nopriv handlers in their constructor
grep -rn 'extends WP_Async_Request\|extends WP_Background_Process' --include="*.php" <plugin_path>
```

**Critical:** For Pattern 2, check the DEFAULT value of the `$public` parameter. If it defaults to `true`, every caller that doesn't explicitly pass `false` is nopriv-exposed. Example from WP Statistics:
```php
public static function register($action, $callback, $public = true) // DEFAULT TRUE
```

Also check for registration gated by `is_admin()` — the handler may be registered as nopriv but only during admin page loads, meaning it's NOT actually reachable from the frontend.

#### 1b. REST API Route Registration

```bash
grep -rn 'register_rest_route' --include="*.php" <plugin_path>
```

For each route, check the `permission_callback`:
- `__return_true` or `function() { return true; }` → **unauthenticated**
- Missing `permission_callback` entirely → WordPress defaults to `__return_true` (unauthenticated)
- `current_user_can(...)` or custom capability check → authenticated
- Signature/HMAC verification → depends on whether the secret is exposed
- **Named function returning `true`** (e.g., `function create_booking_permission() { return true; }`) → **unauthenticated** — grep for `__return_true` misses these. Always also grep for `return true` in `*_permission` functions:
  ```bash
  grep -rn 'function.*_permission.*return true\|function.*permission.*{$' --include="*.php" <plugin_path>
  ```
  Then read each to confirm it unconditionally returns `true`.

Look for base classes that define a default `permissionCallback()` — subclasses that forget to override inherit the default.

**Duplicate controller directories:** Some plugins (e.g., salon-booking-system) maintain parallel API namespaces like `SLB_API_Mobile/` and `SLB_API/` with near-identical controller code. Both directories must be checked independently — the Mobile version may have `__return_true` while the non-Mobile version uses a capability check, or vice versa.

### Phase 2: Trace Each Nopriv Callback

#### Identifying AJAX Registration Mechanisms (Three Architectures)

Plugins may register AJAX handlers via three distinct architectures. Identify which one the plugin uses before searching:

1. **Direct `add_action` registration** — the standard pattern. Grep for `wp_ajax_nopriv_` and `wp_ajax_` directly.

2. **File-name-based auto-registration (glob pattern)** — the plugin iterates a directory and auto-registers every `.php` file as an action where the **filename IS the action name**. Example from WP All Import:
   ```php
   // plugin.php:289-300
   foreach (PMXI_Helper::safe_glob(self::ROOT_DIR . '/actions/*.php', ...) as $filePath) {
       require_once $filePath;
       $function = $actionName = basename($filePath, '.php');
       add_action($actionName, self::PREFIX . str_replace('-', '_', $function), $priority, 99);
   }
   ```
   For this pattern: (a) `find /actions/ -name "wp_ajax_*"` to enumerate handlers, (b) the function body IS the handler logic, (c) `wp_ajax_nopriv_*` files = nopriv surface, `wp_ajax_*` files = authenticated only.

3. **Single-handler dynamic dispatch** — one `wp_ajax_nopriv_*` registration dispatches to model methods via an allowlist + ReflectionMethod. See `references/wp-job-portal-dynamic-dispatch-audit.md` and `references/supsystic-nonce-only-bac-audit.md`.

For each nopriv-exposed action, trace the callback function and check for:

#### 2a. Authentication/Authorization Gaps
- Missing `check_ajax_referer()` / `wp_verify_nonce()` calls
- Missing `current_user_can()` / capability checks
- Nonce checks where the nonce is publicly available (e.g., output in page HTML for frontend AJAX)
- Signature checks where the secret is derived from `wp_salt()` (server-side, not exposed)

#### 2b. SQL Injection
Search broadly for unprepared SQL:
```bash
# Find all $wpdb calls that don't use prepare
grep -rn '\$wpdb->query\|\$wpdb->get_var\|\$wpdb->get_results\|\$wpdb->get_row\|\$wpdb->get_col' --include="*.php" <plugin_path> | grep -v 'prepare'
```

For each hit, check:
- Is the SQL string built with variable interpolation (`$variable` in double-quoted strings or `{}`)?
- Does the variable come from user input (`$_REQUEST`, `$_GET`, `$_POST`, `Request::get()`)?
- Is there a custom query builder? If so, verify it calls `$wpdb->prepare()` before executing.
- Look for `getConditionSQL()`-style helper methods that concatenate values into SQL strings without prepare.

#### 2c. Authentication Endpoint Vulnerabilities (wp_signon / wp_set_auth_cookie)

Search for authentication functions in nopriv handlers — these are brute force / auth abuse vectors:

```bash
# Find wp_signon / wp_set_auth_cookie / wp_set_current_user in nopriv-reachable code
grep -rn 'wp_signon\|wp_set_auth_cookie\|wp_set_current_user' --include="*.php" <plugin_path> | grep -v vendor
```

**`wp_signon()` in a nopriv handler is a brute force enabler when:**
- The nonce is available to unauthenticated visitors (e.g., generated via `wp_create_nonce()` and emitted to page HTML via `wp_localize_script()`)
- There is no rate limiting, attempt counter, lockout, or CAPTCHA
- User-controlled `user_login` and `user_password` from `$_POST` reach `wp_signon()`

This is NOT an auth bypass (valid credentials are still required), but it enables unlimited-speed password brute force through an AJAX endpoint that bypasses any protections configured on `/wp-login.php` (CAPTCHA, rate limiting, etc.).

**Key check:** Trace where the nonce is generated. If it's in a `wp_enqueue_scripts` / `wp_localize_script` call that runs on every frontend page, the nonce is trivially obtainable by any visitor. The `check_ajax_referer()` call is present but not a barrier.

**`sanitize_text_field()` on password fields is a bug:**
```php
$user_password = sanitize_text_field( $form_data['password'] );  // BAD
$wp_user = wp_signon( [ 'user_password' => $user_password, ... ] );
```
`sanitize_text_field()` strips HTML tags and scripts from the password. Users whose passwords contain `<`, `>`, or other HTML-like sequences cannot log in through this endpoint. This is both a functional bug and a minor auth issue — report it as part of the brute force finding, not as a separate vulnerability.

### 2c-2. Broken Access Control / IDOR in Customer Portal AJAX Handlers

A critical pattern found in payment/subscription plugins: **AJAX nopriv handlers that authenticate via cookie/session but don't validate resource ownership**. The handler confirms the user's session is valid, then accepts resource IDs (subscription IDs, payment method IDs) from user input and operates on them WITHOUT checking that the resource belongs to the authenticated user.

**Detection pattern:**
1. Find nopriv AJAX handlers that use cookie/session-based auth (e.g., `findSessionCookieValue()`, `$_COOKIE[...]`)
2. Check if the handler accepts resource IDs from `$_POST` (e.g., `$_POST['subscription-id']`, `$_POST['wpfs-subscription-id']`)
3. **Critical:** Look for a REST API equivalent of the same operation — if the REST handler validates ownership (`$resource->customer !== $session->customerId` → 403) but the AJAX handler doesn't, the AJAX handler is vulnerable

**Key insight — AJAX vs REST handler divergence:** When a plugin has BOTH `wp_ajax_nopriv_X` AND a `register_rest_route` for the same operation, compare them. Developers often add proper authorization to the REST API version (returning `WP_Error('forbidden', ...)` with 403) but forget it in the AJAX version. The AJAX handler authenticates the session (user is who they say they are) but doesn't authorize the operation (user can't access this specific resource). This is a systematic pattern, not a one-off mistake — always diff the two implementations when both exist.

**Exploitability:** The attacker needs a valid session, but the session can often be obtained via the plugin's own email+security-code flow (create session with your own email, confirm with security code, then pass arbitrary resource IDs). This makes it exploitable by any unauthenticated user who has an account on the target site.

**Grep to find the pattern:**
```bash
# Find nopriv handlers that read cookies for auth
grep -rn 'wp_ajax_nopriv.*\$_COOKIE\|wp_ajax_nopriv.*findSession\|wp_ajax_nopriv.*session' --include="*.php" <plugin_path>
# Then check if the same plugin has register_rest_route for the same operation
grep -rn 'register_rest_route' --include="*.php" <plugin_path>
```

**Confirmed example:** WP Full Stripe Free v8.5.3 — `handleSubscriptionCancellationRequest()` (line 2045) cancels arbitrary subscriptions without ownership check, while `handleSubscriptionUpdateRequest()` (REST, line 2158) properly checks `$subscriptionCustomerId !== $cardUpdateSession->stripeCustomerId`. See `references/wp-full-stripe-broken-access-control.md`.

### 2d. Other Vulnerability Classes
```bash
# unserialize with user input
grep -rn 'unserialize|maybe_unserialize' --include="*.php" <plugin_path> | grep -v vendor

# LFI via include/require with variables
grep -rn 'include\s*(|require\s*(|include_once\s*(|require_once\s*(' --include="*.php" <plugin_path> | grep '$'

# RCE via eval/system/exec
grep -rn '\beval\s*(|\bsystem\s*(|\bexec\s*(|\bpassthru\s*(|\bshell_exec\s*(' --include="*.php" <plugin_path>

# File upload with path/extension control
grep -rn 'move_uploaded_file|wp_handle_upload|file_put_contents' --include="*.php" <plugin_path>

# SSRF in URL-fetching functions (import plugins especially)
grep -rn 'fopen\s*(\s*\$|file_get_contents\s*(\s*\$|get_headers\s*(\s*\$|wp_remote_get\s*(\s*\$|curl_init\s*(\s*\$' --include="*.php" <plugin_path> | grep -v vendor
```

#### PHP Object Injection — Checking for Custom Safe Wrappers

Before reporting `maybe_unserialize()` as POI, check if the plugin defines its own wrapper with `['allowed_classes' => false]`:
```bash
grep -rn "allowed_classes.*false" --include="*.php" <plugin_path>
```
If found, verify which unserialize calls use the wrapper (SAFE) vs. direct `unserialize()` or WP core `maybe_unserialize()` (POTENTIALLY UNSAFE). WP core `maybe_unserialize()` does NOT pass `allowed_classes => false` — it calls `@unserialize(trim($data))` without restrictions.

**Import plugin session handling:** Import plugins often store session data as `base64_encode(serialize($data))` in `wp_options`. If the plugin reads this back with WP core `maybe_unserialize()` (no `allowed_classes` restriction), it's technically unsafe, but only exploitable if an attacker can write to that `wp_options` key — which typically requires admin access or a separate vulnerability. Trace where `_import_id` (the option key suffix) comes from: if it's from `$_GET['id']`, an attacker can read any session, but cannot inject serialized objects.

#### SSRF in Import/Feed-Fetching Plugins

Import plugins (WP All Import, WP All Export, similar feed importers) fetch URLs for XML/CSV/JSON feeds and images. Check for:

1. **IP range protection functions** — does the plugin implement `is_private_ip()` or similar? Check: 10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x ranges.
2. **Are ALL fetch paths protected?** Common paths: `fopen($url)`, `file_get_contents($url)`, `get_headers($url)`, `wp_remote_get($url)`, `curl_init($url)`. Look for fallback paths that bypass the IP check — `fopen()` and `file_get_contents()` with URL wrappers bypass curl-level IP checks.
3. **Does the check cover redirect targets?** `curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true)` follows redirects — the final URL may point to an internal IP even if the initial URL doesn't. Check for `CURLINFO_EFFECTIVE_URL` re-validation.
4. **Is the URL from user input or admin settings?** Even if SSRF exists, it's only reportable if reachable without authentication. Import plugin URL fetching typically requires `manage_options` capability — authenticated SSRF is not Patchstack-accepted.

**Safe pattern (WP All Import `pmxi_is_private_ip`):** Checks both initial URL and redirect target. BUT `fopen($url)` and `file_get_contents($url, false, $context)` fallback paths bypass it — only exploitable by authenticated admins.

```php
// Protected: get_file_curl checks pmxi_is_private_ip on both URL and redirect
// Bypassed: fopen($filePath, "rb") in wp_all_import_get_url() — no IP check
// Bypassed: file_get_contents($img, false, $get_ctx) in test_images — no IP check
```

### Phase 3: Evaluate Exploitability

For each potential vulnerability found:

1. **Trace the data flow** from the nopriv entry point to the vulnerable sink
2. **Check for intermediate sanitization** — WordPress helpers like `sanitize_text_field()`, `intval()`, `absint()`, `$wpdb->esc_like()` may neutralize injection
3. **Check for guards** — `is_admin()`, `DOING_AJAX`, `DOING_CRON` checks that limit reachability
4. **Check if the protection mechanism is bypassable**:
   - Nonces output in page HTML are available to unauthenticated visitors
   - `wp_salt()`-based signatures are NOT available to unauthenticated visitors
   - Capability checks in nopriv handlers will always fail for anonymous users (the handler may still execute other code before the check)
5. **Distinguish registration from reachability** — a nopriv action registered only during `admin_init` is NOT reachable from the frontend
6. **Check for `rest_validate_request_arg` with strict format regex** — WordPress REST route args can declare `'validate_callback' => array($this, 'rest_validate_request_arg')` with `'format' => 'YYYY-MM-DD'`. This enforces `preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)` + `strtotime()` before the callback runs. Even if the callback concatenates the value into SQL without `prepare()`, the regex prevents SQLi. Always check the route's `args` array for `validate_callback` entries — they are an effective (if accidental) SQLi defense.

### Phase 4: Report

For each finding, report:
- **File:line** of the vulnerability
- **Vulnerability type** (SQLi, XSS, RCE, LFI, IDOR, auth bypass, etc.)
- **Code snippet** showing the vulnerable pattern
- **Exploitability assessment** from unauthenticated context specifically
- Whether the vulnerability is reachable from a nopriv entry point

## Common WordPress Plugin Protection Patterns

| Pattern | Unauthenticated Bypassable? | Notes |
|---------|---------------------------|-------|
| `check_ajax_referer()` with server-generated nonce | No | Nonce not available to anonymous users |
| `wp_verify_nonce()` with nonce output in page HTML | Partially | Nonce IS available to anonymous visitors who load the page |
| `wp_salt()`-based signature | No | Salt is server-side only |
| `current_user_can()` in nopriv handler | No | Will fail for anonymous, but check if code runs before the check |
| `is_admin()` gate on registration | No | Prevents nopriv registration on frontend |
| `is_admin()` / `DOING_AJAX` check in handler | Partially | `DOING_AJAX` is true for nopriv requests too |
| `sanitize_text_field()` | Yes for SQLi | Only sanitizes text (strips tags/whitespace), does NOT strip or escape single quotes — does NOT prevent SQL injection |
| `$wpdb->prepare()` | No | Proper parameterization prevents SQLi |
| `absint()` / `intval()` | No | Converts to integer, prevents injection |
| `wp_magic_quotes()` on `$_POST`/`$_GET` | Incidental protection only | Escapes `'` in superglobals — blocks `$_POST`-based SQLi but NOT REST API. Not a substitute for `prepare()`. Deprecated in modern PHP. |
| `wp_unslash()` before SQL | Reverses magic quotes | If plugin calls `wp_unslash($_POST['x'])` then uses result in SQL without `prepare()`, magic quotes protection is removed → SQLi exploitable |
| Custom `escs`-type sanitize (strip `<script>` only) | YES for SQLi | Some plugins define custom sanitize that only strips `<script>` tags (e.g., download-manager's `wpdm_escs()`). Zero SQL/path escaping. Dangerous if used in SQL context. Safe if used only for comparison (e.g., password match). Always check what the sanitize function actually does. See `download-manager-v3.3.67-audit.md` |
| Encrypted path params (`Crypt::decrypt`) | NOT a barrier | Encryption prevents forging paths but is containment, not the primary check. Real protection is `realpath()` + prefix match. Don't forge encrypted paths — find handlers accepting raw paths or controllable post meta. See `download-manager-v3.3.67-audit.md` |
| `call_user_func` with array key dispatch | NOT RCE | `call_user_func($array[user_input]['callback'])` is safe if `$array` is server-controlled. User selects which pre-registered callback runs, not arbitrary functions. See `download-manager-v3.3.67-audit.md` |
| `rest_validate_request_arg` with format regex | YES for SQLi | Route args with `'validate_callback' => 'rest_validate_request_arg'` and `'format' => 'YYYY-MM-DD'` enforce `preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)`. Even string-concatenated SQL is safe because the regex rejects injection characters before the callback runs. |
| `wp_handle_upload()` | No | Validates MIME via `wp_check_filetype_and_ext` — blocks `.php` |
| `wp_upload_bits()` | YES — no MIME/extension check | Writes raw bytes to upload dir without validation. Exploitable if filename+content are user-controlled. |
| `wp_signon()` in nopriv handler | YES — brute force | Not an auth bypass (valid creds needed), but enables unlimited-speed brute force when nonce is publicly available and no rate limiting exists |
| `sanitize_text_field()` on password | N/A — functional bug | Strips HTML-like chars from passwords; users with `<>` in passwords cannot log in via that endpoint |
| `is_array()` gate on file upload | Double-gate trap | If BOTH validation AND upload function gate on `is_array($file['name'])`, single-file bypass of validation is moot — file never gets uploaded |

## WordPress Magic Quotes — The #1 SQLi Exploitation Barrier

WordPress calls `wp_magic_quotes()` during bootstrap, which adds backslash-escaping to all `$_GET`, `$_POST`, `$_COOKIE`, and `$_SERVER` superglobals. This means single quotes in user input are escaped to `\'` before the plugin handler ever sees them.

### What This Means for SQL Injection

If a plugin does `$link = sanitize_text_field($_POST['link'])` and then `$wpdb->get_results("WHERE link = '" . $link . "'")`, the SQLi IS in the code but is NOT exploitable via HTTP — the backslash from magic quotes escapes the quote inside the SQL string literal, making it a literal character rather than breaking out of the string.

**Verified:** `wp eval` bypasses magic quotes (runs in CLI context), so `wp eval` PoCs WILL show the injection working, but the same payload via `curl -X POST` will NOT work. This is a critical false-positive trap.

### What Bypasses Magic Quotes

| Input Source | Magic Quotes Applied? | SQLi Exploitable? |
|---|---|---|
| `$_POST['x']` via admin-ajax.php | YES | NO (quotes escaped) |
| `$_GET['x']` via admin-ajax.php | YES | NO |
| `$request->get_params()` via REST API | **NO** | **YES** |
| `$request->get_json_params()` via REST API | **NO** | **YES** |
| `file_get_contents('php://input')` | **NO** | **YES** |
| `wp_unslash($_POST['x'])` before SQL | Reverses magic quotes | **YES** (if plugin calls wp_unslash) |

### Key Exploitation Strategy

**Prioritize REST API endpoints with `__return_true` permission_callback + SQL concatenation.** REST API parameters do NOT go through `wp_magic_quotes()`, so single quotes arrive unescaped. This is the most reliable way to exploit SQLi in WordPress plugins.

Search pattern:
```bash
# Find files with BOTH register_rest_route and SQL without prepare
grep -rl 'register_rest_route' --include="*.php" <plugin_path> | while read f; do
  grep -n '\$wpdb->get_results([^p]\|\$wpdb->query([^p]\|\$wpdb->get_var([^p]' "$f"
done
```

### `sanitize_text_field()` Does NOT Protect Against SQLi

`sanitize_text_field()` strips tags, removes line breaks, and trims whitespace — but it does NOT strip or escape single quotes, double quotes, or backslashes. Many developers incorrectly assume it prevents SQL injection. It does not. The ONLY proper SQLi defense is `$wpdb->prepare()`.

### Verifying SQLi is HTTP-Exploitable (Not Just Code-Exploitable)

1. Check if the input source is `$_POST`/`$_GET` (magic quotes apply) or REST API (no magic quotes)
2. If `$_POST`/`$_GET`: check if the plugin calls `wp_unslash()` on the input before using it in SQL — if yes, magic quotes are reversed and SQLi is exploitable
3. If REST API: SQLi is exploitable (no magic quotes)
4. Always verify with a `curl` HTTP PoC, NOT `wp eval` — `wp eval` runs outside the HTTP request lifecycle and does NOT apply magic quotes
5. A `wp eval` PoC that shows SLEEP(5) delay is NOT proof of HTTP exploitability

## Patchstack Submission Requirements

When submitting to Patchstack (https://patchstack.com/database/report):

- **PoCs must be HTTP-based** — curl commands with full HTTP requests. WP-CLI (`wp eval`) or other server-side-only steps are NOT accepted.
- **Minimum 1,000 active installs** for the component (unless CVSS ≥ 8.5). Fewer than 100 installs is always out of scope.
- **Test against latest version** of the plugin
- **Unauthenticated, Subscriber, or Customer** access level only for the standard program. Contributor-and-higher is out of scope.
- Accepted vuln types: SQLi, arbitrary file upload/deletion/download, RCE, PHP Object Injection, LFI/RFI, privilege escalation, CSRF→write, stored XSS (site-wide)
- **Rejected:** clickjacking, open redirect, CSRF to admin-notice-dismiss, blind SSRF, CSV injection, contributor-level stored XSS, enumeration without significant info disclosure
- reCAPTCHA v3 blocks headless browsers (score 0.0) — automated submission requires browser with computer_use or manual submission
- Vue.js comboboxes on the report form: the dropdowns are `<button id="vulnerability-class" role="combobox">` and `<button id="vulnerability-type" role="combobox">` (not native `<select>`). Click via `document.getElementById('vulnerability-class').click()`, then select from the `[role=listbox]` `[role=option]` that appears. Pre-requisite dropdown is similar. Text areas are `<textarea id="short-description">`, `<textarea id="reproduce">`, `<textarea id="additional-info">` — set `.value` and dispatch `input` + `change` events for Vue reactivity. Submit button stays disabled until consent checkbox (`@e41` equivalent) is ticked AND reCAPTCHA passes.

### "Site-Wide" Requirement for Stored XSS

Patchstack accepts stored XSS **only** as "site-wide stored XSS with JavaScript execution." The rule states: "Stored XSS that does not affect all frontend or backend pages" is "Not processed outside the mVDP program."

**What "site-wide" means:**
- The XSS must render on ALL frontend pages or ALL backend pages — not just a single page with a shortcode
- A chat plugin whose XSS only appears on pages where admin placed `[chat]` shortcode is **NOT** site-wide
- A comment system whose XSS appears on every post page IS site-wide (posts are the core content)
- Admin dashboard widgets that render on ALL admin pages count as "all backend pages"

**Check before submitting:**
1. Does the XSS render on every page load, or only on specific pages?
2. Is the vulnerable output in a sidebar/widget (appears on all pages) or a shortcode/template tag (specific pages)?
3. Does the admin panel render the same vulnerable output? If the admin page uses `esc_attr`/`esc_url` but the frontend doesn't, the XSS is frontend-only → may not be "site-wide"
4. If not site-wide, the finding may still be valid for mVDP but risks rejection in the standard program

### CVSS Threshold for Rejection

- Unauthenticated vulns with only ONE CIA at Low impact (CVSS 5.3) → rejected
- Subscriber-or-higher with minor data (CVSS 5.4 with two CIA at L, or 6.3 with three at L) → rejected
- Most race conditions below CVSS 7.1 → rejected

### Pre-Submission Rule Compliance Checklist

Before submitting, verify each criterion systematically:
1. ✅ Unauthenticated / Subscriber / Customer access level?
2. ✅ Component has ≥ 1,000 active installs (or CVSS ≥ 8.5)?
3. ✅ Tested against latest version?
4. ✅ HTTP PoC (curl, not wp eval)?
5. ✅ Vuln type in accepted list with conditions met?
6. ✅ Not a duplicate of existing CVE/report?
7. ✅ CVSS above rejection threshold?
8. ✅ Site-wide (for stored XSS)?

## Duplicate Checking via WordPress SVN Trac

Before investing time in a full PoC, check if the vulnerability is a duplicate of an existing CVE. The WordPress plugin SVN repository on Trac provides detailed change history.

### Step 1: Search NVD for existing CVEs

```python
import urllib.request, json
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<plugin+name>&resultsPerPage=20"
# Check each CVE description for the parameter name and affected version
```

### Step 2: Examine the fix changeset

When a CVE references a changeset URL like `https://plugins.trac.wordpress.org/changeset/3472258/simple-ajax-chat`, navigate there to see:
- **Which files were actually modified** — the fix may only touch some files
- **What the diff changed** — client-side JS fix vs server-side PHP fix
- **If the vulnerable file was NOT touched** — your finding may be a different, unpatched vector

Trac pages are JS-rendered. Use `browser_console` with `document.querySelectorAll('table')` to extract diff content, or `browser_snapshot` with `full=true`.

### Step 3: Check file-specific revision history

To see when a specific file was last modified:
```
https://plugins.trac.wordpress.org/log/<plugin_slug>/trunk/<filename>
```

This shows all revisions that touched that file. If the CVE fix changeset doesn't appear in the file's log, the file was NOT fixed by that CVE.

### Worked Example: Simple Ajax Chat Duplicate Analysis

- **CVE-2026-2987** described "Stored XSS via 'c' parameter" in versions ≤ 20260217
- **Fix changeset 3472258** (v20260301) modified: `readme.txt`, `resources/sac.php` (JS), `simple-ajax-chat.php` (version)
- **`simple-ajax-chat-form.php` was NOT in the changeset** — the server-side PHP rendering was not touched
- **File revision log** for `simple-ajax-chat-form.php` showed the last modification was r3611800 (v20260717), not the CVE fix revision
- **Conclusion:** The CVE fixed only the client-side JS auto-linking. The server-side PHP `preg_replace` with `\S*` is a different, unpatched vector.

See `references/wordpress-svn-trac-duplicate-checking.md` for the full workflow.

## File Upload Validation Differences

| Function | MIME Validation | Extension Check | Use When |
|---|---|---|---|
| `wp_handle_upload()` | YES (via `wp_check_filetype_and_ext`) | YES (vs allowed MIME list) | Standard file upload — blocks .php |
| `wp_upload_bits()` | **NO** | **NO** | Writes raw bytes to upload dir — does NOT validate MIME or extension |
| `move_uploaded_file()` | NO (unless plugin adds check) | NO | Raw PHP — no WP validation |

**Key insight:** `wp_upload_bits()` is significantly less secure than `wp_handle_upload()`. If a plugin uses `wp_upload_bits($filename, null, $content)` with user-controlled `$filename` and `$content`, it can write arbitrary files including `.php` — BUT check if the REST endpoint permission requires authentication.

## Mass Plugin Discovery & Scanning

### Downloading Plugins from WordPress.org API

```python
# Get plugin info + download link
url = f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}"
# Download link is in data['download_link'] — includes version number
# Browse modes: 'popular', 'updated', 'new'
url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=updated&request[per_page]=100&request[page]={page}"
# last_updated format: "2026-08-11 3:06am GMT" (not ISO format)
```

### Efficient Scanning Pipeline

1. Query API for target plugins (by install count, search term, browse mode)
2. Download + unzip to local directory
3. Batch scan with Python: `grep` for `wp_ajax_nopriv`, `register_rest_route.*__return_true`, SQL without `prepare`, `wp_upload_bits`/`move_uploaded_file`
4. Cross-reference: files with BOTH nopriv/REST-public AND SQL-without-prepare are highest priority
5. For each hit, trace data flow from entry point to vulnerable sink
6. Verify with HTTP `curl` PoC against local WP lab (NOT `wp eval`)
7. Also search for `str_replace`/`preg_replace` with `$_POST`/`$_GET` — the preg_replace URL auto-linking XSS pattern is the ONE class that bypasses both magic quotes AND sanitize_text_field

### Search Term Strategy for Plugin Discovery

The WordPress.org API search returns plugins matching keywords. These category-based search terms yielded the most nopriv-exposed plugins across 23 batches:

- **High-yield categories** (most nopriv handlers): chat/forum/guestbook, form builders, booking/calendar, review/rating, contact forms
- **Medium-yield**: email subscribe/newsletter, file manager, popup/notification, social login
- **Low-yield** (mostly safe, few nopriv): SEO, caching, analytics, image optimization, URL shortener
- **Search term format**: Use `+` for spaces, `request[per_page]=10-15` for manageable results
- **Install range**: 1,000-30,000 is the sweet spot — enough installs for Patchstack, not large enough to be pre-audited
- **Track scanned slugs**: Maintain a `scanned_slugs` set across batches to avoid re-downloading

### Cross-Batch Pattern Search

After accumulating multiple batches, run cross-batch searches to find specific high-value patterns:

```python
# Search ALL audit directories for REST API + raw SQL (bypasses magic quotes)
for d in range(1, N):
    grep -rn --include="*.php" -l "register_rest_route" audit_dir
    # Then in each file: grep for $wpdb->query/get_results.*$request WITHOUT prepare

# Search for wp_unslash + raw SQL (bypasses magic quotes if plugin calls wp_unslash)
grep -rn "wp_unslash.*\$_(POST|GET|REQUEST)" all_audit_dirs | grep "$wpdb->(query|get_results|get_var|get_row)"

# Search for str_replace/preg_replace with $_POST (XSS via HTML building)
grep -rn "(str_replace|preg_replace).*\$_(POST|GET|REQUEST)" all_audit_dirs
```

**Empirical result after 444 plugins**: ZERO instances of REST API + raw SQL without prepare() found. ZERO instances of wp_unslash + raw SQL found. The WordPress ecosystem has largely internalized proper SQL preparation. The only viable XSS vector remains `preg_replace`/`str_replace` building HTML from user input.

**Reinforced after 580+ plugins across 41 batches (Aug 2026)**: The WordPress ecosystem is extremely hardened. ZERO new high-value findings beyond the `woo-refund-and-exchange-lite` settings modification pattern (which was found via the "exposed nonce + no capability check" pattern, not via SQLi). Nearly ALL plugins (580+) verify BOTH nonce AND capability in nopriv handlers. Cross-batch scans for `wp_unslash + $wpdb`, `update_option($_POST)`, `file_put_contents($_POST)`, and "nonce created but not verified" patterns returned ZERO hits. The most productive vulnerability class remains "frontend-exposed nonce + no capability check + `update_option()`" — but even this is rare (1 in 580 plugins). Do NOT expect to find SQLi in modern WordPress plugins via `$_POST`/`$_GET` (magic quotes) or REST API (everyone uses `prepare()`). Focus on the access-control pattern instead.

**Reinforced again after 800+ plugins (Aug 2026, combined popular+updated scan)**: One new submittable finding — Charitable v1.8.12 unauth file upload via `charitable_plupload_image_upload` (nonce exposed on frontend in `templates/form-fields/picture.php`, no capability check, `wp_handle_upload` saves allowed MIME types to web-accessible uploads dir). See `references/batch-scan-500-plus-plugins-2026.md`. The "exposed nonce + no capability check" pattern now has TWO confirmed instances across 800+ plugins (woo-refund-and-exchange-lite settings mod + Charitable file upload). This is the single most reliable vulnerability class in the WordPress plugin ecosystem. All high-nopriv-count plugins (booking 16, ays-popup-box 10, simple-membership 10, boldgrid-backup 9, master-addons 9) had proper nonce+cap checks inside handler bodies.

**WP Swings plugin family pattern (Aug 2026):** The vendor WP Swings (wpswings.com) produces ~20+ WordPress plugins (woo-refund-and-exchange-lite, points-and-rewards-for-woocommerce, subscriptions-for-woocommerce, etc.) that share a common codebase pattern: onboarding step classes with `skip_onboarding_popup` and `send_onboarding_data` nopriv handlers. The `skip_onboarding_popup` handler typically has NO nonce AND NO capability check but only sets a timestamp (low impact). The `standard_save_settings_filter` handler (found in woo-refund-and-exchange-lite) has a nonce check but NO capability check — this is the exploitable one. When auditing WP Swings plugins, specifically search for `standard_save_settings_filter` and check if the nonce is exposed via `wp_localize_script` on frontend pages.

## XSS Vectors in WordPress Plugin Output

### preg_replace URL Auto-Linking (Server-Side)

A common WordPress plugin pattern auto-links URLs in user-submitted text using `preg_replace`. When the regex uses `\S*` (match any non-whitespace) and the matched URL is placed into an HTML `href` attribute without `esc_url()`, stored XSS is possible.

**Vulnerable pattern:**
```php
$pattern = "/(http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/";
$chat_text = preg_replace($pattern, '<a href="\\0">\\0</a>', $chat_text);
```

**Why it works:**
1. `sanitize_text_field()` strips HTML tags but does NOT strip double quotes (`"`)
2. `\S*` in the regex matches double quotes as part of the URL
3. The matched URL (containing `"`) is placed into `href="\\0"` without `esc_url()`
4. The `"` breaks out of the `href` attribute, enabling attribute injection

**Payload:** `http://x.com/"onmouseover="alert(document.cookie)` — **NO SPACE after the double quote!**
**Rendered:** `<a href="http://x.com/"onmouseover="alert(document.cookie)">` → `onmouseover` becomes a new attribute → XSS on hover

**Why no space matters:** `\S*` matches any non-whitespace. A space after `"` terminates the regex match, so only `http://x.com/"` goes into `href` and `onmouseover` becomes plain text outside the `<a>` tag (no XSS). Without a space, the entire payload is one `\S*` match and goes into `href="..."` where the double quote breaks out. This is the #1 gotcha for this pattern class.

**Grep pattern to find this in source code:**
```bash
grep -rn 'preg_replace.*href.*\\\\0\|preg_replace.*href.*\$1\|preg_replace.*href.*\\\${1}' --include="*.php" <plugin_path>
```

**Key distinction from JS-side auto-linking:** The JavaScript equivalent often uses `[^\s'"\%]` in the regex (excluding quotes), making it safe. The server-side PHP regex frequently uses `\S*` (including quotes), making it vulnerable. Always check BOTH the server-side and client-side auto-linking code — they may have different regex patterns.

**Confirmed example:** Simple Ajax Chat v20260811 (2,000 installs) — `simple-ajax-chat-form.php` line 143-144. Server-side regex uses `\S*` (vulnerable), JS-side regex uses `[^\s'"\%]` (safe). See `references/simple-ajax-chat-xss-example.md`.

### wp_kses_post vs wp_filter_kses (XSS Output Sanitization)

WordPress plugins use different kses functions for sanitizing user input before storage. The distinction matters for XSS auditing:

| Function | HTML Tags Allowed? | on* Attributes? | `<script>`? | Safe for Output? |
|---|---|---|---|---|
| `wp_kses_post()` | YES (a, img, strong, em, span, div, etc.) | NO (stripped) | NO (stripped) | Mostly — but allows `<a href>` which can be used for `javascript:` if not also `esc_url`'d |
| `wp_filter_kses()` / `wp_kses($val, 'strip')` | NO (all tags stripped) | N/A | N/A | YES — plain text only |
| `sanitize_text_field()` | NO (all tags stripped) | N/A | N/A | YES — but does NOT strip `"` or `'` quotes |

**Audit implication:** If a plugin stores user input with `wp_kses_post()`, the stored value may contain `<a>`, `<img>`, `<span>` tags. When this is later output without `esc_html()`, it's not immediately XSS (because `on*` attributes were stripped), BUT it can become XSS if the output context places the value inside an attribute (e.g., `href="..."`) and the value contains double quotes.

If a plugin uses `wp_filter_kses()` or `wp_kses($val, 'strip')`, the stored value is plain text — safe for output in any context EXCEPT inside HTML attributes where double quotes matter (same `sanitize_text_field` limitation).

**Confirmed examples:**
- Democracy Poll: `wp_kses($val, 'strip')` for non-admin answers → safe against XSS
- Poll Maker: `wp_kses_post()` then `wp_filter_kses()` (double sanitization) → safe
- Simple Ajax Chat: `sanitize_text_field()` only → NOT safe in attribute context (quotes preserved)

## User Preference: Do Not Auto-Submit to Patchstack

The user prefers that vulnerabilities are found and verified but NOT automatically submitted to Patchstack. Present the finding to the user and let them decide whether to submit. Do not navigate to the Patchstack submission page or attempt to submit without explicit user instruction.

## Additional Protection Patterns Discovered in Mass Audit (Batches 12-19)

### `filter_input_array()` with `FILTER_SANITIZE_FULL_SPECIAL_CHARS` (Safe for XSS)

MultiVendorX uses `filter_input_array(INPUT_POST, [...])` with `FILTER_SANITIZE_FULL_SPECIAL_CHARS` for review fields. This PHP filter converts `'`, `"`, `<`, `>` to HTML entities — equivalent to `esc_html()`. When a plugin uses this, stored XSS is prevented even if the value is later output without `esc_html()`. Treat as safe — do not report as XSS.

### `wc_clean()` (WooCommerce Sanitizer)

WooCommerce plugins use `wc_clean()` which calls `sanitize_text_field()` internally. Treat as equivalent to `sanitize_text_field()` — strips tags, trims whitespace, but does NOT strip quotes. Safe against XSS, NOT a SQLi defense.

### React Admin Panels Auto-Escape Content

Plugins with React-based admin interfaces (Quill Forms, Echo KB, Info Cards) store unsanitized `$_SERVER['HTTP_USER_AGENT']` in database entries. The admin panel is a React app that renders content via JSX, which auto-escapes by default. Stored XSS in React admin panels is NOT exploitable unless the code uses `dangerouslySetInnerHTML`. Check the JS bundle for `dangerouslySetInnerHTML` before reporting.

### `isPurchaseCodeVerified()` Hardcoded `return true` (Design Decision, Not a Vuln)

MStore API (3,000 installs) has `function isPurchaseCodeVerified() { return true; }` with the actual verification logic commented out. This makes ALL REST endpoints unauthenticated. However, most endpoints still require a `User-Cookie` header validated via `validateCookieLogin()`. Registration allows only safe roles (`seller`, `customer`, `subscriber`) — no privilege escalation. This is a **design decision** for mobile app API access, not a vulnerability. Patchstack will likely reject this as intended behavior.

### `wp_localize_script` Exposing Auth Tokens (Admin-Only = Not Exploitable)

New User Approve plugin exposes `nua_app_auth_token` (generated via `wp_generate_password(20, false)`) to JavaScript via `wp_localize_script()`. The token is regenerated on every admin page load. This is an admin-only exposure — the token is in the admin page HTML source, not frontend. Not exploitable by unauthenticated users.

### Rate Limiting as Nonce Alternative (Fluent Booking Pattern)

Fluent Booking's `ajaxScheduleMeeting()` is nopriv with NO nonce check, but uses `Helper::checkRateLimit('schedule_meeting', 15)` (max 15 requests per time window) plus `sanitize_text_field()` / `sanitize_textarea_field()` / `sanitize_email()` on every field. Rate limiting prevents brute-force while sanitization prevents injection. This is an acceptable pattern for public-facing endpoints where nonces would break page caching.

### Domain-Specific Sanitization for Structured Data (Open User Map Pattern)

Open User Map's `ajax_add_location_from_frontend()` stores `oum_location_geometry` with `wp_unslash()` (no text sanitize), but `sanitize_location_geometry()` validates: json_decode, enforce `type` must be LineString/Polygon, cast all coordinates to `(float)` with comma→dot replacement, validate lat/lng bounds (-90/90, -180/180), max 500 points. This is STRONGER than `sanitize_text_field()` for structured data — it enforces correct structure, not just strips bad characters.

### json_decode(stripslashes()) + Clean Data = Safe Despite Magic Quotes Bypass

Cost Calculator Builder's `create_cc_order` does `json_decode(stripslashes($_POST['data']))` which bypasses magic quotes, but then `CCBCleanHelper::cleanData()` applies `sanitize_text_field` to all decoded values. The magic quotes bypass alone is NOT a vulnerability — it's the lack of subsequent sanitization that matters.

### No Nonce + Read-Only Handler = Safe (WP Popups Lite Pattern)

WP Popups Lite `check_rules()` is nopriv with NO nonce check and processes raw `$_POST['popups']` and `$_POST['query_string']`. However, it only evaluates popup display rules and returns JSON — no database write, no stored output. `form_submission()` also has no nonce but the lite version doesn't store submissions (data only passed to provider hooks). A nopriv handler without nonce is NOT automatically vulnerable if it doesn't store data that's later displayed without escaping.

### REST __return_true + External Signature = Safe Webhook Pattern

WP User Manager's Stripe webhook uses `__return_true` (no WordPress auth) but validates Stripe signature via `signatureIsValid($request)`. This is the standard pattern for payment webhooks — the external service provides its own authentication layer.

### CVE Already Fixed by Developer = Not a New Finding

wpzoom-portfolio (20k installs) had a reflected XSS via `posts_data.class` in the `load_more_items()` nopriv handler. Developer already fixed it by: `unset($data['total'], $data['class'])` + regex validation `preg_match('/^[A-Za-z0-9_\-]+$/', $args['class'])` + casting `lightbox_caption` to `(bool)` + `esc_html()` on `read_more_label`. The fix is comprehensive. Always check if a suspicious pattern was already addressed before reporting.

### SQL Without `prepare()` but Input Already `intval()`'d (WATU Pattern)

WATU plugin has `$wpdb->get_results("SELECT * FROM table WHERE exam_id=$exam_id")` without `prepare()`, but `$exam_id` is set via `$exam_id = intval($_REQUEST['quiz_id'])` on a preceding line. The variable IS an integer by the time it reaches SQL. NOT exploitable. Always trace variable assignments backwards to find the initial sanitization.

### Dynamic Model Dispatch Architecture (wp-job-portal pattern)

Some plugins use a single nopriv AJAX handler that dispatches to model methods via an allowlist array + ReflectionMethod, rather than registering individual `wp_ajax_nopriv_*` actions. The handler reads a `task` parameter, checks it against an allowed list, loads the corresponding module model, and calls the method with zero required parameters.

**Architecture:**
```php
function ajaxhandler() {
    $fucntin_allowed = array('functionA', 'functionB', ...);
    $task = preg_replace('/[^A-Za-z0-9_]/', '', WPJOBPORTALrequest::getVar('task'));
    if (in_array($task, $fucntin_allowed, true)) {
        $module = sanitize_key(WPJOBPORTALrequest::getVar('wpjobportalme'));
        $model = WPJOBPORTALincluder::getJSModel($module);
        // ReflectionMethod checks getNumberOfRequiredParameters() === 0
        $result = $model->$task(); // calls with no arguments
        echo $result;
        die();
    }
}
```

**Audit implications:**
1. **No auth at dispatch level** — the dispatcher has zero nonce/capability checks. Each model method must self-verify.
2. **Every method in the allowlist is nopriv-exposed** — the allowlist IS the attack surface, not the `add_action` registration. Extract the full array and audit each function individually.
3. **Attacker controls which module/model is loaded** via a `wpjobportalme` parameter — same function name may exist in multiple modules with different security postures (see pitfall below).
4. **`method_exists()` gate with add-on functions:** ~30+ functions in the allowlist may not exist in the core plugin — they're defined in add-on plugins. The `method_exists()` check means they only execute when the add-on is installed. These are still in the nopriv allowlist and need auditing in each add-on separately.
5. **Commented-out nonce check regression:** `jobapply()` in `modules/jobapply/model.php:787-790` has nonce verification code present but **commented out** (`// $wpjobportal_nonce = ...`). This is a regression pattern distinct from "never had a nonce" — always check for commented-out security code, not just missing code. Grep: `grep -rn '//.*wp_verify_nonce\|//.*check_ajax_referer' --include="*.php" <plugin_path>`
6. **Custom request sanitization layer:** Plugins may wrap `$_POST`/`$_GET` in a custom class (e.g., `WPJOBPORTALrequest::getVar()`). The scalar path uses `sanitize_text_field()` but the array path uses `filter_var_array(FILTER_DEFAULT)` which does NOT escape SQL. Always read the custom request class to understand what sanitization is actually applied, especially for array inputs.
7. **Functions in the allowlist that don't exist in the current codebase** are a dead end for auditing — note them as "add-on only, not auditable from core" and move on. The `method_exists()` gate prevents them from executing without the add-on installed.

**Confirmed example:** wp-job-portal v2.5.9 (666K installs) — `includes/ajax.php:19-69` dispatches to ~75 allowed functions across module models. `jobapply()` has commented-out nonce, `getEmailFieldsJobManager()` has no nonce at all. Both are callable by unauthenticated users but impact is limited (job application creation, read-only HTML). See `references/wp-job-portal-dynamic-dispatch-audit.md`.

## Pitfalls

- **Notion API PATCH markdown changed (2026-03-11).** Use `{"type":"replace_content","replace_content":{"new_str":"..."}}`, not `{"markdown":"..."}`. See `references/patchstack-submission-workflow.md` Step 10.
- **Upload URL predictability.** Trace URL from `define()`→`wp_upload_dir()`→`$_POST`→filename. If hardcoded base + attacker-controlled folder+filename, URL is predictable without response. See `references/cf7-drag-drop-file-upload-phtm-bypass.md`.
- **Dynamic model dispatch: same function name in different modules has different security.**
- **Commented-out nonce checks are a regression, not "missing nonce."** Always grep for commented-out `wp_verify_nonce` / `check_ajax_referer` lines inside handler functions — the code was there and was removed, indicating a deliberate change or accidental regression. Confirmed: wp-job-portal `jobapply()` at `modules/jobapply/model.php:787-790`.
- **AJAX vs REST handler divergence (WP Full Stripe pattern).** When a plugin registers BOTH `wp_ajax_nopriv_X` AND a `register_rest_route` for the same operation (e.g., cancel subscription), the REST handler often gets proper authorization (ownership check → 403) while the AJAX handler is forgotten. Always diff the two implementations when both exist — compare how each validates resource ownership. The AJAX handler authenticates the session but may not authorize the specific resource access.
- **Don't assume nopriv registration = exploitable.** Many plugins register nopriv handlers but the callback has proper nonce/capability/signature checks. Always trace the callback.
- **Don't miss the default parameter value.** A `register($action, $callback, $public = true)` method means every caller without an explicit `false` is nopriv. Grep for callers and check each one.
- **Don't confuse `is_admin()` with authentication.** `is_admin()` returns true for AJAX requests too (`DOING_AJAX`). It checks if the request is to the admin area, not if the user is logged in.
- **Don't skip the query builder.** Many modern plugins use a custom Query builder class. Verify it calls `$wpdb->prepare()` before `$wpdb->query()`. The builder may accumulate values in a `$valuesToPrepare` array and prepare them at execution time.
- **Don't report `$wpdb->query` with `$wpdb->prefix` interpolation as SQLi.** `$wpdb->prefix` is a server-side constant, not user input.
- **Don't forget REST API routes.** The `permission_callback` is the primary auth gate. A missing or `__return_true` callback means unauthenticated access.
- **Check base class defaults.** If a base REST API class has `permissionCallback() { return true; }`, any subclass that doesn't override it is unauthenticated.
- **`maybe_unserialize()` on option data is NOT a vulnerability** unless an attacker can control the option value through a separate write path.
- **Magic quotes make `$_POST`-based SQLi unexploitable via HTTP.** A `wp eval` PoC showing SLEEP(5) does NOT prove HTTP exploitability. Only REST API or `wp_unslash()` paths bypass magic quotes. Always verify with `curl`.
- **`is_array()` double-gate trap (MetForm pattern).** Some plugins gate BOTH validation AND upload on `is_array($file['name'])`. Single-file uploads (string `name`) bypass validation BUT also bypass the upload function — the file is never saved. Check both the validation function AND the upload function for `is_array()` gates.
- **Unreachable SQLi via pre-validation (Contest Gallery pattern).** If a prepared query at line N returns results required to reach an unprepared query at line N+50, the attacker can't inject SQL because the injection payload won't match any real database row. Trace the full code path, not just the vulnerable line.
- **REST API `ALLMETHODS` + `__return_true` base class (MetForm pattern).** A base REST API class that sets `'methods' => WP_REST_Server::ALLMETHODS` and `'permission_callback' => '__return_true'` makes ALL subclass routes public. The action method is determined by `strtolower($request->get_method()) . '_' . $request['action']` — so POST to `/entries/insert/<id>` calls `post_insert()`.
- **Nonces output in page HTML are available to unauthenticated users.** If a plugin enqueues a script with `wp_localize_script()` containing a nonce, any visitor can extract it from the page source. This is a valid attack path, not a blocker.
- **Stored XSS on shortcode-only pages may not be "site-wide" enough for Patchstack.** If the XSS only renders on pages where the admin explicitly placed a shortcode (e.g., `[chat]`), and the admin settings page uses proper escaping, Patchstack may reject it as "not affecting all frontend or backend pages." Check if the plugin also registers a widget (sidebar = all pages) or if the admin panel renders the same vulnerable output. See the "Site-Wide Requirement" section above.
- **Same plugin with multiple existing CVEs for the same vuln type increases duplicate-rejection risk.** Even if the vector is different (different file, parameter, mechanism), a triager may auto-reject. Always examine the fix changeset to prove the existing CVE did NOT touch your vulnerable file. Use `references/wordpress-svn-trac-duplicate-checking.md` workflow.
- **SQL without `prepare()` where the variable was already `intval()`'d upstream is NOT exploitable.** Trace variable assignments backwards from the SQL query. If `$exam_id = intval($_REQUEST['quiz_id'])` appears before `$wpdb->get_results("WHERE exam_id=$exam_id")`, the value is an integer. This is a code smell but not a vulnerability.
- **`wp_signon()` in nopriv handlers is brute force enablement, not auth bypass.** The handler calls `wp_signon()` with user-controlled credentials and a publicly available nonce. Valid credentials are still required, but there's no rate limiting — enabling unlimited-speed brute force. The `dokan_reviews` nonce pattern (generated on every page via `wp_localize_script`) is the canonical example. Check for rate limiting, attempt counters, or CAPTCHA before reporting.
- **`sanitize_text_field()` on password input breaks authentication.** It strips HTML-like sequences (`<>`) from passwords. Users with these characters in their passwords cannot log in through the endpoint. Report as part of the brute force finding, not separately.
- **`FILTER_SANITIZE_FULL_SPECIAL_CHARS` in `filter_input_array()` is a valid XSS defense.** It HTML-entity-encodes quotes and angle brackets. Do not report stored XSS when this filter is applied to input, even if output lacks `esc_html()`.
- **React admin panels auto-escape via JSX.** Stored user-agent or other metadata in a React-rendered admin panel is NOT XSS unless the code uses `dangerouslySetInnerHTML`. Search the JS bundle for `dangerouslySetInnerHTML` before reporting.
- **Hardcoded `return true` in permission functions may be a design decision.** If a mobile app API plugin hardcodes `isPurchaseCodeVerified() { return true; }`, the endpoints are unauthenticated — but most still require app-level auth (cookie/token headers). This is intended behavior for API access, not a vulnerability. Check if endpoints still have their own auth checks before reporting.
- **Different templates in the same plugin can have different sanitization.** Newsletter Subscription Form has `select_template1.php` (raw `$_GET` in SQL — vulnerable) and `select_template2.php` (uses `sanitize_text_field` + `sanitize_email` — safe). Always check ALL template files, not just one. The vulnerable template is the one that matters.
- **$_GET SQL injection is still blocked by wp_magic_quotes() even for shortcode-rendered pages.** A shortcode like [nls_form] renders during a normal WordPress page load, so wp_magic_quotes() runs on $_GET. Raw $wpdb->get_row("WHERE email LIKE '$email'") with $email = $_GET['email'] is code-vulnerable but NOT HTTP-exploitable via GET parameters. The code is still insecure and worth reporting, but don't claim HTTP exploitability without a working curl PoC.
- **File manager plugins with nopriv frontend connectors are safe by default.** The File Manager plugin (10k installs) has a connector_front nopriv endpoint, but getGuestPermissions() returns commands=[], path='' by default — no volumes accessible, all commands disabled. Only dangerous if admin explicitly configures guest access with a writable path and too many commands. Don't report as a vulnerability unless the admin has configured insecure guest permissions.
- **Deprecated JSON API plugins use similar sanitization as modern REST.** JSON API User plugin extends the deprecated JSON API but still uses sanitize_user(), sanitize_email(), sanitize_text_field(), and nonce verification. Role is hardcoded to get_option('default_role'). update_user_meta disallows capability-related meta keys. Don't dismiss these plugins as outdated — they may still be secure.
- **REST __return_true on internal filters (not register_rest_route) is NOT a REST endpoint.** Plugins like WP Telegram use add_filter('wptelegram_p2tg_bypass_post_date_rules', '__return_true') — this is an internal WordPress filter, not a REST API permission_callback. Only register_rest_route(..., 'permission_callback' => '__return_true') creates unauthenticated REST endpoints.
- **wp-async-request nopriv handlers require a secret identifier.** Background processing libraries register wp_ajax_nopriv_<identifier> but the maybe_handle() method checks a hash of the identifier against a server-side secret. These are NOT exploitable without the secret.
- **No nonce + no storage = safe read-only handler.** WP Popups Lite `check_rules()` has no nonce and processes raw `$_POST` but only evaluates popup display rules (returns JSON, no DB write). A nopriv handler without nonce is NOT automatically vulnerable — check if it stores data that's later displayed unescaped. Read-only handlers (evaluate rules, return cached data, track analytics) are safe.
- **REST __return_true + external service signature = safe webhook.** Stripe/PayPal webhook endpoints use `__return_true` (no WP auth) but validate the service's own signature. Not exploitable unless the signature secret is leaked.
- **Rate limiting as nonce alternative.** Fluent Booking's scheduling endpoint has no nonce but uses rate limiting + full sanitization of all fields. Acceptable for public-facing endpoints (booking, contact) where nonces break caching.
- **Domain-specific sanitization for structured data.** Open User Map stores GeoJSON with `wp_unslash()` (no text sanitize) but validates via `sanitize_location_geometry()` which enforces JSON structure, casts coords to float, validates lat/lng bounds. Stronger than `sanitize_text_field()` for structured data.
- **CVE already fixed by developer = not a new finding.** wpzoom-portfolio had a reflected XSS via `posts_data.class` in `load_more_items()`. Developer fixed it with `unset($data['total'], $data['class'])` + regex validation. Always check if a suspicious pattern was already addressed before reporting.
- **Nonce faucet pattern: nopriv endpoint issuing nonces is by design, not a vuln.** When a plugin has a dedicated nopriv endpoint that issues nonces to unauthenticated users (e.g., `aipkit_get_frontend_chat_nonce`), and other nopriv handlers verify that nonce, the nonce check is a CSRF defense, not an auth gate. The handlers ARE reachable by unauthenticated users by design. Focus on the handler's data logic, not the nonce. Do not report "nonce is available to unauthenticated users" as a finding — it's intended behavior for guest-access features (chatbots, AI forms).
- **Pro/addon handler not in free codebase = audit limitation, not a finding.** When a nopriv hook is registered conditionally (`if class_exists(...)`) and the handler class is in a Pro addon not included in the free version, you cannot audit the server-side validation from the free code. Check equivalent free-version handlers for validation patterns, check client-side JS for allowed types (bypassable, but informational), and report the limitation. Do NOT assume the Pro handler is vulnerable or safe without seeing its code.
- **WooCommerce `WC()->session` session IDs are server-generated, not user-controlled.** SQL queries using session IDs from `WC()->session->get()` (e.g., `WHERE session_id='$session_id'`) are NOT injectable even without `prepare()` — the session ID is a server-generated hash, not from user input. Always trace where the session ID originates.
- **Nonce created only in `admin_enqueue_scripts` is unreachable by nopriv users.** If a plugin registers `wp_ajax_nopriv_X` but only creates the nonce during `admin_enqueue_scripts` (admin context), unauthenticated frontend visitors cannot obtain the nonce. The nopriv handler is effectively dead code from an unauthenticated attack perspective. Don't waste time tracing it — note it as "nonce not obtainable by nopriv users" and move on.
- **Authenticated BAC: nonce-only protection with NO capability check (Supsystic pattern).** A pattern found in the Supsystic plugin family: ALL AJAX handlers are registered via a single `wp_ajax_<menu_slug>` action (not individual `wp_ajax_<action>` registrations). The handler dispatches to any module/action based on a `route[module]` + `route[action]` POST parameter. The ONLY authorization check is `_checkNonce()` which calls `wp_verify_nonce($nonce, 'dtgs_nonce')` — a CSRF token, NOT a capability check. There is zero `current_user_can()` / `manage_options()` anywhere in any controller. This means: (1) Any logged-in user with a valid `dtgs_nonce` can call ANY AJAX action (create/delete tables, modify settings, update_option). (2) The `dtgs_nonce` is enqueued only for admins or users with roles in the plugin's `access_roles` setting. (3) If `access_roles` includes `subscriber` (configurable, especially in PRO), subscribers get the nonce and can perform all admin operations. (4) The `saveSettingsAction` in the Settings controller can modify `access_roles` itself — potential privilege escalation. (5) At least one action (`sendMailAction` in the Overview controller) has NO nonce check at all — exploitable by any authenticated user. This is distinct from the "nopriv settings modification" pattern because the handlers are registered as `wp_ajax_` (authenticated only), not `wp_ajax_nopriv_`. The vulnerability is BAC at the authenticated level (subscriber→admin operations), not unauthenticated access. See `references/supsystic-nonce-only-bac-audit.md`.
- **`wp_json_encode()` AJAX responses prevent XSS.** Handlers that return `echo wp_json_encode($response_data); die();` are safe from XSS even if `$response_data` contains user-controlled strings. JSON encoding escapes `<`, `>`, and quotes. The XSS risk is only on the client-side if JS uses `innerHTML`/`dangerouslySetInnerHTML` to render the response.
- **SSRF in AI plugin API calls: check if endpoint URL comes from admin settings or user input.** AI plugins (chatbots, content generators) make outbound API calls to provider endpoints. The URL is almost always constructed from `get_option()` (admin-configured `base_url`), not from user POST/GET input. User-supplied prompts/queries go into the request body, not the URL. Do not report SSRF unless user input directly controls the outbound URL.
- **Guest session IDOR with crypto-random UUIDs is likely not Patchstack-qualifying.** When a plugin uses a client-generated UUID (`crypto.getRandomValues`) as the session identifier for guest conversations, and the UUID is required to access conversation history, an attacker who knows the UUID can access another guest's data. However, the UUID keyspace is 2^122, making brute-force impractical. This is a weak design pattern but likely does not meet Patchstack's vulnerability threshold (no enumeration vector, no sequential IDs).
- **DB-internal values in unprepared SQL are NOT injectable.** When a query like `SELECT * FROM table WHERE id = ` . $lastid[0]['MAX(id)'] uses a value from a prior `$wpdb->get_results('SELECT MAX(id) FROM table')` call, the interpolated value is a database-internal integer — not user input. Always trace the source of the interpolated variable backwards. If it originates from a prior DB query (SELECT MAX, COUNT, LAST_INSERT_ID, etc.) with no user input, the unprepared SQL is a code smell but NOT exploitable.
- **Unescaped output from external API responses is NOT exploitable XSS.** When a handler echoes `$response['description']` from an HTTP API call to a third-party service (e.g., `smsalert.co.in`) without `esc_html()`, it's a code quality issue but not exploitable — the attacker cannot control the API response content. This is distinct from unescaped output of direct user input. Verify that all inputs sent TO the API are sanitized (e.g., `sanitize_text_field` strips HTML tags), so even if the API reflects input, no HTML can survive the round trip.
- **`$wpdb->prepare('%s', $wpdb->update(...))` is a misuse pattern, not a vulnerability.** Some plugins wrap `$wpdb->update()` (which internally calls `prepare()`) in an outer `$wpdb->prepare('%s', ...)`. The outer `prepare()` receives the integer row count from `$wpdb->update()`, not any SQL — it's meaningless but harmless. Don't confuse this with `$wpdb->update()` being unprotected.
- **Dead nopriv handlers never called by plugin's own JS.** Some plugins register `wp_ajax_nopriv_X` but the plugin's JavaScript never makes an AJAX call to action `X`. An attacker could manually call it via `admin-ajax.php`, but if the handler only does low-impact operations (e.g., `update_option` with a timestamp), it's not a Patchstack-accepted vulnerability. Check the plugin's JS files to see if the action is actually used.
- **Custom phone sanitization via `preg_replace('/[^0-9]/', '', $no)` is equivalent to `intval()` for SQLi.** Some plugins implement their own phone number cleaning that strips all non-digit characters. The result contains only numeric characters — safe for SQL even without `prepare()`. Recognize this pattern when tracing data flow through custom sanitization functions.
- **Guest Order IDOR via `get_current_user_id() === $order->get_user_id()`.** WooCommerce plugins with nopriv AJAX handlers often check order ownership with `if ( get_current_user_id() === $user_id || array_intersect( $allowed_roles, $user->roles ) )`. For **guest orders** (placed without an account), `$order->get_user_id()` returns `0`. For unauthenticated visitors, `get_current_user_id()` also returns `0`. Therefore `0 === 0` evaluates to `true`, granting full access to any guest order's data. This enables unauthenticated IDOR on: order message read/write, file upload to return requests, return request cancellation, and any other order-scoped operation. This is a CRITICAL pattern — check every nopriv handler that takes an `order_id` parameter and verify what `get_user_id()` returns for guest orders. See `references/woo-refund-exchange-guest-order-idor.md`.
- **Nopriv settings modification via frontend-exposed nonce (no capability check).** When a nopriv AJAX handler calls `check_ajax_referer()` but has NO `current_user_can()` check, and the nonce is exposed to unauthenticated users via `wp_localize_script()` on a publicly accessible page, an attacker can modify plugin settings (enable/disable features, activate licenses) without authentication. The nonce is a CSRF token, NOT an auth gate — it's available to any visitor who loads the page. This is distinct from the "nonce faucet" pattern (which is by design for guest-access features) — here the handler modifies site configuration (`update_option()`), which should require admin capability. Always check: (1) is the handler registered as nopriv? (2) does it call `update_option()` or similar? (3) is there a `current_user_can()` check? (4) is the nonce exposed on a public page? If all four → critical privilege escalation. See `references/woo-refund-exchange-guest-order-idor.md`.
- **Plugin auto-creates nonce-exposing pages on activation.** Some plugins call `wp_insert_post()` during `register_activation_hook` to create pages automatically (e.g., "View Order Message", "Refund Request Form"). If these auto-created pages load a script containing `wp_localize_script()` with a nonce, the nonce is exposed by default on EVERY install — no admin configuration needed. Always check the activator class (e.g., `class-{plugin}-activator.php`) for `wp_insert_post()` calls and cross-reference the created page IDs with `wp_enqueue_scripts` conditions. This means the vulnerability is exploitable on every site by default, not just misconfigured ones. Confirmed example: woo-refund-and-exchange-lite `class-woo-refund-and-exchange-lite-activator.php:97-110` auto-creates the "View Order Messages" page which loads the `wps_rma_react_nonce` (for action `ajax-nonce`) via `is_page($wps_rma_view_order_msg_page_id)`.
- **Cart manipulation via nopriv handlers with zero nonce AND zero capability check.** Some WooCommerce plugins register checkout/cart nopriv AJAX handlers that modify `WC()->cart` contents (add products, change quantities, remove items) with NO nonce verification and NO capability check. Unlike the "no nonce + read-only = safe" pattern (WP Popups Lite), these handlers perform state-changing operations on the cart session. While exploitation requires an active cart session (the attacker and victim must share a session, limiting remote attack feasibility), any unauthenticated user who can load a checkout page can manipulate the cart. Report as broken access control / missing CSRF protection.
- **Gift card balance check with nonce-only protection IS exploitable.** A nopriv handler that checks `check_ajax_referer()` with a nonce exposed via `wp_localize_script()` on public pages, and then reveals gift card balance when email + coupon code match, IS exploitable for information disclosure. The nonce is obtainable by any visitor. An attacker who knows a gift card code and can guess/obtain the recipient email can check balances without authentication. This enables balance enumeration and is Patchstack-reportable as broken access control / information disclosure. The earlier assessment of woo-gift-cards-lite as "safe" was incorrect for the balance check handler.
- **Different nonces for different actions load on different pages.** A plugin may create multiple nonces via `wp_localize_script()` but enqueue them on DIFFERENT pages. Example: woo-refund-and-exchange-lite creates `wps_rma_nonce` (for `wps_rma_ajax_security`) on My Account / order pages, but `wps_rma_react_nonce` (for `ajax-nonce`) is ONLY on the "View Order Message" page (enqueued in a separate `is_page($wps_rma_view_order_msg_page_id)` block). If your PoC returns `-1` (nonce verification failed), you extracted the wrong nonce — trace which `wp_localize_script` call creates the nonce matching the handler's `check_ajax_referer()` action name, then find which page-load condition enqueues that script. The nonce name in JS (`wps_rma_react_nonce`) maps to the `check_ajax_referer()` action (`ajax-nonce`), NOT to the JS variable name itself.
- **Live WP lab PoC verification when lab is the local machine.** When the WordPress lab IP is the local machine's IP (check with `hostname -I`), you can: (1) read DB credentials directly from `/var/www/html/wordpress/wp-config.php`, (2) use `wp-cli` (`wp user update 1 --user_pass=newpass --path=/var/www/html/wordpress --allow-root`) to reset the admin password, (3) install plugins via `wp plugin install {slug} --activate --path=... --allow-root`, (4) create missing WooCommerce pages via `wp post create --post_type=page --post_title="My Account" --post_content="[woocommerce_my_account]" --post_status=publish ...` and set options `woocommerce_myaccount_page_id`, `woocommerce_shop_page_id`, `woocommerce_cart_page_id`, `woocommerce_checkout_page_id`. WooCommerce must be installed before dependent plugins will activate.
- **PHP backslash in single-quoted strings breaks when patched via find-replace tools.** When fixing `str_getcsv()` deprecation by adding the `$escape` parameter, writing `'\\'` (escaped backslash in single quotes) can get double-escaped to `'\\\\'` by patch tools, causing a PHP Parse Error. Use `chr(92)` instead of a string literal backslash: `str_getcsv($str, ',', chr(92))`. This is a tool-usage pattern, not a PHP pattern — the fix is correct in any context but the tool delivery matters.
- **Pie Register custom login replaces wp-login.php.** When the WP lab uses the Pie Register plugin, `wp-login.php` redirects to a custom `/login/` page. Standard curl login to `wp-login.php` will NOT work. The custom form requires a `piereg_login_form_nonce` field (extract from the login page HTML). XML-RPC (`/xmlrpc.php`) may still work for credential brute-forcing but Pie Register doesn't affect XML-RPC — try `wp.getUsersBlogs` method to verify credentials.
- **`__return_true` + no internal auth check in callback = IDOR.** When a REST route uses `__return_true` as `permission_callback` and the callback function does NOT contain its own `current_user_can()` or `is_user_logged_in()` check, the endpoint is fully unauthenticated. If it accepts a resource ID (e.g., `GET /customers/(?P<id>[\d]+)`), any unauthenticated user can fetch arbitrary resources by sequential ID enumeration. This is distinct from a route where the callback DOES check capabilities internally (e.g., `get_items()` checking `manage_salon` and returning 403). Always read BOTH the `permission_callback` AND the first lines of the callback function — a `__return_true` permission with an internal `current_user_can()` is gated; a `__return_true` permission with no internal check is wide open. Confirmed example: salon-booking-system `Customers_Controller::get_item()` (unauthenticated IDOR) vs `get_items()` (internal `manage_salon` check).
- **HPOS test orders need BOTH `wp_wc_orders` AND `wp_posts` entries.** When creating a guest order via direct SQL for IDOR/exploit testing, `wc_get_order()` may return `false` if only `wp_wc_orders` is populated — it still checks CPT (wp_posts) for compatibility. Always insert into BOTH `wp_wc_orders` (id, status, type, total_amount, currency, customer_id=0, billing_email) AND `wp_posts` (ID matching, post_type='shop_order', post_status='wc-completed'), plus `wp_postmeta` (_customer_user='0', _billing_email, _order_total). See `references/woo-refund-exchange-guest-order-idor.md` for the full SQL template.
- **`mysql -e "..."` strips double quotes from PHP serialized data.** When using `mysql -e "INSERT ... 'a:1:{s:8:\"products\";...}'"` from the shell, the double quotes inside the serialized string get stripped (s:8:"products" → s:8:products). PHP's `unserialize()` then fails silently. **Always write SQL containing PHP serialized data to a temp file, then use `mysql < file.sql`** — file-based approach preserves quotes correctly. This is critical when injecting test return-request meta for cancel-refund exploit verification.
- **Fatal error DoS in nopriv handlers that call methods on `wc_get_order()` false.** When a nopriv handler does `$order = wc_get_order($order_id)` (returns `false` for invalid IDs) then calls `$order->get_billing_email()` BEFORE the ownership check, PHP throws a fatal error (`<p>There has been a critical error on this website.</p>`). This is a per-request DoS (site keeps working for other requests). Not Patchstack-worthy alone, but confirms the nonce passed and the handler is reachable. The code pattern: `$order = wc_get_order($id); if ('shop_manager' === $type) { $to = $order->get_billing_email(); }` — the method call on `false` crashes before any user check.
- **Action name regex extraction can include leading underscores (Aug 2026).** When parsing `wp_ajax_nopriv_` registrations with regex like `r"wp_ajax_nopriv_[\"']([^\"']+)[\"']"`, the captured action name is correct. But when using a broader regex like `r"nopriv['\"]?\s*\.?\s*['\"]?([^'\"]+)"`, the captured group may include a leading underscore (e.g., `_submit_nex_form` instead of `submit_nex_form`). This causes PoC curl requests to use the wrong `action=` parameter and return `0` (handler not found). Always verify extracted action names against the actual `add_action()` call — the action parameter in the `wp_ajax_nopriv_` hook name is the string AFTER `wp_ajax_nopriv_` with no leading separator.
- **WordPress nonces expire — stale nonces cause false negatives in PoC testing (Aug 2026).** When testing multiple upload/PoC calls in sequence, a nonce generated via `wp eval wp_create_nonce()` at the start of a test session may expire before later curl calls. A PoC that returns `{"success":false,"data":{"error":"Sorry, you are not allowed to upload this file type."}}` might be due to an expired nonce, not a file type restriction. Always generate a fresh nonce immediately before each PoC attempt. The error message difference is subtle: nonce failure returns `-1` or `Security check Failed`, while file type rejection returns `Sorry, you are not allowed to upload this file type.`
- **`wp_handle_upload()` MIME restrictions confirmed (Aug 2026).** `wp_handle_upload()` with `test_form => false` still validates file types via `wp_check_filetype_and_ext()` against `get_allowed_mime_types()`. Confirmed accepted: txt, png, jpg, csv, pdf, zip, doc, mp3, mp4. Confirmed blocked: php, html, svg, css, xml. A polyglot file (HTML content with .jpg extension) is also blocked because `wp_check_filetype_and_ext()` checks file content via `finfo` in addition to extension. For unauth file upload findings, the impact is limited to allowed MIME types — no RCE, but disk abuse, malware hosting, and attachment spam are possible. Additional Aug 2026 pitfalls (glob auto-registration, SSRF fallback bypass, custom maybe_unserialize): see `references/wp-all-import-v4.1.1-audit.md`.

### Nonce Faucet Pattern (Pro/Addon Conditional Registration)

Some plugins register nopriv handlers that are intentionally available to unauthenticated users by design. The plugin provides a dedicated nopriv endpoint that issues fresh nonces to anonymous visitors — a "nonce faucet." This is common in chatbot/AI plugins where guest access is a core feature.

**Pattern:** `aipkit_get_frontend_chat_nonce` endpoint (nopriv) issues `wp_create_nonce('aipkit_frontend_chat_nonce')` to any caller. Subsequent nopriv handlers verify this nonce via `check_frontend_permissions()`. The nonce is a CSRF token, NOT an authentication token — it proves the request came from a page that loaded the plugin's JS, not that the user is authenticated.

**Audit implication:** When you see a nopriv handler with a nonce check AND a separate nopriv endpoint that issues that nonce, the nonce check is a CSRF defense, not an auth gate. The handler IS reachable by unauthenticated users by design. Focus on whether the handler's actual logic (data access, file operations, SQL) is safe, not on the nonce.

**Confirmed example:** GPT3 AI Content Generator (AI Power) v2.4.62 — 19 nopriv handlers all use `check_frontend_permissions()` which verifies a nonce obtainable via the dedicated `aipkit_get_frontend_chat_nonce` nopriv endpoint. See `references/woocommerce-jetpack-and-gpt3-ai-audit.md`.

### Pro/Addon Conditional Handler Registration (Code Not in Free Version)

Some plugins register nopriv hooks conditionally — only when a Pro addon class exists AND a license/plan check passes. The handler implementation lives in the Pro addon, which is NOT included in the free plugin's source code.

**Pattern:**
```php
if ($chat_file_upload_ajax_dispatcher && method_exists($chat_file_upload_ajax_dispatcher, 'ajax_handle_frontend_file_upload')) {
    add_action('wp_ajax_nopriv_aipkit_frontend_chat_upload_file', [$chat_file_upload_ajax_dispatcher, 'ajax_handle_frontend_file_upload']);
}
```
Where `ChatFileUploadAjaxDispatcher` is in `WPAICG\Lib\Chat\Frontend\Ajax\` — a Pro namespace not shipped in the free version.

**Audit implication:** You can identify the hook registration and the class name, but CANNOT audit the handler's server-side validation from the free codebase alone. In this case:
1. Check if there's an equivalent handler in the free version with similar functionality (e.g., the AI Form file upload handler `aipkit_ai_form_upload_and_parse_file` uses `AIPKit_Upload_Utils::validate_upload_file()` — a robust server-side validation)
2. Check client-side JS bundles for allowed file types (but note: client-side validation is bypassable and NOT a security control)
3. Report the inability to audit the Pro handler as a limitation, not a finding

**Confirmed example:** GPT3 AI Content Generator — `aipkit_frontend_chat_upload_file` handler is in Pro addon (not in codebase). The free AI Form upload handler demonstrates proper validation with MIME whitelist, extension check, content-type detection. See `references/woocommerce-jetpack-and-gpt3-ai-audit.md`.

### WooCommerce Plugin Sanitization Patterns

WooCommerce plugins commonly use WooCommerce-specific sanitization and output functions that affect vulnerability assessment:

| Pattern | SQLi Protection? | XSS Protection? | Notes |
|---------|-----------------|-----------------|-------|
| `wc_clean()` (= `sanitize_text_field`) | NO | YES (strips tags) | Does NOT strip quotes — not a SQLi defense |
| `wc_get_product($id)` | N/A | N/A | Returns product object or `false` for invalid IDs — safe for ID handling |
| `WC()->cart->add_to_cart()` | YES | N/A | WooCommerce handles validation internally |
| `wc_price()` | N/A | YES | Returns HTML-formatted price, safe for output |
| `wp_json_encode()` response | N/A | YES | JSON-encoding prevents XSS in AJAX responses |
| `wp_kses_post(wc_price())` | N/A | YES | Double-safe for price HTML output |

**Key insight:** WooCommerce AJAX handlers that return `wp_json_encode($response_data)` are safe from XSS even if the response data contains user-controlled strings — JSON encoding escapes `<`, `>`, and quotes. The risk is only when the JSON is consumed by client-side JS that uses `innerHTML` or `dangerouslySetInnerHTML` without escaping.

### Session ID from WC()->session (Not User-Controlled)

WooCommerce cart abandonment plugins often use `WC()->session->get('session_id')` to identify carts. This session ID is server-generated (e.g., `md5(uniqid(wp_rand(), true))`), NOT user-controlled. SQL queries using this session ID (even without `prepare()`) are NOT injectable.

**Confirmed example:** WooCommerce Jetpack `class-wcj-cart-abandonment.php:425`: `UPDATE ... WHERE session_id='$session_id'` — `$session_id` comes from `WC()->session->get('wcj_ca_session_id')`, server-generated. Not exploitable.

### Nonce Exposed Only via admin_enqueue_scripts (Nopriv Users Can't Obtain)

When a plugin creates a nonce in `wp_localize_script()` called during `admin_enqueue_scripts` (not `wp_enqueue_scripts`), the nonce is only in admin page HTML. Unauthenticated frontend visitors cannot obtain it. The nopriv handler registration exists but is effectively unreachable.

**Confirmed example:** WooCommerce Jetpack `class-wcj-price-by-user-role.php:83` registers `wp_ajax_nopriv_woocommerce_get_customer` but the nonce `wcj-order-users` is only created in `enqueue_admin_script()` (admin context). Nopriv users can't get the nonce → handler is dead code from unauthenticated perspective.

## Tool Tips

- Prefer `search_files` (ripgrep-backed) for content searches. On large plugins (500+ PHP files) it may time out — fall back to `grep -rn` via `terminal` with `--include="*.php"`.
- Use `execute_code` (Python) for batch analysis: iterate over PHP files, apply regex patterns for SQL injection detection, and collect findings with file:line context.
- For large plugins (>500 PHP files), first identify the nopriv surface, then only trace those specific callback files — don't read every file.

## WP Lab Setup for PoC Verification

### When the Lab IS the Local Machine

If `hostname -I` returns the lab IP (e.g., 10.10.16.102), you have direct filesystem access:

```bash
# 1. Get DB credentials
grep -E "DB_|USER|PASS|HOST" /var/www/html/wordpress/wp-config.php

# 2. Reset admin password (if forgotten)
wp user update 1 --user_pass=admin --path=/var/www/html/wordpress --allow-root

# 3. Install WooCommerce (required for WooCommerce-dependent plugins)
wp plugin install woocommerce --activate --path=/var/www/html/wordpress --allow-root

# 4. Install target plugin
wp plugin install {slug} --activate --path=/var/www/html/wordpress --allow-root

# 5. Create missing WooCommerce pages (if /my-account/ returns 404)
wp post create --post_type=page --post_title="My Account" --post_status=publish \
  --post_content="[woocommerce_my_account]" --path=/var/www/html/wordpress --allow-root
# Repeat for Shop, Cart, Checkout pages, then set options:
# woocommerce_myaccount_page_id, woocommerce_shop_page_id, etc.
```

### Pie Register Custom Login

When the WP lab uses Pie Register, `wp-login.php` redirects to `/login/`. The custom form needs `piereg_login_form_nonce` (extract from login page HTML). XML-RPC (`/xmlrpc.php`) bypasses Pie Register — use `wp.getUsersBlogs` method to verify credentials.

### Nonce Page-Location Pitfall

A plugin may expose different nonces on different pages. If a PoC returns `-1`, you extracted the nonce from the wrong page. Match the `check_ajax_referer()` action name (first argument) to the `wp_create_nonce()` call, then trace which `wp_enqueue_scripts` conditional loads that specific nonce. The JS variable name (`wps_rma_react_nonce`) is irrelevant — only the `wp_create_nonce()` action string (`ajax-nonce`) matters.

## Making the WP Lab Externally Accessible

When the user needs to test the WP lab from another device on the network:

```bash
# Apache already listens on *:80 by default — no config change needed.
# But WordPress siteurl/home defaults to http://localhost, causing IP-based access to redirect.
wp option update siteurl http://<MACHINE_IP> --path=/var/www/html/wordpress --allow-root
wp option update home http://<MACHINE_IP> --path=/var/www/html/wordpress --allow-root
```

Verify with `curl -sL http://<MACHINE_IP>/<page-slug>/` — check for the expected content and no 301 redirect to localhost.

## Full WP Lab Rebuild (Teardown + Reinstall)

When the lab needs a fresh WordPress install (corrupted state, wrong plugins, user request):

```bash
# 1. Stop services
sudo systemctl stop apache2 && sudo systemctl disable apache2
sudo systemctl stop mariadb && sudo systemctl disable mariadb

# 2. Drop DB + user
sudo mysql -e "DROP DATABASE IF EXISTS wordpress; DROP USER IF EXISTS 'wpuser'@'localhost';"

# 3. Remove files + Apache config
sudo rm -rf /var/www/html/wordpress/
sudo rm -f /etc/apache2/sites-enabled/wordpress.conf /etc/apache2/sites-available/wordpress.conf

# 4. Restart services + create DB
sudo systemctl start mariadb && sudo systemctl enable mariadb
sudo systemctl start apache2 && sudo systemctl enable apache2
sudo mysql -e "CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
sudo mysql -e "CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'WpP@ssw0rd!2026'; GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost'; FLUSH PRIVILEGES;"

# 5. Download + extract WordPress — DOWNLOAD DIRECTLY TO /var/www/html, NOT /tmp
# (tmpfs → ext4 cross-device mv/cp fails silently with "inter-device move failed")
sudo curl -s -o /tmp/wp-latest.zip https://wordpress.org/latest.zip
sudo unzip -q -o /tmp/wp-latest.zip -d /var/www/html/
sudo chown -R www-data:www-data /var/www/html/wordpress/

# 6. Configure wp-config.php — use sudo tee (Python can't write to www-data-owned files)
SALTS=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
sudo tee /var/www/html/wordpress/wp-config.php > /dev/null << WPCONF
<?php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'WpP@ssw0rd!2026' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', 'utf8mb4_unicode_ci' );
${SALTS}
define( 'WP_HOME', 'http://<MACHINE_IP>' );
define( 'WP_SITEURL', 'http://<MACHINE_IP>' );
\$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
WPCONF
sudo chown www-data:www-data /var/www/html/wordpress/wp-config.php

# 7. Apache vhost with AllowOverride All (required for WP permalinks)
sudo tee /etc/apache2/sites-available/wordpress.conf > /dev/null << 'APACHECONF'
<VirtualHost *:80>
    DocumentRoot /var/www/html/wordpress
    <Directory /var/www/html/wordpress>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
APACHECONF
sudo a2enmod rewrite && sudo a2dissite default && sudo a2ensite wordpress && sudo systemctl restart apache2

# 8. Run install + set permalinks
wp core install --url="http://<MACHINE_IP>" --title="CVE Lab" --admin_user=admin --admin_password=admin --admin_email=admin@cvelab.local --path=/var/www/html/wordpress --allow-root
wp rewrite structure '/%postname%/' --path=/var/www/html/wordpress --allow-root
wp rewrite flush --path=/var/www/html/wordpress --allow-root

# 9. Install plugins — FIX PERMISSIONS FIRST (wp-cli as root can't write to www-data dirs)
sudo chmod -R 777 /var/www/html/wordpress/wp-content/
wp plugin install woocommerce --activate --path=/var/www/html/wordpress --allow-root
wp plugin install woo-refund-and-exchange-lite --activate --path=/var/www/html/wordpress --allow-root
sudo chown -R www-data:www-data /var/www/html/wordpress/

# 10. Create WooCommerce pages (must be AFTER WooCommerce is activated)
wp post create --post_type=page --post_title="My Account" --post_status=publish --post_content="[woocommerce_my_account]" --path=... --allow-root
# Repeat for Shop, Cart, Checkout, View Order Message
# Set options: woocommerce_myaccount_page_id, woocommerce_shop_page_id, woocommerce_cart_page_id, woocommerce_checkout_page_id, wps_rma_view_order_msg_page_id
```

### wp-cli Plugin Install Permission Pitfall

`wp plugin install` downloads to `wp-content/upgrade/` then extracts. If wp-cli runs as root but `wp-content/` is owned by `www-data`, it gets "Could not create directory" errors. Fix: `sudo chmod -R 777 /var/www/html/wordpress/wp-content/` before install, then `sudo chown -R www-data:www-data` after. Alternatively, `sudo chown -R kali:kali` (current user) before install.

### PHP 8.1+ Deprecation Fixes for WP Plugins

When WordPress displays `Deprecated:` warnings from plugins on pages (which can interfere with PoC nonce extraction):

| Deprecation | Fix |
|---|---|
| `json_decode(null)` — Passing null to parameter #1 | `json_decode($var ?? '')` |
| `str_getcsv()` — missing `$escape` parameter | `str_getcsv($str, ',', chr(92))` — use `chr(92)` to avoid backslash escaping issues in PHP single-quoted strings. Writing `'\\'` in the patch tool can produce `'\\\\'` (double-escaped) which causes a Parse Error. |
| `str_getcsv()` with literal backslash in single quotes | Do NOT use `str_getcsv(..., '\\')` — the `\\` in single quotes is an escaped backslash, but patch tools may double-escape it. Always use `chr(92)`. |

## References

- `references/wp-statistics-audit-example.md` — Worked example: full audit of WP Statistics v14.16.10 showing the methodology applied end-to-end
- `references/mass-audit-findings-2026-08.md` — Findings from mass audit of ~170 plugins (batches 1-11) for Patchstack: which were safe, which had code-level vulns but were not HTTP-exploitable, and why (magic quotes, is_array double-gate, unreachable SQLi, preg_replace URL auto-linking XSS). Avoid re-auditing these plugins.
- `references/mass-audit-findings-batches-12-19.md` — Findings from extended mass audit of ~150 more plugins (batches 12-20): Newsletter Subscription Form SQLi (code-vulnerable, not HTTP-exploitable), MStore API `isPurchaseCodeVerified()=true` design decision, MultiVendorX `filter_input_array` sanitization, WATU intval'd SQL, File Manager default-safe guest permissions, JSON API User deprecated-but-secure, and ~145 safe plugins. Combined total: ~320 plugins scanned across all batches.
- `references/mass-audit-findings-batches-20-23.md` — Findings from extended mass audit of ~120 more plugins (batches 20-23): wpzoom-portfolio CVE already fixed, open-user-map domain-specific GeoJSON sanitization, SupportCandy/Review-Schema nonce+sanitize, Cost Calculator Builder json_decode+cleanData, Fluent Booking rate-limiting-as-nonce, Stripe webhook signature validation, WP Popups Lite no-nonce-read-only-safe. Combined total: ~440 plugins scanned across all batches.
- `references/simple-ajax-chat-xss-example.md` — Worked example: confirmed unauthenticated stored XSS in Simple Ajax Chat v20260811 via server-side preg_replace URL auto-linking. Shows the full find → verify → HTTP PoC flow including nonce extraction, hardcoded JS nonce bypass, and curl reproduction.
- `references/wordpress-svn-trac-duplicate-checking.md` — Workflow for checking if a finding duplicates an existing CVE using WordPress.org SVN Trac changesets and file revision logs. Includes the Simple Ajax Chat worked example where CVE-2026-2987 fixed only the JS file, leaving the PHP file vulnerable.
- `references/dokan-lite-nopriv-ajax-audit.md` — Worked example: Dokan Lite v5.0.12 (30k installs) unauthenticated brute force via `wp_signon()` in `wp_ajax_nopriv_dokan_login_user` with publicly available nonce and no rate limiting. Also documents the `sanitize_text_field()` on password bug and confirms 7 other nopriv handlers are secure.
- `references/wp-full-stripe-broken-access-control.md` — Worked example: WP Full Stripe Free v8.5.3 (9k installs) broken access control via AJAX vs REST handler divergence. The AJAX nopriv handler `handleSubscriptionCancellationRequest()` cancels arbitrary subscriptions without ownership validation, while the REST API `handleSubscriptionUpdateRequest()` properly checks `$subscriptionCustomerId !== $cardUpdateSession->stripeCustomerId`. Documents the "always diff AJAX vs REST implementations when both exist" pattern.
- `references/woocommerce-jetpack-and-gpt3-ai-audit.md` — Worked example: Deep audit of WooCommerce Jetpack v8.2.0 (30k installs) and GPT3 AI Content Generator v2.4.62 (10k installs). Documents: nonce faucet pattern (dedicated nopriv nonce-issuing endpoint), Pro/addon conditional handler registration (handler not in free codebase), WooCommerce sanitization patterns (`wc_clean`, `wc_price`, `wp_json_encode` response safety), session ID from `WC()->session` (server-generated, not user-controlled), nonce exposed only via `admin_enqueue_scripts` (unreachable by nopriv users), SSRF in AI API calls (endpoint URLs from admin settings, not user input), and guest session IDOR (weak pattern, likely not Patchstack-qualifying).
- `references/sms-alert-nopriv-ajax-audit.md` — Worked example: Deep audit of SMS Alert v3.9.8 (3k installs) — 9 nopriv handlers, 49 unprepared SQL queries, all safe. Documents: DB-internal values (SELECT MAX(id) results) in unprepared SQL as NOT injectable, unescaped output from external API responses as NOT exploitable XSS, `$wpdb->prepare('%s', $wpdb->update(...))` misuse pattern, dead nopriv handlers never called by plugin's own JS, `checkPhoneNos()` custom sanitization (digits-only via preg_replace), and hardcoded encryption key not independently exploitable when hash requires DB values.
- `references/woo-refund-exchange-guest-order-idor.md` — Worked example: Deep audit of 3 WooCommerce plugins (WPFunnels, Woo Gift Cards Lite, Woo Refund and Exchange Lite) for Patchstack. Documents: (1) guest order IDOR via `get_current_user_id() === $order->get_user_id()` where `0 === 0` grants access to all guest orders, (2) nopriv settings modification via frontend-exposed nonce with no capability check, (3) cart manipulation via nopriv handlers with zero nonce AND zero capability check, (4) gift card balance check with nonce-only protection exploitable for info disclosure, (5) full 7-step verified exploit chain with DB-level proof (settings mod, IDOR, email injection, refund cancellation, file upload, onboarding skip), (6) HPOS test order creation via direct SQL (requires BOTH wp_wc_orders AND wp_posts entries), (7) `mysql -e` quote-stripping pitfall for PHP serialized data.
- `references/patchstack-submission-workflow.md` — End-to-end Patchstack submission workflow: plugin discovery, attack surface scanning, nonce exposure analysis, capability check patterns, REST API SQLi (magic quotes bypass), version verification, CVE duplicate checking, rule compliance checklist, PoC format, and Notion upload. Includes common vulnerability patterns (nopriv+exposed nonce, guest order IDOR, REST SQLi, non-guessable ID rejection) and session examples from ~400 WooCommerce plugin audits.
- `references/woocommerce-mass-audit-400-plugins.md` — Final results from mass audit of ~400 WooCommerce plugins (2026-08-12): 1 submittable finding (woo-refund-and-exchange-lite unauth settings modification), 5 rejected by Patchstack rules (Rule 79 non-guessable ID, Rule 58 duplicate CVE, Rule 54 fixed-in-latest), 25+ plugins confirmed safe with reasons. Includes key lessons on REST SQLi rarity, nopriv settings modification reliability, and guest order IDOR CVE saturation.
- `references/rest-api-return-true-deep-audit.md` — Deep targeted REST API `__return_true` SQLi audit of 4 booking plugins (wholesalex, webba-booking-lite, salon-booking-system, ecab-taxi-booking-manager). Documents: named `return true()` permission functions (not caught by `__return_true` grep), `rest_validate_request_arg` strict regex as accidental SQLi defense, `__return_true` + no internal auth check = IDOR pattern, duplicate API directories (SLB_API_Mobile vs SLB_API), and reinforces that zero exploitable REST SQLi found across 444 plugins.
- `references/batch-scan-500-plus-plugins-2026.md` — Results of 500+ plugin scan using combined popular+updated browse modes (Aug 2026). Confirmed Charitable v1.8.12 unauth file upload (nonce exposed on frontend, no cap check, `wp_handle_upload` saves allowed MIME types). Also documents: woo-product-table cart emptying (Rule 47 reject), nex-forms form spam (Rule 84 reject), wp-job-portal insufficient impact, 15+ plugins confirmed safe with reasons.
- `references/wp-job-portal-dynamic-dispatch-audit.md` — Worked example: Deep audit of wp-job-portal v2.5.9 (666K installs) dynamic model dispatch architecture. Documents: single nopriv handler dispatching to ~75 model methods via allowlist + ReflectionMethod, commented-out nonce check regression in `jobapply()`, same function name with different security across modules (`fieldordering` vs `customfield`), custom request sanitization layer (`WPJOBPORTALrequest::getVar()`), and ~30 add-on-only functions not auditable from core.
- `references/supsystic-nonce-only-bac-audit.md` — Worked example: Deep audit of Data Tables Generator by Supsystic v1.14.2 (1.6M installs). Documents the "single-handler dynamic dispatch" architecture (one `wp_ajax_<menu_slug>` registration dispatching to any controller via `route[module]` + `route[action]` POST params), nonce-only protection with zero capability checks across all controllers, `access_roles` setting enabling subscriber→admin BAC, `sendMailAction` with no nonce check at all (email header injection by any authenticated user), and ChainQueryBuilder `_sanitizeValue` not escaping quotes (latent risk, not exploitable due to upstream sanitization).
- `references/wp-all-import-v4.1.1-audit.md` — Worked example: WP All Import v4.1.1 (100K installs). Documents: (1) file-name-based auto-registration of AJAX handlers (glob pattern — third architecture alongside dynamic dispatch and single-handler dispatch), (2) custom `pmxi_maybe_unserialize` with `['allowed_classes' => false]` as safe POI defense, (3) `pmxi_is_private_ip()` SSRF protection with `fopen()`/`file_get_contents()` bypass (authenticated only), (4) session storage via `base64_encode(serialize())` read with WP core `maybe_unserialize()` (not exploitable without admin write access). All 8 AJAX handlers properly protected with nonce + cap checks.
- `scripts/exploit-nopriv-settings-modification.sh` — Reusable bash exploit template for nopriv settings modification vulnerabilities (frontend-exposed nonce, no capability check). Auto-finds nonce from public pages, sends unauthenticated POST to admin-ajax.php, reports success/failure. Customize HANDLER, NONCE_JS_VAR, and POST_PARAMS at the top of the script for your target plugin.
