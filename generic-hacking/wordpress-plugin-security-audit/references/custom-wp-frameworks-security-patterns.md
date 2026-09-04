# WordPress Custom Framework Security Patterns

When a plugin ships a custom framework in `vendor/`, security enforcement differs from standard WordPress. Check the framework before assuming routes are unprotected.

## wpfluent Framework (FluentForm and derivatives)

### REST API Protection

Routes are registered via `$router->get/post/delete()` with `withPolicy('PolicyName')`:

```php
// app/Http/Routes/api.php
$router->prefix('forms')->withPolicy('FormPolicy')->group(function ($router) {
    $router->get('/', 'FormController@index');
    $router->post('/', 'FormController@store');
});
$router->post('form-submit', 'SubmissionHandlerController@submit')->withPolicy('SubmissionPolicy');
```

The framework's `Route::register()` → `getDefaultOptions()` (Route.php:807-817) **always** sets `permission_callback`:
```php
protected function getDefaultOptions() {
    return [[
        'methods' => $this->method,
        'callback' => [$this, 'callback'],
        'permission_callback' => [$this, 'permissionCallback'],  // always set
        'args' => [],
    ]];
}
```

**Key difference from raw `register_rest_route`:** The framework enforces `permission_callback` on every route. Devs can't forget it. The `permissionCallback` resolves to the policy class method matching the controller method name (e.g., `FormPolicy::index()` gates `FormController@index`, `FormPolicy::store()` gates `FormController@store`).

### Policy Classes

Located in `app/Http/Policies/`. Each extends `Policy` and defines per-method permission checks:

```php
class FormPolicy extends Policy {
    public function verifyRequest(Request $request) {
        return Acl::hasPermission('fluentform_forms_manager', $this->resolveFormId($request));
    }
    public function index(Request $request) {
        return Acl::hasPermission('fluentform_dashboard_access', $this->resolveFormId($request));
    }
}
```

### Acl::verify() — Combined Nonce + Capability Check

```php
public static function verify($permission, $formId = null) {
    static::verifyNonce();  // wp_verify_nonce on AJAX requests
    $allowed = static::hasPermission($permission, $formId);  // current_user_can
    if (!$allowed) { wp_send_json_error(...); }
}
```

**When auditing:** `Acl::verify('capability')` = fully protected (nonce + capability). No need to trace further.

### Query Builder (wpFluent)

Uses Eloquent-like syntax: `Model::where()->get()`, `wpFluent()->table('x')->where()->get()`.

Check `selectRaw()`, `whereRaw()`, `orderByRaw()` for parameterized vs. raw string:
```php
// SAFE — parameterized:
$query->selectRaw("FLOOR(DATEDIFF(DATE(created_at), ?) / 3) as group_num", [$minDate]);
// POTENTIALLY UNSAFE — raw string interpolation:
$query->selectRaw("COUNT({$userInput}) as total");
```

### safeUnserialize() — Safe POI Pattern

```php
public static function safeUnserialize($data) {
    if (is_serialized($data)) {
        return @unserialize(trim($data), ['allowed_classes' => false]);
    }
    return $data;
}
```

`['allowed_classes' => false]` (PHP 7.0+) prevents all object instantiation during deserialization. No gadget chain can be triggered. **Do NOT report as PHP Object Injection.**

## Action Scheduler (bundled by many plugins)

Registers nopriv AJAX for async processing but always protects with nonce:
```php
// WP_Async_Request::__construct()
add_action('wp_ajax_' . $this->identifier, array($this, 'maybe_handle'));
add_action('wp_ajax_nopriv_' . $this->identifier, array($this, 'maybe_handle'));

// WP_Async_Request::maybe_handle()
check_ajax_referer($this->identifier, 'nonce');  // always verified
$this->handle();
wp_die();
```

**When auditing:** Action Scheduler nopriv handlers are nonce-protected. The nonce is created in `get_query_args()` and passed via the query string. An unauthenticated attacker cannot obtain it.

## M2M Secret Key Authentication (Backup Migration pattern)

Some plugins use machine-to-machine (M2M) shared-secret authentication for
nopriv AJAX handlers, typically to let an external service trigger background
processing (e.g., a ping server triggering cloud backup uploads).

### Recognition pattern

```php
add_action('wp_ajax_nopriv_bmip_keepalive', [...]);

private function verify_ping_server_request() {
    $stored_sk = get_option('bmi_sk_keepalive');
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    $request_sk = sanitize_text_field($data['sk'] ?? '');
    if (empty($stored_sk) || empty($request_sk)) return false;
    if (!hash_equals($stored_sk, $request_sk)) return false;  // timing-safe
    return true;
}
```

SK generation: `wp_generate_password(32, false)` → `update_option(...)`.
SK shared with external service via `wp_remote_post()` to a fixed URL.

### When auditing

1. **Check where the SK is generated and stored** — is it random, sufficient length?
2. **Check where the SK is exposed** — grep for the option name across ALL files.
   Common leakage points: `system_info` / debug endpoints, admin AJAX that
   returns site data, error logs, config files rendered to admin pages.
   If the SK appears in any admin-only AJAX response, it's behind nonce auth —
   not unauthenticated, but a privilege escalation vector if a lower-capability
   role can access it.
3. **Check the comparison method** — `hash_equals()` is timing-safe. `==` or
   `===` against a secret is timing-attack-vulnerable.
4. **Check what the handler does after auth** — even with valid M2M auth, does
   it expose sensitive data or allow destructive actions? A well-designed
   handler returns only success/fail status (like this plugin's keepalive).
5. **Do NOT report as unauthenticated vulnerability** if the SK is not
   obtainable by unauthenticated users and the comparison is timing-safe.

## Config-as-PHP-Comment Pattern

Some plugins store configuration as JSON inside a PHP file prefixed with
`<?php //`, e.g., `<?php //{"key":"value"}`. Read via:
```php
$content = file_get_contents($path);
$data = json_decode(substr($content, 8));
```
This prevents direct web access from returning the data (PHP interprets the
`<?php //` and exits or serves nothing). **Not a vulnerability**, but:
- Recognize this pattern when tracing `file_get_contents()` + `substr()` data flow
- The `substr($content, 8)` strips `<?php //` (8 chars) — verify the prefix length matches
- If the web server is misconfigured to serve `.php` files as plaintext, the data is exposed

## Route Registry + Action Policy Service (WP Job Portal pattern)

Some plugins implement a centralized route registry + action policy service
for form/task dispatch, separate from WordPress's AJAX or REST API systems.
This pattern is used by wp-job-portal and similar plugins with custom MVC
frameworks.

### Architecture

```
Request → formhandler.php → dispatch()
  → Route_Registry::is_allowed(module, task, channel)  // is route registered?
  → Core_Action_Policy::authorize(module, task, channel)  // nonce + cap + method + schema + ownership
  → Addon_Action_Policy::authorize(...)  // addon-specific checks
  → Controller->$task()  // method execution with reflection checks
```

### Key components

1. **Route Registry** (`class-wpjobportal-route-registry-service.php`):
   - Hardcoded array of allowed module → task pairs
   - `is_allowed()` checks if the route exists in the registry
   - Unknown routes are denied (allowlist, not blocklist)

2. **Core Action Policy** (`class-wpjobportal-core-action-policy-service.php`):
   - `policies()` returns per-route policy: HTTP methods, role, nonce action,
     nonce field, input schema, ownership resolver
   - `authorize()` checks: HTTP method → role → nonce → schema → ownership
   - **Read-only routes** are listed in a `$read_only` array and SKIP the
     policy check entirely — they only pass the route registry gate

3. **Controller-level checks**: Even read-only routes may have their own nonce
   or capability checks inside the controller method body. Must read the
   controller to determine actual auth level.

### When auditing this pattern

1. **Read the route registry** — the allowed routes array IS the attack surface
2. **Find the `$read_only` list** — these routes skip the policy service auth
3. **For each read-only route, read the controller method** — check for nonce,
   capability, or data sensitivity
4. **Check the policy overrides** — `override_policy()` changes the default
   `administrator` role to `public`, `employer_or_administrator`, etc.
5. **Look for `wp_localize_script` nonce exposure** — if a nonce action used
   by the policy is exposed to unauthenticated users via `wp_localize_script()`
   on frontend pages, the nonce check passes for anonymous users
6. **Check for ownership resolvers** — `owns_records()`, `owns_resume()` verify
   the current user owns the target object. Guest orders (user_id=0) may bypass this

### Safe vs. vulnerable in this pattern

**Safe:**
- Read-only routes returning public data (categories, cities) with `esc_sql()`
- State-changing routes with `administrator` role + nonce
- File download routes with `Authorization_Service` ownership checks

**Potentially vulnerable:**
- Read-only routes with NO controller-level auth returning sensitive data
- State-changing routes with role overridden to `public` + nonce exposed via
  `wp_localize_script()` (the nonce check passes but there's no capability gate)
- Ownership resolvers that accept user_id=0 (guest) as valid owner

## General Pattern for Custom Frameworks

1. **Read the framework's route registration code** — does it enforce `permission_callback` or leave it to the dev?
2. **Check for a centralized ACL/permission class** — does a single `verify()` call combine nonce + capability?
3. **Look for query builder raw methods** — `selectRaw/whereRaw/orderByRaw` with `?` placeholders + bound params = safe.
4. **Check `unserialize()` for `allowed_classes` option** — `false` = safe from POI.
5. **Verify the framework's IP resolution** — does it validate trusted proxies before trusting `X-Forwarded-For`?
6. **Check for M2M secret key auth on nopriv handlers** — `hash_equals()` against a stored option that's never exposed to unauthenticated users = properly authenticated.
7. **Recognize `sanitize_text_field()` custom recursive wrappers** — they strip tags/whitespace but do NOT escape SQL. Functions relying solely on such wrappers for SQL safety are vulnerable.
8. **Check for a route registry + action policy dispatch** — if the plugin has a `formhandler.php` or similar central dispatcher, read the route registry AND the read-only routes list. Read-only routes skip policy checks.
9. **Verify `wp_localize_script` nonce exposure on frontend** — `wp_create_nonce()` exposed via `wp_localize_script()` on `wp_enqueue_scripts` = available to all visitors. Nonce checks pass for unauthenticated users.
10. **`wp_filesystem()` ≠ `system()`** — automated scanners flag `wp_filesystem()` as `system()` calls. These are WP_Filesystem API initialization, not command execution.
