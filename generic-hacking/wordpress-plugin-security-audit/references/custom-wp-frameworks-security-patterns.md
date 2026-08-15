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

## General Pattern for Custom Frameworks

1. **Read the framework's route registration code** — does it enforce `permission_callback` or leave it to the dev?
2. **Check for a centralized ACL/permission class** — does a single `verify()` call combine nonce + capability?
3. **Look for query builder raw methods** — `selectRaw/whereRaw/orderByRaw` with `?` placeholders + bound params = safe.
4. **Check `unserialize()` for `allowed_classes` option** — `false` = safe from POI.
5. **Verify the framework's IP resolution** — does it validate trusted proxies before trusting `X-Forwarded-For`?
