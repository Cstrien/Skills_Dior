# Supsystic Nonce-Only BAC Audit (Data Tables Generator v1.14.2)

**Plugin:** Data Tables Generator by Supsystic v1.14.2 (1.6M installs)
**Date:** 2026-08-15
**Prior CVEs:** CVE-2024-56253, CVE-2020-12075, CVE-2020-12076

## Architecture: Single-Handler Dynamic Dispatch

Unlike typical WordPress plugins that register individual `wp_ajax_*` actions per handler, this plugin uses a **single AJAX entry point** that dynamically dispatches to any controller method.

### Registration Flow (`Core/Module.php:392-432`)

1. Registers `wp_ajax_supsystic-tables` (the menu_slug) for ALL logged-in users
2. Registers `wp_ajax_nopriv_supsystic-tables` ONLY for frontend methods when user is NOT logged in
3. The handler reads `route[module]` and `route[action]` POST parameters
4. Sanitizes module/action via `sanitize_key()`
5. Loads the module, gets its controller, calls `{action}Action()` method

### Frontend Methods (`Core/Module.php:16-24`)

```php
private $frontendMethods = [
  'ajax' => [
    'tables' => ['saveEditableFields', 'getPageRows', 'saveEditableFieldsFile', 'deleteEditableFieldsFile', 'sendTableToEmail'],
    'woocommerce' => ['productsAddToCart'],
  ],
  'post' => [
    'importer' => ['import'],
  ],
];
```

These methods are the ONLY ones accessible via `wp_ajax_nopriv_`. In the free version, `saveEditableFields`, `saveEditableFieldsFile`, `deleteEditableFieldsFile`, and `sendTableToEmail` have NO implementation (PRO-only).

## Finding 1: Missing Capability Checks (BAC) — High

### Root Cause

`Core/BaseController.php:80-118` — `_checkNonce()` ONLY verifies the nonce:
```php
public function _checkNonce($request) {
  // ... extracts nonce from request ...
  if (!empty($nonce) && wp_verify_nonce($nonce, 'dtgs_nonce')) {
    return true;
  }
  return false;
}
```

There are ZERO `current_user_can()`, `manage_options()`, or capability checks in ANY controller. Verified via grep across all controller files.

### Nonce Distribution (`Core/Module.php:84-115`)

```php
public function loadDataTablesNonces() {
  // ...
  if (is_admin() && (current_user_can('administrator') || $userCanEdit)) {
    $nonce = wp_create_nonce('dtgs_nonce');
    // enqueued as DTGS_NONCE
  }
  if (!is_admin()) {
    $nonce = wp_create_nonce('dtgs_nonce_frontend');
    // enqueued as DTGS_NONCE_FRONTEND
  }
}
```

- `dtgs_nonce`: only for admins or users with roles in `access_roles` setting (admin pages)
- `dtgs_nonce_frontend`: for ALL frontend visitors (pages with tables)

### Access Roles Configuration

The `access_roles` setting (in `supsystic_tbl_settings` option) is configurable in the PRO version's settings page. Admins can grant table-editing access to any role including `subscriber`. When a subscriber is in `access_roles`:
1. They receive `dtgs_nonce` on admin pages
2. They can call ANY `wp_ajax_supsystic-tables` action (all controllers, all methods)
3. This includes `saveSettingsAction` (Settings/Controller.php:33) which modifies the `access_roles` setting itself

### Exploitable Actions (all require only `dtgs_nonce`, no capability check)

| Action | File:Line | Impact |
|--------|-----------|--------|
| `saveSettingsAction` | Settings/Controller.php:33 | Modify global plugin settings (incl. `access_roles`) |
| `removeAction` | Tables/Controller.php:130 | Delete any table |
| `createAction` | Tables/Controller.php:28 | Create tables |
| `updateRowsAction` | Tables/Controller.php:510 | Modify table data |
| `saveSettingsAction` | Tables/Controller.php:554 | Modify per-table settings |
| `reviewNoticeResponseAction` | Tables/Controller.php:835 | `update_option()` with user-controlled data |
| `cloneTableAction` | Tables/Controller.php:794 | Clone tables |

### Exploitability Assessment

- **Unauthenticated:** NOT exploitable — nopriv handler only covers frontend methods, and the `dtgs_nonce` is not given to unauthenticated users
- **Subscriber (default):** NOT exploitable — subscribers don't receive `dtgs_nonce` unless `access_roles` includes their role
- **Subscriber (with access_roles):** FULLY exploitable — can perform all admin operations including modifying `access_roles` (potential privilege escalation)
- **Any role in access_roles:** FULLY exploitable

## Finding 2: No Nonce Check on sendMailAction — Medium

### Vulnerable Code (`Overview/Controller.php:21-48`)

```php
public function sendMailAction(RscDtgs_Http_Request $request) {
  $mail = $request->post['route']['data'];
  $headers = ['Content-Type: text/html; charset=UTF-8', 'From: ' . $mail['name'] . ' <' . $mail['email'] . '>'];
  $message = [...];
  wp_mail($config['mail'], $mail['subject'], $message, $headers);
```

- NO `_checkNonce()` call
- NO capability check
- User-controlled `name`, `email`, `subject` injected into email headers
- Exploitable by ANY authenticated user (subscriber+)
- Enables email header injection (CRLF in `name`/`email`) and spam relay

## Finding 3: ChainQueryBuilder _sanitizeValue — Not Exploitable

### Pattern (`vendor/BarsMaster/ChainQueryBuilder.php:196-202`)

```php
protected function _sanitizeValue($val, $search = false) {
  if (!is_numeric($val)) {
    $val = '\'' . $val . '\'';  // NO quote escaping!
  }
  return $val;
}
```

Wraps strings in single quotes without escaping quotes within. If user input with a single quote reaches a `where()` clause, SQL injection is possible.

### Why Not Exploitable

Traced all user-controllable paths:
- Table IDs: cast to `(int)` everywhere
- Search tokens (`getTableIdsBySearchTokens`): sanitized via `sanitize_text_field()` + `$wpdb->esc_like()`. Input comes from `get_search_query()` which applies `esc_attr()` (converts `'` to `&#039;`), preventing quote breakout
- `getRowsLike`: defined but never called in free version (PRO-only)
- `getListTbl`: uses `$wpdb->prepare()` for search
- All other where clauses use integer values

**Latent risk:** If PRO code or future changes pass unsanitized strings through the query builder, SQL injection would be exploitable.

## Secure Items Verified

- **PHP Object Injection:** All 20+ `unserialize()` calls use `['allowed_classes' => false]`
- **File operations:** No file upload in free version; cache cleaning uses numeric ID validation
- **LFI/RFI:** No include/require with user input
- **SSRF:** Only hardcoded URLs (GitHub API, updates.supsystic.com)
- **REST API:** All routes use `checkPermission()` requiring `manage_options` capability
- **Migration export:** Uses `current_user_can('administrator')`
- **Magic quotes:** WordPress magic quotes protect `$_POST`-based queries even without `prepare()`

## Audit Methodology Notes

1. **Single-handler dispatch** is harder to audit — the attack surface is the `route` parameter, not individual `wp_ajax_*` registrations. Grep for `wp_ajax_` finds only one registration; must trace the dispatch logic to find all reachable methods.

2. **Methods listed in `frontendMethods` but not implemented** (PRO-only) create a false sense of nopriv surface. The free version's nopriv attack surface is limited to `getPageRows` and `productsAddToCart` (both have nonce checks accepting either `dtgs_nonce` or `dtgs_nonce_frontend`).

3. **`_checkNonce` vs `_checkNonceFrontend`** — some methods check both (`||`), meaning the frontend nonce (available to all visitors) suffices. But these methods (`getPageRowsAction`, `productsAddToCartAction`) are read-only or WooCommerce cart operations, not high-impact.

4. **Nonce as sole authz** is the core issue. WordPress nonces are CSRF tokens, not authorization gates. The plugin treats nonce verification as sufficient authorization, but nonces only prevent cross-site requests — they don't prevent unauthorized users who have a valid nonce from performing privileged operations.
