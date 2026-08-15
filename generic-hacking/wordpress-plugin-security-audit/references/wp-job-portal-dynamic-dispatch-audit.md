# wp-job-portal v2.5.9 — Dynamic Model Dispatch Audit

**Plugin:** wp-job-portal v2.5.9 (666K active installs)
**Date:** August 2026
**Outcome:** No Patchstack-submittable findings (insufficient impact), but architecture pattern is instructive.

## Architecture

The plugin uses a single nopriv AJAX handler that dispatches to model methods
via an allowlist array + ReflectionMethod, rather than registering individual
`wp_ajax_nopriv_*` actions per function.

**File:** `includes/ajax.php:19-69`

```php
function ajaxhandler() {
    $fucntin_allowed = array('DataForDepandantFieldResume', ..., 'executeCoverLetterCopilot');
    $task = preg_replace('/[^A-Za-z0-9_]/', '', (string) WPJOBPORTALrequest::getVar('task'));
    if (in_array($task, $fucntin_allowed, true)) {
        $module = sanitize_key(WPJOBPORTALrequest::getVar('wpjobportalme'));
        $model = WPJOBPORTALincluder::getJSModel($module);
        // ReflectionMethod checks getNumberOfRequiredParameters() === 0
        $result = $model->$task();
        echo $result;
        die();
    }
}
```

**Key:** The dispatcher has NO nonce or capability check. Each model method
must self-verify. ~75 functions are in the allowlist — all nopriv-exposed.

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

## Functions WITHOUT Nonce Checks

| Function | File:Line | Impact |
|----------|-----------|--------|
| `jobapply()` | `modules/jobapply/model.php:786` | **Nonce check COMMENTED OUT** (lines 787-790). Inserts job application record into DB. Has `getIfResumeOwner()` ownership check (line 817). Visitor/guest apply path (line 848) allows unauthenticated applications when `visitor_can_apply_to_job` config is enabled. **Impact: Unauthenticated arbitrary job application creation (DB write).** Not Patchstack-qualifying due to low impact (job application creation, not admin-level changes). |
| `getEmailFieldsJobManager()` | `modules/jobapply/model.php:1265` | NO nonce, NO capability check. Returns HTML email form template. Read-only HTML generator — low impact per Patchstack criteria. |

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
These include: `saveJobShortlistJobManager`, `getShortListViewByJobIdJobPortal`,
`getResumeDetailJobManager`, `getResumeCommentSection`, `getFolderSection`,
`saveToFolderResume`, `storeResumeComments`, `setResumeRatting`,
`hideTemplateBanner`, `validateandshowdownloadfilename`, `getlanguagetranslation`,
`changeNotifyOfNotifications`, `changeViewOfNotifications`,
`getOptionsForFieldEdit`, `listdepartments`, `updateJobApplyResumeStatus`,
`deletecompanylogo`, `getLogForUserById`, `jobapplyid`, `visitorapplyjob`,
`getPacakageListByUid`, `sendmessageresume`, `sendmailtofriend`,
`storeConfigurationSingle`, `getPackagePopup*`, `gettagsbytagname`,
`listDepartments`, `getFolderSectionJobManager`, `getPaymentPopup`,
`getStripePlans`.

**These need individual nonce auditing in each add-on.**

## SSRF Analysis

All `wp_remote_post()` / `wp_remote_get()` calls use hardcoded URLs:
- `https://api.zywrap.com/v1/proxy` (AI copilot functions)
- `https://api.zywrap.com/v1/key/check` (key validation)
- `https://api.zywrap.com/v1/sdk/v1/sync` (data import)
- `http://www.joomsky.com/translations/api/1.0/index.php` (translations)

**No SSRF found** — user input never controls the outbound URL.

## Settings Changes (update_option/delete_option)

All `update_option()` / `delete_option()` calls are in controller files or
behind nonce/capability checks. No unprotected settings changes found in the
nopriv AJAX path.

## SQL Injection

No SQL injection found. Functions use `esc_sql()`, `(int)` casts, or
`$wpdb->prepare()` for user-supplied values in queries. The `filter_var_array()`
in `getVar()` for array inputs uses `FILTER_DEFAULT` (no escaping), but no
examined function uses array inputs in raw SQL queries.

## Why Not Patchstack-Submittable

1. `jobapply()` — commented-out nonce allows unauthenticated job application
   creation, but impact is limited to creating job application records (not
   admin-level changes, not privilege escalation, not data exfiltration).
   Patchstack CVSS threshold for unauthenticated vulns requires significant
   impact (CVSS ≥ 5.3 with at least two CIA at Low).
2. `getEmailFieldsJobManager()` — read-only HTML template, no sensitive data.
3. The module-dispatch difference (customfield vs fieldordering) only matters
   when the customfield add-on is installed, limiting the attack surface.

## Lessons for Future Audits

1. **Extract the full allowlist array** — the entire array IS the attack surface.
2. **Grep for commented-out nonces** — `grep -rn '//.*wp_verify_nonce\|//.*check_ajax_referer'`
3. **Check ALL modules for duplicate function names** — same name, different security.
4. **Read the custom request class** — understand what `getVar()` actually does.
5. **Note add-on-only functions** — they're in the allowlist but can't be audited
   from core alone.
