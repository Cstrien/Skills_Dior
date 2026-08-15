# Patchstack Submission Workflow for WordPress Plugins

End-to-end workflow for finding, verifying, and preparing WordPress plugin
vulnerabilities for Patchstack CVE submission. Built from real audit sessions
covering 400+ WooCommerce plugins.

## Patchstack Rules Quick Reference

Source: `/home/kali/Desktop/rules_patchstack.txt` — re-read each session; rules update.

### Accepted vuln types (must meet conditions)
| Type | Condition |
|---|---|
| SQL injection | Always accepted |
| Arbitrary file upload/deletion/download | Full control over path AND extension |
| RCE / Arbitrary Code Execution | Always accepted |
| PHP Object Injection | Always accepted |
| Arbitrary settings change | Must involve WP options with significant site impact |
| Privilege escalation | Must lead to contributor+ access |
| LFI / RFI | Full control over path AND extension |
| Broken access control | Must access significant/sensitive objects (API keys, secrets, password hashes, backup/SQL files) |
| IDOR | Must lead to significant security impact. PII-only or interactions with orders/attachments/tickets/events/appointments = mVDP scope only |
| CSRF | Must chain into an accepted write action |
| XSS | Site-wide stored XSS or reflected XSS with JS execution only |
| DoS | Must crash/deface entire site, demonstrable, not volume-based |

### Key rejection rules (auto-reject even if type is accepted)
| Rule | What gets rejected |
|---|---|
| 46 | Price tampering / price manipulation |
| 47 | Payment bypass (mVDP only) |
| 48 | IDOR limited to orders, attachments, tickets, events, appointments (mVDP only) |
| 50 | <1000 active installs (unless CVSS >= 8.5; <100 always out) |
| 54 | Must test against latest available version |
| 58 | Duplicates of existing CVEs |
| 62 | Unrealistic prerequisites |
| 79 | Actions requiring non-guessable/unrealistic identifier (e.g. cancelling subscription needing random Stripe sub ID) |
| 84 | Lack of brute-force protection / rate-limiting on login |

## Step-by-Step Workflow

### Step 1: Plugin Discovery
- Query WordPress.org API for plugin candidates
- Target sweet spot: 1,000–30,000 active installs
- Download via `https://downloads.wordpress.org/plugin/{slug}.{version}.zip`
- Get latest version info: `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}`

### Step 2: Attack Surface Discovery
Scan extracted PHP files for:
- `wp_ajax_nopriv_` — unauthenticated AJAX handlers
- `register_rest_route` with `permission_callback => '__return_true'` — public REST endpoints
- `$wpdb->query/get_results/get_var/get_row` without `$wpdb->prepare()` — potential SQLi
- `$_FILES` handling in nopriv handlers — potential file upload
- `update_option()` / `update_user_meta()` in nopriv handlers — potential settings/user modification
- `wp_unslash()` calls — indicates developer aware of magic quotes; check if removed before SQL

### Step 3: Nonce Exposure Analysis (CRITICAL)
A nopriv handler with `check_ajax_referer()` is NOT necessarily safe. The nonce
may be available to unauthenticated users.

Checklist:
1. Find `wp_create_nonce('{nonce_name}')` in the codebase
2. Check if it's passed via `wp_localize_script()` — this exposes the nonce in page HTML as a JS variable
3. Check if the script is enqueued via `wp_enqueue_scripts` (frontend) — not just `admin_enqueue_scripts`
4. Check the page-load condition function (e.g., `is_account_page()`, `is_order_received_page()`, `is_page($guest_page_id)`) — if ANY public page qualifies, the nonce is exposed to unauth users
5. If nonce is exposed → the `check_ajax_referer()` check is bypassable by unauthenticated attackers

### Step 4: Capability Check Analysis
For each nopriv handler, trace:
- `check_ajax_referer()` / `wp_verify_nonce()` — nonce check
- `current_user_can()` — capability check
- `is_admin()` — admin context check
- Ownership: `get_current_user_id() === $order->get_user_id()` or similar

**Guest order IDOR pattern:** `get_current_user_id()` returns `0` for
unauthenticated users. `$order->get_user_id()` returns `0` for guest orders.
So `0 === 0` evaluates to `TRUE` — unauthenticated users pass ownership
checks on guest orders. This affects any WooCommerce plugin that handles
guest orders with this check pattern.

### Step 5: REST API SQLi (REST bypasses magic quotes)
REST API parameters are NOT magic-quoted by WordPress. If user input from
`$request->get_param()` reaches `$wpdb->query()` via string concatenation
(without `$wpdb->prepare()`), it is directly exploitable.

Checklist:
1. Find `register_rest_route` with `__return_true` permission_callback
2. Trace the callback function
3. Look for `$request->get_param()` or `$request->get_body_params()`
4. Trace data flow to `$wpdb->query/get_results/get_var` without `prepare()`
5. Check if `wp_unslash()` is called (may re-add slashes to REST params)
6. If string concatenation with user input → exploitable SQLi

### Step 6: Version Verification (Patchstack Rule 54)
1. Get latest version from WordPress.org API
2. Download and extract latest version
3. Check if vulnerable code still exists in latest
4. If fixed, determine which version introduced the fix (download intermediate versions)
5. Note: Patchstack may still accept historical vulns if no existing CVE covers the specific finding

### Step 7: CVE Duplicate Check (Patchstack Rule 58)
Query NVD API:
```
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={plugin+name+wordpress}&resultsPerPage=20
```
For each CVE found, compare:
- Same function/handler name?
- Same parameter?
- Same vulnerability type?
- Same affected version range?

If ANY dimension differs, it may be a new finding worth submitting.

### Step 8: Patchstack Rule Compliance Check
For each finding, verify:
- [ ] Accepted vulnerability type with conditions met
- [ ] Not in rejection list (check rules 22–63, 76–80)
- [ ] >= 1000 active installs (or CVSS >= 8.5)
- [ ] Tested against latest version
- [ ] No existing CVE covers this specific finding
- [ ] HTTP PoC available (curl command, not wp-cli)
- [ ] Unauthenticated or subscriber/customer level only

### Step 9: PoC Format
Provide step-by-step curl commands:
```
# Step 1: Obtain nonce (if needed) from public page
curl -s https://target.com/my-account/ | grep -oP '"nonce_name":"\K[^"]+'

# Step 2: Send exploit request
curl -X POST https://target.com/wp-admin/admin-ajax.php \
  -d 'action={handler}' \
  -d 'nonce={NONCE}' \
  -d 'param1=value1'

# Step 3: Verify impact
```

### Step 10: Upload to Notion

**CRITICAL: Notion API version 2026-03-11 changed the markdown PATCH format.**

The old `POST /v1/pages` with `{"markdown": "..."}` still works for CREATE,
but PATCH `/v1/pages/{id}/markdown` now requires a `type` discriminator:

```python
import json

payload = {
    "type": "replace_content",
    "replace_content": {
        "new_str": report_content
    }
}
with open('/tmp/notion_patch.json', 'w') as f:
    json.dump(payload, f, ensure_ascii=False)

# curl with Notion-Version: 2026-03-11 (NOT 2025-09-03 for PATCH markdown)
curl -s -X PATCH "https://api.notion.com/v1/pages/{page_id}/markdown" \
  -H "Authorization: Bearer $NOTION_API_KEY" \
  -H "Notion-Version: 2026-03-11" \
  -H "Content-Type: application/json" \
  -d @/tmp/notion_patch.json
```

Other supported `type` values for the PATCH markdown endpoint:
- `"update_content"` with `update_content.content_updates[]` — search-and-replace ops (recommended for targeted edits)
- `"insert_content"` with `insert_content.content` + optional `position` — append/prepend (legacy)
- `"replace_content_range"` with `replace_content_range.content_range` — replace a range (legacy)
- `"replace_content"` with `replace_content.new_str` — replace entire page (recommended for full rewrites)

**Creating a new page** still uses `POST /v1/pages` with `{"parent": {...}, "properties": {...}, "markdown": "..."}`.

- Parent page ID for Pentest Reports: `38d8622b-cd7d-8181-a9d1-c5f637ab17d1`
- Write JSON payload to temp file (`json.dump`), pass `-d @/tmp/file.json` to avoid shell escaping
- Title format: `[CVE Pending] {plugin} v{version} — {vuln type}`

## Common Vulnerability Patterns

### Pattern: Nopriv handler with exposed nonce (no capability check)
```
wp_ajax_nopriv_{handler}
  → check_ajax_referer('{nonce_name}', 'nonce')    // nonce check only
  → NO current_user_can()                           // missing capability check
  → update_option() / wp_delete_post() / etc.       // dangerous action

wp_localize_script(..., '{nonce_name}', wp_create_nonce('{nonce_name}'))
  → enqueued via wp_enqueue_scripts (frontend)
  → available on is_account_page() / is_order_received_page() / guest pages
```
**Result:** Exploitable by unauthenticated users — nonce is public, no capability gate.

### Pattern: Guest order IDOR
```
if ( get_current_user_id() === $order->get_user_id() )
// Unauth user: get_current_user_id() = 0
// Guest order: $order->get_user_id() = 0
// 0 === 0 → TRUE → ownership check passes
```
**Result:** Unauthenticated users can access/modify any guest order's data.

### Pattern: REST API SQLi (magic quotes bypass)
```
register_rest_route(..., 'permission_callback' => '__return_true')
$param = $request->get_param('user_input')
$wpdb->get_results("SELECT ... WHERE col = '" . $param . "'")  // no prepare()
```
**Result:** Directly exploitable — REST params are not magic-quoted.

### Pattern: Non-guessable ID rejection (Rule 79)
```
$subscription_id = $_POST['sub_id']  // e.g., "sub_1NxYbWCJ8vQkH4Xf"
$this->stripe->cancelSubscription($subscription_id)  // no ownership check
```
**Result:** Even with missing ownership check, Patchstack rejects because
the Stripe subscription ID is a random non-guessable string.

## Session Examples

### Accepted: woo-refund-and-exchange-lite v4.6.3 — Unauth Arbitrary Settings Modification
- Handler: `wps_rma_standard_save_settings_filter` (nopriv)
- Nonce `ajax-nonce` exposed via `wp_enqueue_scripts` on View Order Message page (NOT My Account — that page exposes `wps_rma_nonce` for a DIFFERENT action `wps_rma_ajax_security`)
- No `current_user_can()` check
- Calls `update_option()` for 10+ settings: refund/exchange/cancel/wallet/COD/tracking/order-messages/order-emails/multistep-done
- `licenseCode` param calls `wps_rma_license_activate()` but only if function exists (Pro only — not in lite)
- Handler can only ENABLE features (sends `true` → `update_option('...','on')`). Sending `false` does NOT update the option — the value stays at its previous setting.
- Patchstack: Rule 14 (Arbitrary settings change) — ACCEPTED
- No existing CVE — NEW finding
- CVSS 8.6 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L
- **Live PoC verified on local WP lab (10.10.16.102):**
  - Lab IS the local machine → read DB creds from `wp-config.php`, use `wp-cli` to reset password
  - Installed WooCommerce + woo-refund-and-exchange-lite v4.6.3 via `wp plugin install ... --activate`
  - Created My Account page (`wp post create --post_type=page --post_title="My Account" --post_content="[woocommerce_my_account]""`)
  - Created View Order Message page, set `wps_rma_view_order_msg_page_id` option
  - **Nonce extraction:** `wps_rma_react_nonce` (for action `ajax-nonce`) is ONLY on the View Order Message page — NOT on My Account (which has `wps_rma_nonce` for action `wps_rma_ajax_security`). PoC returns `-1` if wrong nonce used.
  - Unauthenticated curl POST → response `"yes"`, settings changed: `wps_rma_refund_enable`, `wps_rma_cancel_enable`, `wps_rma_wallet_enable` all set to `on`
  - **Full lab rebuild performed:** torn down (drop DB, remove files, stop services) then reinstalled from scratch — see "Full WP Lab Rebuild" section in SKILL.md
  - Uploaded to Notion: parent page `38d8622b-cd7d-8181-a9d1-c5f637ab17d1`, title `[CVE Pending] woo-refund-and-exchange-lite v4.6.3 — Unauth Arbitrary Settings Modification`

### Rejected: wp-full-stripe-free IDOR subscription cancellation
- Missing ownership check on `handleSubscriptionCancellationRequest()`
- But: requires victim's random Stripe subscription ID (`sub_xxx`)
- Rule 79: "Actions that require a non-guessable or unrealistic identifier" — REJECTED

### Rejected: woo-refund-and-exchange-lite guest order message IDOR
- `get_current_user_id() === $user_id` passes for guest orders (0 === 0)
- But: duplicate of CVE-2025-12881 — REJECTED under Rule 58

### Rejected: classified-listing unauth listing deletion
- `rtcl_delete_temp_listing` nopriv with `// TODO: check_ajax_referer` (commented out)
- But: fixed in v6.0.0 + overlaps CVE-2025-58601 — REJECTED

### Rejected: advanced-form-integration SQLi via CF7 form_id
- `$wpdb->get_results("SELECT * FROM ... WHERE form_id = ".$form_id)` — no prepare()
- `$form_id` from `$_POST['_wpcf7']` — user-controlled
- But: fixed in v1.76.0 (latest is v2.8.2) — weak under Rule 54
- No existing CVE for this specific parameter (CVE-2024-2387 covers different param)
