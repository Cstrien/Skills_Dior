# Mass Plugin Audit — 500+ Plugins (August 2026)

Extended audit bringing total scanned to 500+ plugins across directories
`plugin_audit_new1` through `plugin_audit_new7`. This batch used combined
`popular` + `updated` browse modes from the WordPress.org API, downloading
336 new plugins in a single batch and quick-scanning for nopriv/REST_TRUE.

## Confirmed Finding: Charitable v1.8.12 — Unauth File Upload

- **Plugin:** Charitable – Donation Plugin (10,000 installs, v1.8.12 latest)
- **Handler:** `charitable_plupload_image_upload` (nopriv, `includes/ajax/charitable-ajax-functions.php:66`)
- **Nonce:** `charitable-upload-images-{$field_key}` — created in
  `templates/form-fields/picture.php:72` via `wp_create_nonce()` in a
  FRONTEND template (accessible to unauthenticated users)
- **Auth:** `check_ajax_referer()` present, NO `current_user_can()` check
- **Upload:** `wp_handle_upload($file, array('test_form' => false))` — saves
  to `wp-content/uploads/[year]/[month]/` (web-accessible)
- **Impact:** Unauthenticated upload of allowed MIME types (txt, png, jpg,
  csv, pdf, zip, doc, mp3, mp4...). PHP/HTML/SVG/CSS/XML blocked by
  `wp_check_filetype_and_ext`. No rate limit, no `post_id` validation
  (can attach to nonexistent posts). Files accessible via web.
- **PoC:**
  ```
  # Generate nonce (accessible on any donation form page with picture field)
  # Then upload:
  curl -X POST http://target/wp-admin/admin-ajax.php \
    -F action=charitable_plupload_image_upload \
    -F post_id=1 \
    -F field_id=test_field \
    -F _ajax_nonce=<nonce_from_frontend> \
    -F async-upload=@file.txt
  # → {"success":true} — file uploaded
  ```
- **CVE check:** NVD has 12 CVEs for Charitable. None cover this upload
  issue. CVE-2026-10038 covers attachment *deletion* (different).
- **Patchstack:** Likely submittable as Broken Access Control / Arbitrary
  File Upload (unauthenticated). No RCE capability limits severity to
  Medium.

## Not-Submittable Findings

### woo-product-table v6.1.3 (5k installs) — Cart Emptying
- `wpt_fragment_empty_cart` nopriv, NO nonce, NO cap
- `WC()->cart->empty_cart()` — empties caller's cart session
- Rejected: Rule 47 (cart/price tampering)

### nex-forms v9.2.5 (6k installs) — Form Submission
- `submit_nex_form`, `nf_send_nf_email` nopriv, NO auth
- Public form submission is by design; no nonce = CSRF, no rate limit = spam
- Rejected: Rule 84 (brute force/spam)

### wp-job-portal v2.5.9 (8k installs) — AJAX Dispatch
- `wpjobportal_ajax` nopriv with no nonce at dispatch level
- Some methods (getEmailFieldsJobManager) return HTML template without nonce
- `jobapply()` has commented-out nonce check (regression)
- Same function name in different modules has different security (fieldordering vs customfield)
- Insufficient impact (read-only HTML, job application creation — not admin-level changes)
- Full deep audit: see `references/wp-job-portal-dynamic-dispatch-audit.md`

## Plugins Confirmed Safe (This Batch)

| Plugin | Installs | Why Safe |
|---|---|---|
| jupiterx-core | 70k | Form handler has upload blacklist + nonce |
| media-library-plus | 10k | All 39 nopriv handlers have nonce+cap |
| data-tables-generator-by-supsystic | 10k | Admin nonce not exposed to frontend |
| quiz-master-next | 40k | All nopriv handlers check nonce |
| simple-membership | 40k | All nopriv handlers check nonce |
| ays-popup-box | 50k | All nopriv check nonce, install/activate have cap |
| boldgrid-backup | 50k | Uses hash_equals shared secret validation |
| booking | 50k | Checks nonce inside handler |
| gpt3-ai-content-generator | 10k | Nonce faucet pattern + ownership checks |
| power-coupons | 30k | Nonce exposed but only cart manipulation |
| wp-polls | 50k | Vote checks per-poll nonce |
| content-views | 100k | Intentionally unauth for public pagination |
| interactive-3d-flipbook | 70k | Read-only public content |
| content-protector (Passster) | — | Hash endpoint by design |
| events-manager | 100k | Mature, uses $wpdb->prepare |
| erp | 10k | __return_true only on static dropdown data |
| ays-popup-box | 50k | All nopriv: nonce check + install/activate have cap |

## Methodology Notes

### Combined Browse Modes
Querying both `browse=popular` and `browse=updated` yields broader coverage
than either alone. The `updated` mode catches freshly-updated plugins with
new code that may not have been audited yet.

```python
for browse in ['updated', 'popular']:
    for page in range(1, 10):
        url = f"https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]={browse}&request[per_page]=100&request[page]={page}"
```

### Quick-Scan-Then-Deep-Audit
1. Download all candidates to a local directory
2. Quick scan: count `wp_ajax_nopriv` occurrences + check for
   `__return_true` + `register_rest_route` in same file
3. Deep audit only plugins with hits (typically 30-40% of downloaded)
4. For each hit: read handler body, trace nonce + cap checks

### Cross-Reference Frontend Nonce Exposure
For plugins with nopriv handlers that check nonce but NOT capability:
1. Search for `wp_create_nonce` with the same action name
2. Check if it's in a `wp_enqueue_scripts` context (frontend) or
   `admin_enqueue_scripts` (admin-only)
3. If frontend → nonce is obtainable by unauthenticated users → exploitable
4. Charitable's nonce is in `templates/form-fields/picture.php` — a
   frontend template rendered on donation form pages
