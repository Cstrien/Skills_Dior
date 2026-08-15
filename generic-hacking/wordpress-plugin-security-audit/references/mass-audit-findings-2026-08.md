# Mass Plugin Audit Findings (August 2026)

Audited ~170 WordPress plugins across 11 directories for Patchstack submission.
This file records which plugins were checked, what was found, and why findings
were or were not exploitable — to avoid re-auditing the same plugins.

## Confirmed Vulnerability (HTTP-Exploitable)

### Simple Ajax Chat v20260811 (2,000 installs) — STORED XSS ✅
- **File:** `simple-ajax-chat-form.php` lines 143-144
- **Vuln:** Unauthenticated Stored XSS via preg_replace URL auto-linking
- **Root cause:** Regex `\S*` matches double quotes; matched URL placed in `href="\\0"` without `esc_url()`
- **Payload:** `http://x.com/"onmouseover="alert(document.cookie)` in chat text field
- **Rendered:** `<a href="http://x.com/"onmouseover="alert(document.cookie)">` → attribute breakout → XSS
- **Prerequisites:** `registered_only=false` (default), nonce from page HTML, hardcoded `sac_js_nonce`
- **HTTP PoC verified:** curl POST to `simple-ajax-chat-core.php` → XSS renders on page load
- **Not a duplicate:** CVE-2026-2987 (different param 'c'), CVE-2024-1983 (name field) — different vectors
- **Full worked example:** `references/simple-ajax-chat-xss-example.md`
- **Note:** User instructed NOT to submit to Patchstack — finding only, no auto-submission

## Confirmed Vulnerability (NOT HTTP-Exploitable)

### Auto Affiliate Links v6.9.3 (3,000 installs)
- **File:** `aal_stats.php`, function `aal_url_stats_save_action`
- **Vuln:** Unauthenticated SQLi — `$wpdb->get_results("WHERE link = '" . $link . "'")` with no `prepare()`
- **Nopriv:** YES — `wp_ajax_nopriv_aal_stats_save` registered
- **Nonce:** Available to unauth users in page HTML (`"security":"<nonce>"`) when `aal_statsactive == 'active'`
- **Confirmed via `wp eval`:** SLEEP(5) → 5.06s delay; UNION SELECT → extracted admin user/pass/email
- **NOT exploitable via HTTP:** WordPress `wp_magic_quotes()` escapes `'` in `$_POST`. The `\` escapes the quote inside the SQL string literal.
- **Patchstack rejection reason:** PoC must be HTTP-based (curl), not WP-CLI. No HTTP PoC exists due to magic quotes.
- **Key lesson:** `sanitize_text_field()` does NOT strip quotes. Magic quotes are the only "protection" — incidental, not intentional. Would be exploitable on GBK-encoded databases or if plugin called `wp_unslash()` before SQL.

## Audited & Safe (No Exploitable Vulnerability)

### Batches 1-7 (Original ~130 plugins)

### MetForm (600,000 installs)
- REST API base class: `permission_callback => '__return_true'`, `methods => ALLMETHODS` — ALL routes public
- `file_extension_validation()` only validates `is_array($file_data['name'])` — single files bypass validation
- BUT `handle_file()` also gates on `is_array()` — single files are never uploaded to disk
- Double-gate on `is_array()`: validation bypass + upload bypass = no exploit
- All SQL uses `$wpdb->prepare()`
- Nonce check (`form_nonce`) required in `submit()` at line 168

### Pie Register (1,000 installs)
- 18 REST endpoints with `__return_true` (login, user-data, invitations, etc.)
- All SQL uses `$wpdb->prepare()` — no SQLi
- `auth_key` header required for all endpoints except login
- Login only allows administrator role → no auth bypass
- Not exploitable

### Contest Gallery (1,000 installs)
- SQLi at line 359: `$wpdb->get_var("WHERE activation_key = '".$cgkey."'")` — no prepare
- BUT line 27 uses `$wpdb->prepare()` with same `$cgkey` → must match real DB row to proceed
- SQLi payload won't match any activation_key → `count($userAccountEntries)` = 0 → code returns before reaching line 359
- Unreachable SQLi — not exploitable

### Hippoo (1,000 installs)
- `wp_upload_bits($data['name'], null, base64_decode($data['content']))` — no MIME/extension check
- REST endpoint requires `edit_others_posts` capability (editor-level) — not unauthenticated
- Image-sizes endpoint IS public but only returns size list, no upload

### Other Audited Plugins (All Safe) — Batches 1-7
- **Events Made Easy** (1k): Nopriv handlers have nonce + honeypot. `move_uploaded_file` uses `wp_check_filetype_and_ext`.
- **Simple Event Planner** (1k): Nopriv `sep_event_option_save` has nonce check.
- **WholesaleX** (1k): REST `__return_true` only returns filter settings. Nopriv login has nonce.
- **Tickera** (1k): All nopriv handlers have nonce + inputs sanitized (int, sanitize_text_field).
- **ABlocks** (1k): REST `__return_true` but `verify_nonce()` checks `wp_rest` nonce. File upload uses `wp_upload_bits` but not in REST endpoint.
- **RestroPress** (1k): Nopriv checkout has nonce check (`rpress_is_checkout_request_nonce_valid`).
- **Booking & Rental Manager** (1k): Nopriv `rbfw_load_duration_form` has nonce check.
- **Wired Impact Volunteer Management** (1k): Nopriv handler has nonce + honeypot.
- **Banhammer** (1k): SQL concat in AJAX but `check_ajax_referer` + `manage_options` required.
- **Contact List** (1k): Nopriv `cl_send_mail_public` — no nonce but inputs sanitized. Email spam only.
- **Simple Countdown** (1k): Nopriv `ajax_subscribe_form` has nonce check.
- **WP Email** (1k): Nopriv `email` handler has `check_ajax_referer`.
- **HT Builder** (1k): Nopriv `templates_ajax_request` has nonce. SSRF via `wp_remote_get` but host is fixed.
- **Listdom** (1k): Nopriv `autosuggest` has nonce. REST public endpoints use WP_Query (safe). Terms handler no nonce but uses `get_terms()` (safe).
- **Calculated Fields Form** (40k): File upload via `wp_handle_upload`. No nopriv handlers. Nonce is optional (can be disabled).
- **Appointment Hour Booking** (10k): SQL uses `$wpdb->prepare` for user-facing queries. No nopriv handlers.
- **Contact Form to Email** (8k): File upload via `wp_handle_upload`. Has nonce check. Extension blacklist (php, asp, etc.).
- **CodePeople Post Map** (3k): SQL uses `prepare`. No nopriv handlers.
- **Search in Place** (3k): `nopriv_search_in_place` → `populate()` uses `WP_Query` (safe, parameterized). `sanitize_text_field` on input. No SQL concat.
- **CP Blocks** (1k): SQL `WHERE id=' . $this->item` — admin-only context, no nopriv handlers. Not reachable.

### Batch 8: Directorist, Classified Listing, Ultimate Auction, EventPrime, etc.

- **Directorist** (100k): Nopriv handlers have `directorist_verify_nonce`. REST listings controller has auth checks. `wp_unslash` used but all data goes through `sanitize_text_field`. Safe.
- **Classified Listing** (9k): `rtcl_gallery_upload` has nonce + login + capability check. Safe.
- **Ultimate Auction** (1k): All nopriv handlers have nonce checks. `private_message` uses `esc_html`. `place_bid_now` has nonce. Safe.
- **EventPrime** (8k): REST `__return_true` on `/extensions/combined-status` (low value). AJAX API reads `php://input` (bypasses magic quotes) but all SQL uses `prepare`. No SQLi.
- **Easy Post Submission** (4k): Has nonce check. File upload uses `wp_upload_bits` with auto-generated UUID filename. Validates MIME type (images only). Safe.
- **Frontend Post Submission Manager Lite** (1k): Has nonce. Extension validation (jpg, png, gif, bmp). Also validates against `get_allowed_mime_types()`. Safe.
- **Custom Registration Form Builder** (1k): No SQL with concat. All SQL uses prepare. Safe.

### Batch 9: WP Data Access, Import/Export plugins

- **WP Data Access** (10k): 8 REST endpoints with `__return_true` BUT all callbacks check `current_user_can_access()`. `autocomplete_anonymous` → `autocomplete()` which requires nonce. Table/column names sanitized with `str_replace('`', '')`. Safe.
- **WP Import Export Lite** (1k): Has nonce checks. Uses `wpdb->prepare`. Safe.

### Batch 10: Testimonial, Poll, Quiz, Chat plugins

- **Testimonial Free** (40k): Nopriv handler not found in this version. Shortcode renders form with nonce.
- **Testimonial Slider and Showcase** (20k): `tss_submit_action` has nonce check. `wp_kses_post` on testimonial text (allows some HTML but strips `on*` attributes and `<script>`). File upload via `wp_handle_upload` (validates MIME). Safe.
- **Poll Maker** (7k): `ays_finish_poll` has nonce check. `ays_add_answer_poll` uses `wp_filter_kses` (strips all HTML). All SQL uses `$wpdb->insert` with format specifiers. Safe.
- **Quiz Master Next** (40k): All nopriv handlers have nonce checks. `load_page_questions` has `check_ajax_referer`. `ajax_submit_results` has `wp_verify_nonce`. Unescaped `echo $question_template` is admin-set content (not user input). Safe.
- **Democracy Poll** (7k): Nopriv `dem_ajax` — NO nonce check! BUT user answers sanitized with `wp_kses($val, 'strip')` (strips ALL HTML). Answer text output without `esc_html` at line 452 but HTML was already stripped at storage time. Safe.
- **User Submitted Posts** (10k): `usp_ajax_challenge_nonce` — has nonce check. Safe.
- **Gutena Forms** (20k): `nopriv_gutena_forms_submit` — has nonce check. Safe.
- **WP Ultimate Review** (70k): Checking for nopriv handlers — none found. Safe.
- **GS Testimonial** (1k): Nopriv handler — has nonce check. Safe.
- **Super Testimonial** (2k): Nopriv handler — has nonce check. Safe.

### Batch 11: Recently Updated plugins

- **Handl UTM Grabber** (10k): No nopriv handlers. Stores UTM from `$_COOKIE`/`$_GET`. All SQL uses `$wpdb->prepare`. Safe.
- **Advanced IP Blocker** (2k): REST `/live-attacks` with `__return_true` BUT requires `hash_equals` token check. All AJAX handlers have nonce + `manage_options`. Notification manager SQL uses `(int)` cast on IDs. Safe.
- **Top-10** (10k): `tptn_tracker` nopriv — NO nonce, but all inputs use `absint()`. `taxonomy_search_tom_select` has nonce check. Safe.
- **PW WooCommerce Gift Cards** (20k): `ajax_redeem` and `ajax_remove` both have `check_ajax_referer`. Safe.
- **Simple Ajax Chat** (2k): **VULNERABLE** — see confirmed finding above.
- **Ultimate Maps by Supsystic** (10k): Dynamic nopriv registration via `frame.php`. File uploader uses `wp_handle_upload` with `test_form=false` (validates MIME by default). Safe.
- **Contact Form by Supsystic** (6k): Dynamic nopriv registration. No file upload on frontend. Safe.
- **Independent Analytics** (100k): Nopriv async request for background processing. No user-facing SQL injection. Safe.
- **Image Map Hotspots** (3k): No nopriv handlers found. Safe.
- **Vibe AI** (8k): No nopriv handlers found. Safe.

## Summary Statistics

| Category | Count |
|----------|-------|
| Total plugins scanned | ~170 |
| Confirmed HTTP-exploitable vuln | 1 (Simple Ajax Chat — Stored XSS) |
| Code-level vuln, NOT HTTP-exploitable | 1 (Auto Affiliate Links — SQLi blocked by magic quotes) |
| Safe (nonce + sanitization + prepare) | ~168 |
| Directories used | plugin_audit through plugin_audit11 |
| Extended audit | See `references/mass-audit-findings-batches-12-19.md` (~130 more plugins, batches 12-19) |
| **Grand total (all batches)** | **~300 plugins** |
