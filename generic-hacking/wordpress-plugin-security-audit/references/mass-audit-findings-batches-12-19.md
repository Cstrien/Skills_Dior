# Mass Plugin Audit Findings — Batches 12-19 (August 2026)

Extended audit of ~130 additional plugins across batches 12-19 (directories
`plugin_audit12` through `plugin_audit19`). Total across all batches: ~300 plugins.

## Code-Level Vulnerability (NOT HTTP-Exploitable)

### Newsletter Subscription Form v1.5.8 (1,000 installs) — SQLi ⚠️
- **File:** `options/themes/select_template1.php` lines 250-256
- **Vuln:** Unauthenticated SQL Injection — raw `$_GET` in SQL without `prepare()`
- **Code:**
  ```php
  $act_code = $_GET['act_code'];  // NO sanitization
  $email = $_GET['email'];        // NO sanitization
  $wpdb->get_row("SELECT * FROM `$table_name` WHERE `email` LIKE '$email' AND `act_code` LIKE '$act_code'");
  // Also: $wpdb->query("UPDATE `$table_name` SET `flag` = '1' WHERE `email` = '$email'");
  ```
- **Vector:** GET params `?act_code=X&email=Y` on any page with `[nls_form]` shortcode
- **NOT HTTP-exploitable:** WordPress `wp_magic_quotes()` escapes `'` in `$_GET` — cannot break out of SQL string literal
- **select_template2.php** uses `sanitize_text_field()` + `sanitize_email()` — safe. Only template1 is vulnerable.
- **No existing CVEs** on NVD for this plugin
- **Patchstack:** Reportable as insecure code even without HTTP PoC, but may be rejected without working exploit

## Notable Safe Plugins (Key Patterns)

### MStore API v4.21.1 (3,000 installs) — `isPurchaseCodeVerified()` returns true
- `functions/index.php` line 15: `function isPurchaseCodeVerified() { return true; }` — verification commented out
- ALL REST endpoints technically unauthenticated BUT most require `User-Cookie` header via `validateCookieLogin()`
- Registration allows only safe roles: `seller`, `wcfm_vendor`, `customer`, `subscriber` — no privilege escalation
- `flutter-b2bking.php` `/debug_price` and `/debug_visibility` use `__return_true` but only return plugin settings/b2b pricing — no sensitive data
- Design decision for mobile app, not a vulnerability

### New User Approve v2.x (2,000 installs) — Auth token in admin HTML
- `class-pw-new-user-approve.php` line 664: `wp_generate_password(20, false)` → `update_option('nua_app_auth_token', $token)`
- Token exposed via `wp_localize_script()` on admin pages only
- REST endpoints (`/v1/user-approve`, `/v1/get-dashboard-data`, etc.) use `__return_true` but require `verify_secure_token(FCMToken, deviceId)`
- `verify_secure_token` uses `md5($fcm_token . $device_id)` checked against stored tokens — tokens only issued via `connect_app` which requires `authToken`
- Not exploitable by unauthenticated users

### MultiVendorX v5.0.13 (2,000 installs) — `filter_input_array` sanitization
- `submit_review()`: `filter_input_array(INPUT_POST, [...])` with `FILTER_SANITIZE_FULL_SPECIAL_CHARS` — HTML-entity-encodes all special chars
- `get_reviews()`: Outputs with `esc_html($review->review_title)` and `esc_html($review->review_content)` — safe
- `submit_question()`: Has nonce + requires login + `sanitize_textarea_field` — safe

### WATU v3.4.8 (3,000 installs) — SQL without prepare but intval'd
- `show_exam.php` line 244: `$wpdb->get_results("SELECT * FROM table WHERE exam_id=$exam_id")` — no prepare()
- BUT `$exam_id = intval($_REQUEST['quiz_id'])` on line 4 — value is integer
- Line 39: `$wpdb->get_row($wpdb->prepare("SELECT * FROM ... WHERE ID=%d", $exam_id))` — properly prepared
- Code smell but NOT exploitable

### Echo Knowledge Base v17.212.0 (10,000 installs) — AI chat REST
- `class-epkb-ai-rest-chat-controller.php`: `/ai-chat/start-session` uses `__return_true` for guest access
- `send-message` requires `check_rest_nonce` (session-based) — not unauthenticated
- Admin endpoints require `can_access_settings` capability
- SQL without prepare in `class-epkb-ai-messages-db.php` uses `$this->table_name` (class property, not user input) — safe

### Quill Forms v5.7.1 (3,000 installs) — Form submission
- `class-form-submission.php`: `json_decode(stripslashes($_POST['formData']), true)` — bypasses magic quotes
- Nonce is OPTIONAL (disabled by default via `apply_filters('quillforms_renderer_nonce_verify', false)`)
- Each field value sanitized via `$block_type->sanitize_field()` — safe
- `$_SERVER['HTTP_USER_AGENT']` stored unsanitized — but admin panel is React (auto-escapes)

### Asgaros Forum v3.4.0 (10,000 installs) — SQL without prepare in reactions
- `forum-reactions.php` line 46: `"SELECT r.* FROM ... WHERE p.parent_id = {$topic_id}"` — no prepare()
- `$topic_id` comes from `$this->asgarosforum->current_topic` which is set from database query results (not raw user input)
- REST reactions endpoint uses `__return_true` but requires `is_user_logged_in()` — not unauthenticated
- REST mentioning endpoint uses `__return_true` + `absint($data['topicid'])` + `$wpdb->prepare()` — safe

### Simple Job Board v2.14.4 (10,000 installs) — Process applicant form
- `class-simple-job-board-ajax.php`: Has `check_ajax_referer('jobpost_security_nonce')` + referer check
- `$parent_id = sanitize_text_field($_POST['job_id'])` then `intval()` — safe
- SQL without prepare in `templates/single-jobpost.php` uses `$wpdb->prefix` (constant) — safe

### Gwolle Guestbook (40,000 installs) — `wp_kses($output, array())` strips ALL tags
- `gb-formatting.php` line 50: `wp_kses($output, array())` for content fields — strips all HTML
- `htmlspecialchars_decode($output, ENT_COMPAT)` runs BEFORE kses — decodes entities but kses re-strips
- Double quotes replaced with `&#34;`, single quotes with `&#39;` — safe in attribute context
- Not exploitable for stored XSS

## Full Safe Plugin List (Batches 12-19)

### Batch 12 (Recently Updated)
- **WP PostRatings** (10k): REST `__return_true` but internal nonce + `can_rate()` + `intval()`. Safe.
- **WOOF** (10k): `woof_draw_products` has nonce. Safe.
- **ShipStation** (10k): Nopriv `update-order-review` has nonce + field whitelist. Safe.
- **Breeze** (10k): `woocs_currency_get` has nonce. Safe.
- **BetterLinks** (10k): Analytics tracking uses nonce. Geolocation REST uses `__return_true` but no SQL. Safe.
- **Amelia** (10k): Slim Framework app, well-structured. No SQLi found. Safe.
- **WP Umbrella** (10k): Nopriv handlers have nonce checks. Safe.
- **Quiz Maker** (10k): All nopriv handlers have nonce + capability checks. Safe.

### Batch 13 (Recently Updated)
- **Master Addons** (10k): `jltma_like_dislike` has nonce. Safe.
- **Secure Copy Content Protection** (10k): Nopriv handlers have nonce + capability. `sanitize_email()` + `esc_sql()`. Safe.
- **HurryTimer** (10k): `update_timestamp` has nonce. Safe.
- **GS Logo Slider** (10k): Nopriv `filter_logos` has nonce. WP_Query sanitizes internally. Safe.
- **Ecwid** (10k): `get_product_info` uses `intval()`. Safe.
- **Squirrly SEO** (10k): REST `__return_true` but internal token/signature auth. Safe.
- **Wow Carousel Divi** (10k): REST `__return_true` only reads published content. Safe.
- **Advanced Dynamic Pricing** (10k): `checkNonceOrDie()`. Safe.
- **Advanced Form Integration** (10k): Teamleader REST is OAuth callback. Safe.
- **Mystickyelements** (10k): Form trigger at priority 0, only captures if webhook configured. Safe.
- **WPZoom** (10k): Has nonce. WP_Query args sanitized internally. Safe.
- **Live Sales Notifications** (10k): `getOrders` has nonce. Safe.

### Batch 15 (Low-Install Candidates)
- **DC WooCommerce Multi-Vendor** (2k): `submit_review` has nonce + login + `filter_input_array`. `get_reviews` no nonce but output uses `esc_html`. Safe.
- **DHLPWC** (2k): All nopriv handlers use `wc_clean()`. No SQL. Safe.
- **Info Cards** (2k): `ncbPosts_callback` has nonce. `$queryAttr` unsanitized but goes through WP_Query. Safe.
- **Simple Link Directory** (2k): `qcopd_upvote` has `check_ajax_referer`. Safe.
- **Advanced Free Flat Shipping** (2k): `wp_unslash($_GET['keyword'])` + `sanitize_text_field` in admin context. Safe.
- **B-Pricing Table** (2k): Freemius wrapper, `sanitize_text_field(wp_unslash())`. Safe.
- **Falcon** (2k): REST `__return_true` for `automatic_updater_disabled` filter (not a REST endpoint). SQL without prepare uses `$wpdb->posts` (constants). Safe.

### Batch 16 (Very Low Install)
- **Add to Calendar Button** (3k): No nopriv handlers. Safe.
- **WooCommerce Google Sheet Connector** (3k): Freemius `php://input` in vendor. Safe.
- **MWB Bookings** (3k): Nopriv onboarding + booking retrieval have nonce checks. Safe.
- **W4 Post List** (3k): No nopriv handlers. Safe.
- **Slider Hero** (3k): Nopriv `qcld_sliderhero_actions` has nonce. Safe.
- **Bulglish Permalinks** (3k): No nopriv handlers. Safe.
- **MStore API** (3k): See detailed analysis above. Design decision, not a vuln.
- **Before/After Image Compare** (3k): `icbPremiumChecker` nopriv but only checks license status. Safe.
- **Themify Event Post** (3k): No nopriv handlers. Safe.
- **Caddy** (3k): REST `__return_true` on interactivity API but only reads cart data. Safe.
- **Helper Lite for PageSpeed** (3k): No nopriv handlers. Safe.
- **Advanced Local Pickup** (3k): REST `__return_true` on customizer endpoints but admin-only context. Safe.
- **WATU** (3k): See detailed analysis above. intval'd, not exploitable.
- **HT Menu Lite** (3k): `templates_ajax_request` has nonce. Safe.

### Batch 17 (Form/Forum/Chat Plugins)
- **Asgaros Forum** (10k): See detailed analysis above. DB-derived topic_id, safe.
- **BP Better Messages** (10k): Nopriv `better_messages_new_nonce_token` just returns a nonce. REST `__return_true` but session-based auth. Safe.
- **WPForo** (20k): Widget AJAX handlers use nonce. `__return_true` only for admin loading filters. Safe.
- **Echo Knowledge Base** (10k): See detailed analysis above. AI chat has session auth. Safe.
- **Simple Job Board** (10k): See detailed analysis above. Nonce + referer check. Safe.
- **WP Photo Album Plus** (10k): `wppa_get()` centralizes sanitization via filter system. REST `__return_true` but only returns public photo data. Safe.
- **myCred** (10k): `mycred-click-points` nopriv but uses `intval()` + nonce. `php://input` in BitPay gateway (payment callback). Safe.
- **Disqus** (30k): No nopriv handlers (comments managed by Disqus servers). Safe.
- **GeoDirectory** (10k): Nopriv handlers via `geodir_ajax` wrapper. REST `__return_true` for post types (public data). Safe.

### Batch 18 (Small Plugins)
- **Quill Forms** (3k): See detailed analysis above. Field sanitization per block type. Safe.
- **Slider Hero** (3k): Nonce check. Safe.
- **TotalPoll Lite** (1k): `totalpoll` nopriv route but uses nonce + sanitization. Action Scheduler vendor SQL uses constants. Safe.

### Batch 19 (Very Small Plugins)
- **Email Subscribe** (1k): `store_email_callback` has nonce + `sanitize_email()` + `sanitize_text_field()`. SQL without prepare only for COUNT(*) (no user input). Safe.
- **SendPress** (1k): Nopriv `subscribe_to_list` has nonce. REST `__return_true` on autocron/sending but internal auth. `php://input` used for API endpoints with token auth. Safe.
- **Testimonial Maker** (1k): `tml_submit_testimonial` has nonce + `sanitize_text_field` + `sanitize_textarea_field`. Post inserted as 'pending'. Safe.
- **ePoll WP Voting** (1k): Nopriv `it_epoll_vote` has nonce + `sanitize_text_field` + `intval`. Safe.
- **Retainful** (1k): Nopriv tracking handlers use `wffn_clean` (sanitize_text_field). REST `__return_true` but no sensitive data. `php://input` in Input helper for cart tracking. Safe.
- **Atarim Visual Collaboration** (1k): REST `/status` `__return_true` returns version/connection status only. `php://input` handler requires `manage_options` + nonce. SQL without prepare in Ninja/Fluent form integrations (admin context). Safe.
- **CF7 Message Filter** (1k): Freemius vendor `php://input`. No nopriv. Safe.
- **Feedbucket** (1k): No nopriv handlers found. Safe.
- **Stars Testimonials** (1k): `wp_kses_post(wp_unslash())` on content. Nonce on save. Safe.
- **Business Reviews WP** (1k): No nopriv handlers found. Safe.
- **Newsletter Subscription Form** (1k): See SQLi finding above. Code-vulnerable but NOT HTTP-exploitable.
- **Benchmark Email Lite** (1k): REST `__return_true` on block rendering but only returns public content. Safe.
- **WPDataTables Forminator** (1k): No nopriv handlers found. Safe.
- **Social Share Button** (1k): No nopriv handlers found. Safe.
- **Share Social Media** (1k): No nopriv handlers found. Safe.
- **JSON API User** (1k): Uses deprecated JSON API plugin. Register has nonce + `sanitize_user` + `sanitize_email`. Role hardcoded to `default_role`. `update_user_meta` requires valid cookie + disallows capability meta keys. `generate_auth_cookie` uses `wp_authenticate()`. Safe.

### Batch 20 (Frontend/Upload/User Plugins)
- **Rate My Post** (20k): 4 nopriv handlers (load_results, process_rating, process_feedback, process_rating_amp). All have nonce check + `sanitize_text_field` + token verification. Safe.
- **Advanced Gutenberg** (20k): 3 nopriv (contact_form_save, newsletter_save, lores_validate). All have nonce + `sanitizeFormPostField`. Safe.
- **File Manager** (10k): `connector_front` is nopriv with `nonce:public` middleware. BUT default guest permissions: `commands=[]`, `path=''` → no volumes accessible, all commands disabled. Safe by default — only dangerous if admin explicitly configures guest access with a writable path.
- **Funnel Builder** (30k): Nopriv `frontend_analytics` + `tracking_events` use `wffn_clean` (sanitize). REST `__return_true` only for analytics tracking. Safe.
- **UsersWP** (20k): `get_ajax_events()` returns all `nopriv=false`. `ayecode_connect_helper` nopriv only returns boolean. `wp-async-request` requires secret identifier. Safe.
- **WP Telegram** (30k): `php://input` in PostSender for Telegram webhook. `__return_true` filters are internal (not REST). Safe.
- **Image Hover Effects Ultimate** (20k): Nopriv `image_hover_ultimate` has nonce. SQL without prepare uses `$table` (constant from class property). Safe.
- **Media Library Organizer** (20k): REST `__return_true` on Themeisle SDK (internal, not REST). SQL without prepare in import/migration (admin context, constants). Safe.
- **PublishPress Authors** (20k): CMB2 `nopriv_cmb2_oembed_handler` — oEmbed preview. `__return_true` on CMB2 internal filters. SQL without prepare on `SHOW TABLES` (constant). Safe.
- **Co-Authors Plus** (20k): `pre_handle_404` `__return_true` (not REST). SQL without prepare uses `$tt_id` from validated taxonomy. Safe.
- **Simple User Avatar** (20k): No nopriv handlers. Safe.
- **WP Image Zoom** (10k): No nopriv handlers. Safe.
- **Frontend Reset Password** (10k): No nopriv handlers. Safe.
- **Image Prioritizer** (40k): No nopriv handlers. Safe.
- **What The File** (40k): No nopriv handlers. Safe.
- **File Upload Types** (40k): No nopriv handlers. Safe.

## Summary Statistics (Batches 12-20)

| Category | Count |
|----------|-------|
| Total plugins scanned | ~150 |
| Confirmed HTTP-exploitable vuln | 0 |
| Code-level vuln, NOT HTTP-exploitable | 1 (Newsletter Subscription Form — SQLi blocked by magic quotes) |
| Safe (nonce + sanitization + prepare) | ~149 |
| Directories used | plugin_audit12 through plugin_audit20 |

## Combined Statistics (All Batches)

| Category | Count |
|----------|-------|
| Total plugins scanned (all batches) | ~320 |
| Confirmed HTTP-exploitable vuln | 1 (Simple Ajax Chat — Stored XSS) |
| Code-level vuln, NOT HTTP-exploitable | 2 (Auto Affiliate Links, Newsletter Subscription Form) |
| Safe | ~317 |
| Directories used | plugin_audit through plugin_audit20 |

## Key Patterns That Make Plugins Safe (Frequency)

1. **Nonce check via `check_ajax_referer()`** — present in ~95% of nopriv handlers
2. **`sanitize_text_field()` on all user inputs** — strips tags, prevents XSS
3. **`$wpdb->prepare()` for all SQL** — prevents SQLi
4. **`absint()` / `intval()` on ID parameters** — prevents SQLi
5. **Capability checks (`current_user_can`, `manage_options`)** — prevents privilege escalation
6. **`wp_kses($output, array())` or `wp_filter_kses()`** — strips all HTML, prevents stored XSS
7. **`wp_handle_upload()` instead of `wp_upload_bits()`** — validates MIME type
8. **`esc_html()` / `esc_attr()` on output** — prevents reflected/stored XSS
9. **Default-safe guest permissions** — file manager plugins default to `commands=[], path=''` for unauthenticated users (opt-in required for guest access)
10. **Deprecated JSON API dependency** — plugins extending the old JSON API plugin use `sanitize_user()`, `sanitize_email()`, and nonce checks similar to modern REST API

## Scanning Efficiency Notes

- The WordPress.org API `request[browse]=updated` with `request[per_page]=100` is the most efficient way to get recently updated plugins
- Searching by keyword (`request[search]=form+chat`) yields more relevant results than browsing
- Plugins with 100-1000 installs are the least audited but also have the lowest Patchstack value (may be below 1,000 install threshold)
- The 1,000-3,000 install range is the sweet spot: enough installs for Patchstack acceptance, but not large enough to have been security-audited
- `grep -rn` with `--include=*.php` and `-E` flag is the fastest pattern scanner; `execute_code` with subprocess is reliable for batch scanning
- **Exhaustive `wp_unslash($_GET/$_POST)` cross-reference with raw SQL**: After 20 batches, only 2 code-level SQLi found and both blocked by magic quotes. The pattern `wp_unslash()` + raw SQL that would bypass magic quotes is extremely rare in the wild — most plugin developers use `$wpdb->prepare()`. REST API + raw SQL (which bypasses magic quotes) is the highest-value remaining search target but was not found in any of the ~320 plugins scanned.
- **Cross-batch `wp_unslash` + raw SQL search**: Running `grep -rn 'wp_unslash.*\$_GET\|wp_unslash.*\$_POST'` across ALL audit directories while filtering for files that also contain `$wpdb->query/get_results/get_var/get_row.*\$` found ~50+ files with `wp_unslash` but every single one also applied `sanitize_text_field()`, `intval()`, or `absint()` before the SQL. This confirms that the WordPress ecosystem has largely internalized the "unslash then sanitize" pattern correctly.
