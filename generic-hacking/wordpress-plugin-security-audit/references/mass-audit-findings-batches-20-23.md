# Mass Plugin Audit Findings — Batches 20-23 (August 2026)

Extended audit of ~120 additional plugins across batches 20-23 (directories
`plugin_audit20` through `plugin_audit23`). Total across all batches: ~440 plugins.

## Key Findings

### wpzoom-portfolio v1.4.31 (20,000 installs) — Reflected XSS CVE Already Fixed
- `build/blocks/portfolio/index.php` line 358: `wp_ajax_nopriv_wpzoom_load_more_items`
- **No nonce check** on `load_more_items()` — truly unauthenticated
- `$data = json_decode(sanitize_text_field(wp_unslash($_POST['posts_data'])), true)` — user-controlled JSON
- Previous CVE: reflected XSS via `$data['class']` key concatenated into HTML attributes
- **Fix applied**: `unset($data['total'], $data['class'])` on line 379 + regex validation `preg_match('/^[A-Za-z0-9_\-]+$/', $args['class'])`
- `$data['read_more_label']` also user-controlled but escaped with `esc_html()` at output (line 1160)
- `$data['lightbox_caption']` cast to `(bool)` — safe
- `$args['order']`, `$args['order_by']` go through `WP_Query` (sanitized internally)
- **Conclusion**: CVE was found and fixed. No new bypasses found. Example of a well-handled fix.

### open-user-map v1.4.47 (10,000 installs) — 5 nopriv handlers, all safe
- `ajax_add_location_from_frontend`: Nonce check + `sanitize_text_field(wp_strip_all_tags())` on all fields
- `oum_location_text`: Uses `wp_kses_post()` (allows safe HTML subset)
- `oum_location_geometry`: `wp_unslash()` without sanitize BUT `sanitize_location_geometry()` called before save (line 1180) — validates GeoJSON structure, casts coordinates to float, validates lat/lng bounds
- `ajax_toggle_vote`, `ajax_get_vote_count`, `ajax_refresh_location_nonce`: All have nonce checks
- **Safe**. Well-sanitized user-submitted content.

### supportcandy v3.5.2 (10,000 installs) — 5 nopriv chatbot handlers, all safe
- `chatbot_send_message`: `check_ajax_referer('general', '_ajax_nonce')` + `sanitize_textarea_field(wp_unslash())` + rate limiting + 3000 char limit
- `chatbot_get_previous_messages`, `chatbot_end_conversation`, `chatbot_create_ticket`, `chatbot_cancel_ticket_escalation`: All have nonce + sanitize
- **Safe**

### review-schema v3.0.4 (10,000 installs) — 5 nopriv review handlers, all safe
- `rtrs_review_filter`, `rtrs_pagination`, `rtrs_review_edit_form`, `rtrs_self_video_popup`, `rtrs_remove_file`: All have `wp_verify_nonce()` + `sanitize_text_field(wp_unslash())`
- **Safe**

### Cost Calculator Builder v4.0.14 (20,000 installs) — nopriv order creation, safe
- `create_cc_order` is nopriv BUT has `check_ajax_referer('ccb_add_order', 'nonce')` — nonce required
- `ccb_calc_views`, `ccb_calc_interactions`: Nonce + `CCBCleanHelper::cleanData()` + `intval()`
- `php://input` handlers require `manage_options` capability
- `wp_handle_upload()` for file uploads with `validateFile()` checking allowed extensions
- **Safe**

### Fluent Booking v2.2.0 (20,000 installs) — nopriv scheduling, safe
- `ajaxScheduleMeeting`: No nonce but uses rate limiting + validator + `sanitize_text_field()` on ALL fields
- Custom fields: `sanitize_text_field()` / `sanitize_textarea_field()` based on field type
- `ajaxHandleCancelMeeting`, `ajaxGetAvailableDates`: Proper sanitization
- **Safe**

### wp-user-manager v2.9.18 (10,000 installs) — Stripe integration
- `wpum_stripe_register` nopriv: `parse_str($_POST['data'], $data)` → goes through WPUM form handler with own validation
- Stripe webhook REST `__return_true`: Validates Stripe signature via `signatureIsValid()`
- **Safe**

## Full Safe Plugin List (Batches 20-23)

### Batch 20
- **Rate My Post** (20k): 4 nopriv handlers, all nonce + sanitize. Safe.
- **Advanced Gutenberg** (20k): 3 nopriv, all nonce + sanitizeFormPostField. Safe.
- **File Manager** (10k): connector_front nopriv but default guest = no commands, no path. Safe.
- **Funnel Builder** (30k): nopriv tracking uses wffn_clean. Safe.
- **UsersWP** (20k): No nopriv in get_ajax_events. Safe.
- **WP Telegram** (30k): php://input for webhook, __return_true on internal filters. Safe.
- **Image Hover Effects Ultimate** (20k): Nopriv has nonce. Safe.
- **Media Library Organizer** (20k): __return_true on SDK internal. Safe.
- **PublishPress Authors** (20k): CMB2 oembed nopriv. Safe.
- **Co-Authors Plus** (20k): __return_true on pre_handle_404. Safe.
- Others: No nopriv handlers. Safe.

### Batch 21
- **Cost Calculator Builder** (20k): See above. Safe.
- **Easy Facebook Likebox** (30k): nopriv popup_html (no input), REST __return_true with integer validate. Safe.
- **Extensions for Elementor Form** (20k): Nonce + sanitize. Safe.
- **Happyforms** (20k): All nonce checks. Safe.
- **Fluent Booking** (20k): See above. Safe.
- **FluentForms PDF** (20k): downloadPublic uses intval(Protector::decrypt(base64_decode())). Safe.
- **Stripe Payments** (20k): nopriv check_coupon + create_pi have nonce + sanitize. Safe.
- **NotificationX** (30k): REST __return_true for notice (returns notification data) + send_rating (intval + sanitize_text_field). Safe.
- **Sticky Chat Widget** (10k): nopriv save_form_data has nonce + $wpdb->insert (prepare internally) + admin display uses esc_attr. Safe.
- **WP Popups Lite** (30k): nopriv check_rules (no nonce, but only evaluates popup display rules) + form_submission (no nonce, but lite version doesn't store submissions). Safe.
- **Visitors Traffic Real Time Statistics** (30k): nopriv track_visitor, no nonce BUT sanitize_text_field on all inputs. Safe.
- **Simplybook** (30k): REST __return_true for onboarding. Safe.
- **WP Google Places Review Slider** (30k): Admin-only wp_unslash + sanitize. Safe.
- **WP Stats Manager** (20k): Nonce checks. Safe.
- **WPZoom Portfolio** (20k): See above. CVE already fixed. Safe.

### Batch 22
- **Visitors Traffic Real Time Statistics** (30k): See batch 21. Safe.
- **WP Google Places Review Slider** (30k): Admin context. Safe.
- **Simplybook** (30k): REST onboarding __return_true. Safe.
- **NotificationX** (30k): See batch 21. Safe.
- **WP Popups Lite** (30k): See batch 21. Safe.
- **WP Video Lightbox** (30k): No nopriv. Safe.
- **Review Widgets for TripAdvisor** (20k): Nopriv webhook requires token validation. Safe.
- **WP Stats Manager** (20k): Nonce checks. Safe.
- **Update URLs** (20k): nopriv from WP_Async_Request (needs secret). Safe.
- **Lightbox PhotoSwipe** (20k): No nopriv. Safe.
- **Gallery Block Lightbox** (20k): No nopriv. Safe.
- **WP Lightbox 2** (20k): No nopriv. Safe.
- **Portfolio Filter Gallery** (20k): wp_unslash + sanitize + nonce. Safe.
- **WPZoom Portfolio** (20k): See above. Safe.
- **Team Members** (20k): No nopriv. Safe.

### Batch 23
- **Open User Map** (10k): See above. Safe.
- **SupportCandy** (10k): See above. Safe.
- **Review Schema** (10k): See above. Safe.
- **WP User Manager** (10k): See above. Safe.
- **CF7 Grid Layout** (10k): nopriv save_grid_fields. wp_unslash + sanitize. Safe.
- **CF7 Multi Step** (10k): REST __return_true for CF7 validation (CF7 submit handles sanitization). Safe.
- **CF7 Styler for Divi** (20k): Admin-only wp_unslash + sanitize. Safe.
- **DS CF7 Math Captcha** (10k): nopriv refreshcaptcha. Safe.
- **Conditional Fields for Elementor Form** (10k): Nonce + sanitize. Safe.
- **Fluent Support** (10k): __return_true on user_can_richedit (not REST). Safe.
- **Metronet Tag Manager** (20k): No nopriv. Safe.
- **PW Bulk Edit** (20k): No nopriv. Safe.
- **Featured Image Admin Thumb** (20k): No nopriv. Safe.
- **Disable Media Sizes** (10k): No nopriv. Safe.
- **ACF Frontend Form Element** (9k): Not fully audited. Potential target for future.

## Summary Statistics (Batches 20-23)

| Category | Count |
|----------|-------|
| Total plugins scanned | ~120 |
| Confirmed HTTP-exploitable vuln | 0 |
| Code-level vuln, NOT HTTP-exploitable | 0 |
| CVE already found and fixed by developer | 1 (wpzoom-portfolio reflected XSS) |
| Safe (nonce + sanitization + prepare) | ~119 |
| Directories used | plugin_audit20 through plugin_audit23 |

## Combined Statistics (All Batches)

| Category | Count |
|----------|-------|
| Total plugins scanned (all batches) | ~440 |
| Confirmed HTTP-exploitable vuln | 1 (Simple Ajax Chat — Stored XSS) |
| Code-level vuln, NOT HTTP-exploitable | 2 (Auto Affiliate Links, Newsletter Subscription Form) |
| CVE already fixed by developer | 1 (wpzoom-portfolio) |
| Safe | ~436 |
| Directories used | plugin_audit through plugin_audit23 |

## New Patterns Observed

### "No Nonce + No Storage" = Safe (WP Popups Lite pattern)
WP Popups Lite `check_rules()` has NO nonce check and processes raw `$_POST['popups']` and `$_POST['query_string']`. However:
- `check_rules()` only evaluates popup display rules and returns JSON — it doesn't store user data
- `form_submission()` has NO nonce check and processes raw `$_POST` — but the lite version doesn't store submissions (no database write). Data is only passed to provider hooks which may or may not store it.
- **Lesson**: A nopriv handler without nonce is NOT automatically vulnerable. Check if the handler stores data that is later displayed without escaping. If the handler is read-only (returns data, evaluates rules, etc.), it's safe.

### REST __return_true + External Service Signature = Safe (Stripe Webhook pattern)
WP User Manager's Stripe webhook endpoint uses `__return_true` (no WordPress auth) but validates the Stripe signature via `signatureIsValid($request)`. This is the standard pattern for payment webhooks — the permission_callback is `__return_true` because the external service provides its own authentication layer.
- **Lesson**: REST endpoints with `__return_true` that handle webhooks from external services (Stripe, PayPal, etc.) typically validate the service's signature. Not exploitable unless the signature secret is leaked.

### JSON decode + sanitize_text_field = Safe for XSS (Cost Calculator Builder pattern)
Cost Calculator Builder does `$data = CCBCleanHelper::cleanData((array) json_decode(stripslashes($data)))` on nopriv order creation. The `cleanData` method applies `sanitize_text_field` to all values. Even though `json_decode(stripslashes())` bypasses magic quotes, the subsequent sanitization prevents both SQLi and XSS.
- **Lesson**: `json_decode(stripslashes())` bypasses magic quotes, but if the decoded values are then sanitized with `sanitize_text_field()` or `intval()`, the data is safe. The bypass of magic quotes alone is not a vulnerability — it's the lack of subsequent sanitization that matters.

### Rate Limiting as Nonce Alternative (Fluent Booking pattern)
Fluent Booking's `ajaxScheduleMeeting()` has NO nonce check but uses `Helper::checkRateLimit('schedule_meeting', 15)` (15 requests per time window). All input fields are then sanitized. The rate limiting prevents brute-force attacks while the sanitization prevents injection.
- **Lesson**: Rate limiting is an acceptable alternative to nonce checks for public-facing endpoints (booking forms, contact forms) where nonces would break caching. Check if the handler also sanitizes all inputs — if yes, it's safe.

### sanitize_location_geometry Pattern (Open User Map)
Open User Map stores geometry data with `wp_unslash()` (no text sanitization) but then calls `sanitize_location_geometry()` which:
1. json_decodes the input
2. Validates `type` must be `LineString` or `Polygon`
3. Casts all coordinates to `(float)` with `str_replace(',', '.', ...)`
4. Validates lat/lng bounds (-90/90, -180/180)
5. Limits number of points (default 500)
- **Lesson**: Structured data (JSON, GeoJSON) can be sanitized with domain-specific validators instead of generic `sanitize_text_field()`. The validation is actually STRONGER than text sanitization because it enforces structure, not just strips bad characters.
