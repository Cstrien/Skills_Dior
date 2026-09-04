# Batch 7 Additional Audited Plugins (2026-08-13)

Plugins audited during the 500+ plugin mass scan that were not already
documented in `batch-scan-500-plus-plugins-2026.md`. All confirmed safe.

## gpt3-ai-content-generator v10.x (10,000 installs)

- **19 nopriv handlers** — highest count in the batch
- `aipkit_get_frontend_chat_nonce` is a nopriv **nonce faucet** — issues
  `aipkit_frontend_chat_nonce` to unauthenticated users by design
- All other nopriv handlers call `check_frontend_permissions()` which
  verifies the nonce via `check_ajax_referer('aipkit_frontend_chat_nonce')`
- `ajax_delete_single_conversation` also checks `get_current_user_id()` +
  `session_id` ownership — can't delete other users' conversations
- File upload handlers (`ajax_upload_and_parse_file`, `ajax_handle_frontend_file_upload`)
  check nonce + require Pro plan
- **Verdict:** Safe — nonce faucet pattern with ownership checks

## quiz-master-next (40,000 installs)

- `qsm_create_quiz_nonce` — nopriv nonce generator (by design, for public quizzes)
- `ajax_submit_results` — checks `wp_verify_nonce('qsm_submit_quiz_' . $quiz_id)`
- `qsm_ajax_login` — checks nonce + is login handler (Rule 84 reject if brute force)
- `load_page_questions` — checks `check_ajax_referer('qsm_lazy_load_' . $quiz_id)`
- **Verdict:** Safe — all handlers check per-quiz nonce

## simple-membership (40,000 installs)

- All 10 nopriv handlers are PayPal/Stripe payment + email/username validators
- `handle_onboarded_callback_data` checks `check_ajax_referer`
- `validate_email_ajax` checks `check_ajax_referer('swpm-rego-form-ajax-nonce')`
- **Verdict:** Safe

## ays-popup-box (50,000 installs)

- `ays_pb_install_plugin` — checks nonce + `ays_pb_can_install()` (capability)
- `ays_pb_activate_plugin` — checks nonce + `current_user_can('activate_plugins')`
- `ays_pb_change_status` — checks nonce (admin-only nonce, not frontend-exposed)
- `deactivate_plugin_option` — checks nonce + `current_user_can('manage_options')`
- **Verdict:** Safe — all dangerous handlers have nonce + cap

## boldgrid-backup (50,000 installs)

- 9 nopriv handlers for backup/restore/download
- `is_valid_call()` validates with `hash_equals()` on backup_id + cron_secret
- Not a nonce — uses a shared secret stored in plugin settings
- `public_download` requires the same shared secret
- **Verdict:** Safe — shared-secret validation with `hash_equals()`

## booking (50,000 installs)

- 16 nopriv handlers with dynamic action registration
- `ajax_WPBC_AJX_BOOKING__CREATE` — checks `check_ajax_referer` conditionally
  (`wpbc_is_use_nonce_at_front_end()` setting controls this)
- `ajax_WPBC_AJX_AVAILABILITY` — registered for logged-in users only (nopriv line commented out)
- **Verdict:** Safe — nonce checked inside handler functions

## nex-forms-express-wp-form-builder v9.2.5 (6,000 installs)

- 5 nopriv handlers: `submit_nex_form`, `nf_resend_email`, `nf_send_nf_email`,
  `nf_add_form_view`, `nf_add_form_interaction`
- NONE have nonce or capability checks
- `submit_nex_form` — public form submission (by design for form plugins)
- `nf_send_mail` — reads `$_POST['data']`, sends email based on form settings
- Action names do NOT have leading underscore (registration is
  `wp_ajax_nopriv_submit_nex_form` not `wp_ajax_nopriv__submit_nex_form`)
- **Verdict:** Not exploitable for Patchstack — public form submission is by
  design. No nonce = CSRF, but Rule 84 rejects (spam/brute force)

## woo-product-table v6.1.3 (5,000 installs)

- 5 nopriv handlers, none with nonce or cap
- `wpt_fragment_empty_cart` — calls `WC()->cart->empty_cart()` — empties
  caller's cart session (per-session, not cross-user)
- `wpt_ajax_add_to_cart` — adds product to caller's cart
- `wpt_ajax_multiple_add_to_cart` — multiple products to caller's cart
- **Verdict:** Not submittable — Rule 47 (cart/price tampering). Cart
  operations are per-session, not cross-user impact

## data-tables-generator-by-supsystic v1.14.2 (10,000 installs)

- Dynamic nopriv registration: `wp_ajax_nopriv_supsystic-tables` only when
  route module/action is in `$frontendMethods['ajax']` list AND
  `!is_user_logged_in()`
- Frontend methods limited to: `saveEditableFields`, `getPageRows`,
  `saveEditableFieldsFile`, `deleteEditableFieldsFile`, `sendTableToEmail`
  (and `productsAddToCart` for WooCommerce)
- `_checkNonce()` verifies against `dtgs_nonce` (admin-only, created with
  `is_admin() && current_user_can('administrator')`)
- `_checkNonceFrontend()` verifies against `dtgs_nonce_frontend` (frontend,
  created with `!is_admin()`)
- `getPageRowsAction` and `productsAddToCartAction` check BOTH nonces:
  `if (!$this->_checkNonce($request) && !$this->_checkNonceFrontend($request))`
- Other frontend methods (`saveEditableFields`, `saveEditableFieldsFile`,
  `deleteEditableFieldsFile`, `sendTableToEmail`) don't exist as functions
  in the controller — the frontend method list references non-existent
  actions, so those nopriv handlers never fire
- `sendMailAction` and `viewAction` have NO nonce but are NOT in the
  frontend methods list → nopriv hook never registered for them
- **Verdict:** Safe — frontend nonce not exposed for admin operations,
  dead frontend method references

## content-protector / Passster (installs unknown)

- 5 REST endpoints with `__return_true`:
  `/unlock`, `/hash`, `/captcha`, `/logout`, and one more
- `/hash` — hashes any password with HMAC-SHA256 using site secret key.
  Returns hash. This is BY DESIGN — the plugin uses client-side hashing
  for password protection (client compares hash with stored hash)
- `/unlock` — validates password against stored hash, unlocks content
- `/captcha` — validates reCAPTCHA/hCaptcha token
- `/logout` — clears session cookie
- **Verdict:** Safe — all endpoints are intentionally public

## erp (10,000 installs)

- `__return_true` only on: `/genders`, `/marital-statuses`,
  `/education-result-types`, `/performance-ratings`
- These return static dropdown option lists for HR forms — no sensitive data
- All other endpoints check `current_user_can('erp_view_list')` etc.
- **Verdict:** Safe — `__return_true` only on static data
