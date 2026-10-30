# WP Plugin Lab Validation Playbook

Validate a production plugin build's unauthenticated REST surface on a local WordPress
lab before writing any report. Condensed from a 2026-09 engagement (wb4wp / Bluehost
Website Builder v1.0-2781 on a Kali LAMP lab). Companion to
`conditional-rest-route-registration-pattern.md` (inline-gate pattern) — this file
covers the vendor-zip → lab-validation pipeline and the active_plugins trap.

## 1. Obtain the exact production build

WP vendors expose version APIs that return the deployed zip directly:

```
GET https://{vendor-versions-host}/content/{brand}-version.json
→ {"new_version":"1.0-2781","last_updated":"...","package":"https://.../plugin-production.zip",
   "plugin":".../plugin.php","requires_php":"5.4","requires_wp":"4.7","version":"2781",...}
```

Worked example: `wp-versions.builderservices.io/content/bluehost-version.json` →
`wb4wp-wordpress-plugin-bluehost-production.zip`. Download, unzip, audit FIRST-PARTY
code under `src/` (ignore `vendor/`). This is the exact code running in production —
better ground truth than wordpress.org latest.

Also watch the plugin's `.env` sentinel constants (`{PROVIDER}`, `{ENV}`) in production
builds — they drive Environment_Helper and can hide error messages (§3).

## 2. Install + activate cleanly (the active_plugins trap)

- Copy into `wp-content/plugins/<slug>/`, `chown -R www-data:www-data`.
- **NEVER** write `wp_options.active_plugins` by hand via `mysql -e "UPDATE ..."`:
  shell quoting corrupts the serialized value, and a single trailing newline in
  `option_value` breaks `unserialize()` → `get_option('active_plugins')` returns
  `false` → `in_array(): Argument #2 must be of type array, false given` fatal in
  `wp-admin/includes/plugin.php:663` on ANY plugin activation, and the plugin
  silently stops loading (REST routes 404, namespace missing from `/wp-json/`).
- Correct one-step fix/activate (computes serialization correctly, no shell quoting):

```bash
wp eval 'update_option("active_plugins",
  array("other-plugin/other.php","vendor-slug/vendor-file.php"), true);
  echo "UPDATED";' --path=/var/www/html/wordpress --allow-root
wp plugin activate <slug> --path=/var/www/html/wordpress --allow-root
```

- Verify load: `GET /wp-json/` shows the namespace; `/wp-json/<ns>/v1/ping` returns 200.
- Canonical-host trap: `wp_options.siteurl/home` dictate which Host the app answers
  on. If siteurl is `http://10.10.16.102`, curling `127.0.0.1` returns 000/404 weirdness
  — always test the canonical host.

## 3. Reveal hidden error messages (dev-mode .env trick)

Production builds hide real exception text behind environment sentinels:

```php
// Environment_Helper: '{ENV}' === env('WB4WP_ENVIRONMENT') ? PRODUCTION : $env
// Api_Manager::api_error(): if environment === PRODUCTION → message = "Internal Server Error!"
```

Fix: drop a `.env` INTO THE PLUGIN DIR (the plugin loads Dotenv from its own dir with
`->required([...])` — ALL required keys must be present or bootstrap fails):

```
WB4WP_PLUGIN_VERSION=1.0-2781
WB4WP_ENVIRONMENT=development
WB4WP_PROVIDER=bluehost
WB4WP_APP_GATEWAY_URL=http://127.0.0.1
WB4WP_APP_URL=http://127.0.0.1
WB4WP_APP_DASHBOARD_URL=http://127.0.0.1
```

**`WB4WP_PROVIDER` is mandatory for POST endpoints that touch `Provider_Helper`**
(site-save flows). The production zip ships with the `{PROVIDER}` sentinel: if the
stored `wb4wp_provider` option is empty/unset AND the .env omits the key,
`get_provider()` returns `''` → `self::$providers[null]` → 500 with
`Undefined array key "" @ src/helpers/class-provider-helper.php:19` on every
`save_site` call, while GET routes keep working. Two-step fix: set the key in .env
AND `DELETE FROM wp_options WHERE option_name='wb4wp_provider'` (a load-time
`Options_Helper::set(WB4WP_PROVIDER, env(...))` persists the empty value into the DB,
so the .env fix alone doesn't take). Then re-request.

Now 500s return the real message: `{"success":false,"message":"Undefined array key \"footer\""}`.
Errno field in the JSON is the PHP error level: `0` = Exception, `2` = E_WARNING
(undefined key), `8192` = E_DEPRECATED.

## 4. Noise control (PHP 8.x + WP_DEBUG)

- `WP_DEBUG=true` re-enables `E_DEPRECATED` at runtime regardless of php.ini
  (`error_reporting = E_ALL & ~E_DEPRECATED` in php.ini is overridden), and 8.4-era
  vendor libs (lcobucci/jwt, vlucas/phpdotenv) deprecation-storm.
- The plugin's own REST error handler gates on `error_reporting() & $errno`, so
  deprecations inside plugin files surface as 500s and mask the real flow. Suppress
  with a mu-plugin (loads before regular plugins):

```php
// wp-content/mu-plugins/99-deprec.php
<?php error_reporting(E_ALL & ~E_DEPRECATED);
```

- A custom `set_error_handler()` in the plugin overrides any mu-plugin handler for
  its own files — the mu-plugin only helps pre-gate the reporting level, which is
  enough.
- PHP notices (e.g. `_load_textdomain_just_in_time`) PREFIX wp-json responses and
  break `json.loads` on the client. Salvage: parse from the first `{"`
  (`body[body.find('{"'):]` in Python; `raw[raw.find('{"'):]` in general).

## 5. Schema bootstrapping via the "Undefined array key" oracle

Complex POST endpoints (site-model savers) need the vendor editor's exact payload
shape. Don't reverse-engineer minified editor bundles first:

1. Send minimal JSON → 500 with `Undefined array key "X"`.
2. Add field `X` (nested where the handler expects it) → next 500 names the next key.
3. Iterate. Real sequence on wb4wp `/save_site`: `footer` → `layout` → `weight`
   (fonts must be `"Name:weight"` strings in one place, name/weight objects elsewhere)
   → `siteModel` → `""`. A few minutes of round-trips maps the required schema.
4. For a KNOWN-GOOD baseline, capture the request the vendor's own editor sends from
   the real logged-in app (browser devtools), then replay with modified fields
   (featureScript/baseStyle/apiKeys). This beats guessing nested structures like
   headerSection.layout.section.id + binding._toggle maps.

## 6. Evidence bar

Critical/High findings need two independent tools (curl + python urllib at minimum)
with consistent status codes/bodies, paste-ready commands in the report, and a
before/after state diff from the lab (post created/published, option written, file
written to uploads) — not just a changed error message. For state-changing unauth
POSTs, show the attacker-set value persisting (e.g. `wp_options.wb4wp_api_keys`
contains attacker data, or the injected page renders in the site).
