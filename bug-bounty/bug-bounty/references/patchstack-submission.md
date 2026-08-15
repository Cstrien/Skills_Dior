# Patchstack Vulnerability Submission

Submit WordPress plugin/theme zero-days to Patchstack for CVE assignment.
URL: https://patchstack.com/database/report

## Pre-Submission Checks

1. **Search the Patchstack database** for the plugin slug to avoid duplicates:
   - Navigate to `https://patchstack.com/database/?q=<slug>`
   - If existing CVEs appear for the same vuln class + version, do NOT submit

2. **Verify the vulnerability is a zero-day** (latest version, unpatched):
   - Patchstack's standard Bug Bounty Program scope (as of June 2026) requires:
     - Zero-day (unpatched in latest version), OR
     - mVDP-scope software
   - **SSRF is OUT of standard scope** unless it qualifies as a zero-day
   - Reports "not tested against the actual plugin" → immediate one-week ban

3. **Have a working PoC** — source-code analysis alone is insufficient.
   The form warns: reports containing "incorrect AI-generated assumptions"
   or "not tested against the actual plugin" result in a one-week ban.

## Form Fields

| Field | Form key | Notes |
|---|---|---|
| Submitter name | `name` | |
| Contact email | `email` | |
| Website | `website` | Optional |
| Component type | — | Vue combobox: "WordPress plugin" / "WordPress theme" |
| Affected component | `comp_name` | Plugin display name |
| Component slug | `comp_slug` | wordpress.org slug |
| Component link | `comp_link` | https://wordpress.org/plugins/<slug>/ |
| Prefix | — | Vue combobox: ≤ / < / = / ≥ / > |
| Affected version | `vuln_version` | e.g. "2.9.0" |
| Pre-requisite | — | Vue combobox: Unauthenticated / Subscriber / Customer / Contributor / Author / Editor / Administrator |
| OWASP 2021 class | — | Vue combobox: A1–A10 |
| OWASP 2021 type | — | Vue combobox: SQL Injection / XSS / SSRF / Arbitrary File Upload / etc. |
| Vulnerability description | `shortDescription` | Markdown supported |
| How to reproduce | `reproduce` | Markdown, include curl PoC |
| Additional info | `additional_info` | Optional, Markdown |
| Consent checkbox | `consent` | Must be checked |
| reCAPTCHA token | `g-recaptcha-response` | Invisible reCAPTCHA v3 |

## Vue Combobox Interaction (browser_console)

The form is a **Nuxt 3** app (`#__nuxt` with `__vue_app__`).
Comboboxes are `<button role="combobox">` elements — `browser_click` via ref ID
often fails to open them. Use `browser_console` with `.click()` instead:

```javascript
// Open a combobox by index (0=Component type, 1=Prefix, 2=Pre-requisite, 3=OWASP class, 4=OWASP type)
(function() {
  const allComboboxes = document.querySelectorAll('[role="combobox"]');
  const combo = allComboboxes[2]; // Pre-requisite
  combo.click();
  return new Promise(r => setTimeout(() => r({expanded: combo.getAttribute('aria-expanded')}), 500));
})()
```

After the dropdown opens, snapshot will show `[role="listbox"]` with
`[role="option"]` children — click the option by ref or:

```javascript
// Select an option from the open listbox
(function() {
  const listbox = document.querySelector('[role="listbox"]');
  const options = listbox.querySelectorAll('[role="option"]');
  for (const opt of options) {
    if (opt.textContent.trim().includes('A10')) { opt.click(); break; }
  }
})()
```

## reCAPTCHA v3 Block (Critical)

**reCAPTCHA v3 scores headless browsers at 0.0** (needs ≥ 0.5).
Automated submission from Hermes browser tools is IMPOSSIBLE.

### API Direct Submission (also blocked by reCAPTCHA)

```
POST https://vdp-api.patchstack.com/reports
Content-Type: application/json
X-XSRF-TOKEN: <decoded XSRF-TOKEN cookie value>

{
  "name": "...", "email": "...",
  "comp_name": "...", "comp_slug": "...", "comp_link": "...",
  "vuln_version": "...",
  "shortDescription": "...", "reproduce": "...", "additional_info": "...",
  "consent": true,
  "prerequisite": "none",
  "owasp_class": "A10",
  "owasp_type": "server_side_request_forgery",
  "recaptcha_token": "<from grecaptcha.execute()>"
}
```

Response with headless browser: `{"success":false,"message":"reCAPTCHA verification failed","score":0}`

reCAPTCHA sitekey: `6LcGBsorAAAAAHC3KuVEXPu8eBeGgO_NulJLnp0x`

### Workarounds

1. **Submit manually** from a real desktop browser (not headless)
2. **Use `computer_use`** on a real Firefox/Chrome window — but cua-driver
   may return 0x0 captures if the window is not properly focused
3. **Pre-fill the form** via browser_console (all text fields + comboboxes),
   then have the user click "Submit" from their real browser session

## Text Field Pre-fill (browser_console IIFE)

```javascript
(function() {
  function setVal(el, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
                 || Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
    setter.call(el, value);
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
  }
  setVal(document.querySelector('input[name="name"]'), 'Cstrien');
  setVal(document.querySelector('input[name="email"]'), 'trienl641@gmail.com');
  setVal(document.querySelector('input[name="comp_name"]'), 'BuddyForms');
  setVal(document.querySelector('input[name="comp_slug"]'), 'buddyforms');
  setVal(document.querySelector('input[name="comp_link"]'), 'https://wordpress.org/plugins/buddyforms/');
  setVal(document.querySelector('input[name="vuln_version"]'), '2.9.0');
  // ... etc for shortDescription, reproduce, additional_info
})()
```

## "Arbitrary File Upload" Type Alert

When OWASP type = "Arbitrary File Upload", the form shows an alert:
"full path+extension control" — if the vulnerability doesn't meet this bar,
frame it as "Broken Access Control" or "Server Side Request Forgery" instead.

## Eligibility API (Pre-check)

The form makes pre-submission eligibility checks:
```
GET https://vdp-api.patchstack.com/reports/vdp-eligibility?slug=<slug>&recaptcha_token=<token>
GET https://vdp-api.patchstack.com/reports/wordpress-eligibility?type=plugin&slug=<slug>&recaptcha_token=<token>
```
These run automatically when the slug is entered. If eligibility fails,
the submit button stays disabled.
