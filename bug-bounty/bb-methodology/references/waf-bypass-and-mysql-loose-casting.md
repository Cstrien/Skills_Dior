# WAF Rule Detection, Secure Gateway Pattern, and MySQL Loose Type Casting

Three patterns from the sandbox-royal.securegateway.com engagement (Aug 2026). Each is a class-level pattern that recurs on targets with aggressive WAFs or MySQL backends.

---

## §1. Systematic WAF Rule Detection (Character-by-Character Mapping)

### When to use

Any target where initial SQLi/XSS probes return 302/403/503 instead of the app's normal response. Instead of blindly trying bypass payloads, FIRST map exactly what the WAF blocks and what it allows.

### Methodology

Send each keyword/character individually (sandwiched between a unique marker like `hkm9xq2z4test{KEYWORD}hkm9xq2z4end`) to the endpoint and check if it passes through or gets WAF-blocked:

```python
import urllib.request, urllib.parse, ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

keywords = [
    # SQL
    "OR", "AND", "UNION", "SELECT", "SLEEP", "BENCHMARK", "extractvalue",
    "updatexml", "CONCAT", "version", "database", "information_schema",
    "LOAD_FILE", "INTO", "OUTFILE", "INSERT", "UPDATE", "DELETE", "DROP",
    "CREATE", "ALTER",
    # XSS
    "script", "alert", "onerror", "onload", "onmouseover", "javascript",
    "vbscript", "img", "svg", "iframe", "eval", "document",
    # Special chars
    "'", '"', "<", ">", "=", ";", "(", ")",
]

for kw in keywords:
    payload = f"hkm9xq2z4test{kw}hkm9xq2z4end"
    encoded = urllib.parse.quote(payload)
    # Send to endpoint, check response
    # WAF block = "302 Found" or "Secure Gateway" in response
    # PASSED = marker appears in response body
    # FILTERED = marker appears but keyword stripped/encoded
```

### Classification

| Response | Meaning | Action |
|-----------|---------|--------|
| `302 Found` / WAF error page | WAF blocked the keyword | Need bypass for this keyword |
| Marker + keyword both in response | Keyword passes through unfiltered | Can use in payloads |
| Marker in response but keyword missing | App strips/encodes the keyword | Try encoding bypasses |
| WAF error page with Rule ID (e.g. `Rule=G.S.941170`) | OWASP ModSecurity rule ID | Look up rule to find bypass |

### Key insight: WAFs block PATTERNS, not individual keywords

Individual keywords like `OR`, `UNION`, `SELECT` may pass through when sent alone, but the WAF blocks them when combined with spaces and quotes (e.g. `' OR 1=1`, `UNION SELECT`). The WAF is matching SQL injection PATTERNS (regex rules), not individual tokens.

### What to do with the map

Once you know which characters/keywords are blocked:
- If `<` and `>` are blocked but `'` and `(` pass → try JS-context XSS (string breakout)
- If all SQL keywords are blocked → focus on other vuln classes (IDOR, business logic, info disclosure)
- If the app escapes `'` → `\'` in JS context → try double-encoding or Unicode escapes
- If `#` (MySQL comment) passes but `--` doesn't → use `#` for SQLi comment injection

### Secure Gateway WAF characteristics

| Feature | Behavior |
|---------|----------|
| Non-browser UA | 302 redirect to phone verification page |
| SQL keywords in patterns | 302 redirect to WAF error page |
| `<` character | Stripped from response body |
| `>` character | 302 WAF block |
| `;` character | 302 WAF block |
| Single/double quotes | Pass WAF, app escapes as `\'` `\"` |
| `#` MySQL comment | Passes WAF |
| `--` SQL comment | WAF blocked |
| Event handlers (onerror, onload) | WAF blocked as combined patterns |
| All encoding bypasses (UTF-7, UTF-16, overlong, double-encode, null byte) | WAF blocked |
| Phone verification challenge | `/admin` returns 307 for curl, loads in browser |
| WAF error page | `/msg/sg_err.php?err=XX&SG_ID=...&Rule=G.S.XX` |

---

## §2. MySQL Loose Type Casting as Enumeration Vector

### Symptom

A search/lookup endpoint accepts a numeric ID (tracking number, order ID, user ID) and returns different responses for found vs not-found. The backend SQL query uses string comparison: `WHERE tracking_number = 'INPUT'`.

### Detection

Send the valid ID with a non-numeric suffix. If it still matches, the query uses MySQL loose type casting:

```bash
# Valid tracking number
curl -d "trackingSrch=375301304" https://target/search.php
# → "not-reply" (found)

# Append a letter — if it STILL matches, loose casting is in play
curl -d "trackingSrch=375301304a" https://target/search.php
# → "not-reply" (STILL found — MySQL casts '375301304a' to integer 375301304)
```

### How it works

MySQL's type casting rules for string-to-integer comparison:
- `'375301304a'` → `375301304` (trailing non-numeric chars stripped)
- `'375301304.5'` → `375301304` (decimal truncated to int in integer context)
- `'00375301304'` → `375301304` (leading zeros ignored)
- `'375301304e0'` → `375301304` (scientific notation parsed)
- `'abc'` → `0` (no leading digits → casts to 0)
- `' 375301304'` → `375301304` (leading whitespace ignored)

### Exploitation

Combined with **no rate limiting**, this allows:
1. Enumerate valid IDs by sending sequential numbers
2. The loose casting means brute-force attempts with appended characters all match the same record (can be used to confirm a hit without knowing the exact ID)
3. If the endpoint returns PII (name, phone, complaint text), this is an IDOR/information disclosure

### Important: distinguish from SQL LIKE injection

MySQL loose casting and SQL LIKE wildcards (`%`, `_`) produce DIFFERENT behaviors:

| Input | LIKE `'INPUT%'` | Loose cast `= 'INPUT'` |
|-------|----------------|----------------------|
| `375301304` | Match (exact) | Match (exact) |
| `375301304%` | Match (wildcard) | Match (cast to 375301304) |
| `37530130%` | Match (prefix wildcard) | No match (cast to 37530130, different number) |
| `375301304a` | No match (LIKE is string comparison) | Match (cast to 375301304) |
| `%` | Match ALL records | No match (cast to 0) |

**Key test:** `37530130%` returns "no-tracking" but `375301304a` returns "not-reply" → this is loose casting, NOT LIKE injection. The `%` at position 9 makes it a different integer (37530130), while `a` at position 10 is stripped by the cast.

---

## §3. CDN-to-GitHub Source Code Disclosure

### Symptom

The target loads JavaScript from a CDN that proxies a GitHub repository:
```html
<script src="https://cdn.jsdelivr.net/gh/royalglobalcms/lib/ideabox/ticker.js"></script>
```

The `cdn.jsdelivr.net/gh/` prefix means the source is a **public GitHub repository**.

### Detection

Extract the GitHub org/repo from the CDN URL:
```bash
# From: https://cdn.jsdelivr.net/gh/royalglobalcms/lib/ideabox/ticker.js
# Org: royalglobalcms
# Repo: lib
curl -s "https://api.github.com/repos/royalglobalcms/lib" | jq '.private, .size'
# false  → repo is PUBLIC
```

### What to look for in the repo

```bash
# Full file tree
curl -s "https://api.github.com/repos/ORG/REPO/git/trees/main?recursive=1" | jq '.tree[].path'

# Check for secrets in all files
curl -s "https://raw.githubusercontent.com/ORG/REPO/main/path/to/file.js" | grep -iE 'api_key|secret|password|token|key'

# Check commit history for accidentally committed secrets
curl -s "https://api.github.com/repos/ORG/REPO/commits?per_page=20" | jq '.[].commit.message'
```

### When this is a finding

- In bug-bounty mode: Only if the source code reveals secrets (API keys, DB credentials) or enables exploitation of a specific vulnerability. Source code availability alone is informational.
- In pentest/WAPT mode: Report as informational — source code aids attacker understanding of the application.

### Royal CMS GitHub repo contents (example)

The `royalglobalcms/lib` repo contained:
- `builder/` — Admin form builder (dts-ar-builder.js)
- `codemirror/` — Code editor for admin panel
- `tinymce/` — Rich text editor
- `textEditor/` — Custom WYSIWYG editor
- `ideabox/` — Breaking news ticker (with rss2json API key reference)
- `sweetalert/`, `select2/`, `toastr/` — UI libraries

No secrets were found, but the admin builder code reveals the CMS's internal structure and form handling.

---

## Engagement source

sandbox-royal.securegateway.com (Royal CMS behind Secure Gateway WAF), August 2026.

| Finding | Severity | Pattern |
|---------|----------|---------|
| No rate limiting on all form endpoints | MEDIUM | §2 exploitation amplifier |
| PHPSESSID missing HttpOnly + Secure | LOW | Session security misconfig |
| Complaint tracking number enumeration via loose casting | LOW | §2 |
| CSRF token in JS + no SameSite cookie | LOW | CSRF weakness |
| Public GitHub repo (royalglobalcms/lib) | INFO | §3 |

The WAF (Secure Gateway) was extremely effective — blocked all SQLi/XSS bypass attempts including 30+ encoding variants. The app also properly escaped quotes in JS context and stripped `<` in HTML context. Findings were all in the business-logic/session-management layer, not injection.
