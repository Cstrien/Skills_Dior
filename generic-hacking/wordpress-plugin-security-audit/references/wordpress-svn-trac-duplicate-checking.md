# WordPress SVN Trac Duplicate Checking

When auditing WordPress plugins, existing CVEs may cover the same or a different
vector. Use the WordPress.org SVN Trac to determine whether a finding is truly novel
or a duplicate before submitting to Patchstack.

## NVD Search

```python
import urllib.request, json
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<plugin+name>&resultsPerPage=20"
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
data = json.loads(urllib.request.urlopen(req, timeout=15).read())
for vuln in data.get('vulnerabilities', []):
    cve = vuln['cve']
    print(cve['id'], cve['descriptions'][0]['value'][:200])
    for ref in cve.get('references', []):
        print("  ", ref['url'])
```

Note the affected version ranges and any changeset URLs in the references.

## Examining Fix Changesets

A CVE reference often links to a Trac changeset:
```
https://plugins.trac.wordpress.org/changeset/<revision>/<plugin_slug>
```

Trac pages are JS-rendered. Use `browser_navigate` then `browser_console`:

```javascript
// Extract all diff tables
var tables = document.querySelectorAll('table');
var results = [];
for (var t of tables) {
  var text = t.innerText;
  if (text && text.length > 10) results.push(text.substring(0, 2000));
}
results.join('\n\n--- TABLE ---\n\n')
```

Key questions to answer from the diff:
1. **Which files were modified?** If the vulnerable file you found is NOT in the changeset, the CVE fix did not address your vector.
2. **What was the actual fix?** Was it client-side JS, server-side PHP, or just a version bump?
3. **Did the fix address the same parameter?** A CVE for the 'c' parameter doesn't cover the chat text parameter.

## File-Specific Revision Log

To check if a specific file was modified after the CVE fix:

```
https://plugins.trac.wordpress.org/log/<plugin_slug>/trunk/<filename>
```

This shows every revision that touched the file. Compare:
- The CVE fix changeset revision number
- The latest revision that touched your vulnerable file

If the CVE fix revision doesn't appear in the file's log, your vector was NOT fixed.

## Decision Matrix

| Scenario | Duplicate? | Action |
|----------|------------|--------|
| Same file, same parameter, same mechanism | YES | Do not submit |
| Same file, different parameter | MAYBE | Argue different root cause |
| Different file, same plugin, same vuln type | MAYBE | Show fix changeset didn't touch your file |
| Different file, different mechanism | LIKELY NO | Strongest case for novelty |
| Same plugin, already has 3+ CVEs for same type | RISK | Triager may auto-reject as duplicate |

## Worked Example: Simple Ajax Chat

- CVE-2026-2987: "Stored XSS via 'c' parameter" (versions ≤ 20260217)
- Fix changeset 3472258 (v20260301) changed: `readme.txt`, `resources/sac.php` (JS), `simple-ajax-chat.php`
- `simple-ajax-chat-form.php` was NOT in the changeset → server-side PHP not fixed
- File log for `simple-ajax-chat-form.php`: last modified in r3611800 (v20260717), not the CVE fix
- Conclusion: CVE-2026-2987 fixed only the JS client-side auto-linking. The PHP server-side `preg_replace` with `\S*` is a different, unpatched vector.

## Risk: Triager May Still Reject

Even with clear evidence of a different vector, Patchstack triagers may reject if:
- The same plugin already has multiple CVEs for the same vuln type
- The "site-wide" requirement isn't met (XSS only on shortcode pages)
- The CVSS is below the threshold

Mitigate by clearly stating in the report: "Existing CVE X fixed file Y, but file Z at line N still has [different mechanism]. Verified on latest version."
