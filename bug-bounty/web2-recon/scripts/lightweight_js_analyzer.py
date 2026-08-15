#!/usr/bin/env python3
"""
Lightweight zero-dependency JS analyzer for recon.
Extracts URLs, API paths, and keyword context snippets from a directory of JS files.
Useful as a fallback when SecretFinder/LinkFinder are unavailable, slow, or failing.
Usage: python3 lightweight_js_analyzer.py /path/to/js/dir
"""
import sys, re
from pathlib import Path

def analyze_js(directory):
    base = Path(directory)
    if not base.exists() or not base.is_dir():
        print(f"Directory not found: {directory}")
        sys.exit(1)

    urls, paths, snippets = set(), set(), []
    # Customize keywords based on target context (e.g., GraphQL, payments, auth)
    kw = re.compile(r'(?i)(api|auth|login|token|graphql|kyc|account|portfolio|trade|withdraw|deposit|otp|password|recaptcha|client[_-]?id|secret|endpoint|baseurl|axios|fetch\()')
    
    # Regex for paths - adjust prefixes as needed based on the target's routing
    path_regex = re.compile(r'[\"\'`](/(?:api|auth|login|signup|account|portfolio|trade|kyc|withdraw|deposit|graphql|users?|v[0-9]|onboarding|dashboard|verify|otp|password)[^\"\'`<> ]*)[\"\'`]')
    
    for p in base.rglob('*.js'):
        try:
            s = p.read_text(errors='ignore')
            urls.update(re.findall(r'https?://[^\"\'`<> ){\[\]]+', s))
            paths.update(path_regex.findall(s))
            
            for m in kw.finditer(s):
                # Capture context window around the keyword
                sn = s[max(0, m.start()-120):min(len(s), m.end()+180)].replace('\n', ' ')
                snippet_entry = f'{p.name}: {sn[:400]}'
                if snippet_entry not in snippets:
                    snippets.append(snippet_entry)
        except Exception as e:
            pass

    print(f"Analyzed {len(list(base.rglob('*.js')))} files.")
    print(f"Found {len(urls)} URLs, {len(paths)} paths, and {len(snippets)} keyword snippets.")
    
    Path('js_urls.txt').write_text('\n'.join(sorted(urls)))
    Path('js_paths.txt').write_text('\n'.join(sorted(paths)))
    Path('js_snippets.txt').write_text('\n\n'.join(snippets))
    print("Results written to js_urls.txt, js_paths.txt, and js_snippets.txt in current directory.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 lightweight_js_analyzer.py <js_directory>")
        sys.exit(1)
    analyze_js(sys.argv[1])
