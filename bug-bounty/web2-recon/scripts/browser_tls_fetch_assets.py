#!/usr/bin/env python3
"""Fetch a web page and its JS/CSS assets with browser TLS impersonation.

Use when normal curl/headless browser hits CDN/WAF protocol errors, HTTP/2 errors,
timeouts, or bot-fingerprint blocks, but the goal is passive recon: retrieve HTML,
asset URLs, JavaScript bundles, and cookies for endpoint mapping.

Requires: pip install curl_cffi
Example:
  python3 browser_tls_fetch_assets.py https://www.example.com out/example --impersonate chrome120
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import urllib.parse

try:
    from curl_cffi import requests
except ImportError:
    print("Missing dependency: pip install curl_cffi", file=sys.stderr)
    raise SystemExit(2)


def safe_name(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.strip("/") or "index"
    if parsed.query:
        path += "_" + parsed.query[:80]
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", path)
    return name[-180:]


def absolutize(base_url: str, value: str) -> str:
    if value.startswith("//"):
        return "https:" + value
    return urllib.parse.urljoin(base_url, value)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("outdir")
    ap.add_argument("--impersonate", default="chrome120", help="curl_cffi impersonation profile, e.g. chrome120/chrome124/safari17_0")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--max-assets", type=int, default=200)
    args = ap.parse_args()

    out = pathlib.Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    session = requests.Session(impersonate=args.impersonate, timeout=args.timeout)
    headers = {
        "accept-language": "en-US,en;q=0.9",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    }

    r = session.get(args.url, headers=headers)
    print(f"HTML {r.status_code} {len(r.content)} {r.url}")
    (out / "index.html").write_bytes(r.content)
    (out / "response_headers.txt").write_text("\n".join(f"{k}: {v}" for k, v in r.headers.items()), encoding="utf-8")

    html = r.text
    urls: set[str] = set()
    for m in re.finditer(r"(?:src|href)=['\"]([^'\"]+)['\"]", html, flags=re.I):
        urls.add(absolutize(str(r.url), m.group(1)))
    (out / "asset_urls.txt").write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")

    asset_count = 0
    for u in sorted(urls):
        if asset_count >= args.max_assets:
            break
        if not re.search(r"\.(?:js|css)(?:[?#].*)?$", u, re.I):
            continue
        try:
            ar = session.get(u, headers={"accept": "*/*"})
            print(f"ASSET {ar.status_code} {len(ar.content)} {u}")
            if ar.status_code == 200 and ar.content:
                (out / safe_name(u)).write_bytes(ar.content)
                asset_count += 1
        except Exception as e:  # keep mapping even if one asset fails
            print(f"ASSET_ERR {u} {type(e).__name__}: {e}")

    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
