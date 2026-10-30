#!/usr/bin/env python3
"""Categorize a projectdiscovery httpx -o output file.

Usage: python categorize_httpx.py httpx_out.txt

Separates the 'interesting' hosts from a wide probe (default pages, env-tier hosts,
mesh-routed apps, login portals) and prints counts + the interesting subsets.
Regex assumes the standard httpx -status-code -title -tech-detect -web-server -content-length
line format:  https://host [code] [location] [clen] [title] [webserver] [tech]
"""
import re
import sys
from collections import Counter

PAT = re.compile(
    r'^(https?://\S+?)\s+\[(\d+)\]\s+\[(.*?)\]\s+\[(\d+)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]$'
)

def main(path):
    rows = []
    for line in open(path, errors="replace"):
        m = PAT.match(line)
        if m:
            url, code, loc, clen, title, ws, tech = m.groups()
            rows.append(dict(url=url, code=code, loc=loc, clen=clen, title=title, ws=ws, tech=tech))

    status = Counter(r["code"] for r in rows)
    print("total:", len(rows))
    print("status:", dict(status.most_common()))

    sig = {
        "azure_func_default": [],
        "welcome_nginx": [],
        "artifactory": [],
        "envoy_istio": [],
        "env_hosts": [],
        "forms_auth_login": [],
        "kestrel": [],
        "drupal": [],
        "blazor": [],
    }
    for r in rows:
        t = (r["url"] + " " + r["title"] + " " + r["ws"] + " " + r["tech"]).lower()
        if "azure function app is up and running" in t: sig["azure_func_default"].append(r)
        if "welcome to nginx" in t: sig["welcome_nginx"].append(r)
        if "artifactory" in t or "jfrog" in t: sig["artifactory"].append(r)
        if "envoy" in t or "istio" in t: sig["envoy_istio"].append(r)
        if re.search(r"\.(dev|stage|staging|qa|uat|test|sandpit|sandbox|preview)\.", r["url"], re.I):
            sig["env_hosts"].append(r)
        if "/login.aspx" in r["loc"].lower() or "access is denied" in t: sig["forms_auth_login"].append(r)
        if "kestrel" in t: sig["kestrel"].append(r)
        if "drupal" in t: sig["drupal"].append(r)
        if "blazor" in t: sig["blazor"].append(r)

    for k, v in sig.items():
        print(f"\n### {k}: {len(v)}")
        for r in v[:40]:
            print(f"  {r['url']} [{r['code']}] {r['title']}")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))