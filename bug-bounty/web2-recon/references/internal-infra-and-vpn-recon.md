# Internal Infrastructure & VPN Recon

Session-derived recon patterns for discovering and probing internal infrastructure exposed via sibling domains, VPN portals, and observability tools. Use when env configs or JS bundles reference internal domains (e.g. `diftech.net`, `diftech.org`) that differ from the target's primary domain.

## 1. Sibling domain discovery from env configs

SPAs embed full environment configs as inline `<script type="application/json">` tags. These configs frequently reference sibling domains, internal infrastructure, and third-party services that are not visible in subdomain enumeration of the primary target domain.

```bash
# Extract all URLs from inline env JSON
curl -sk "https://$TARGET" | grep -oP '<script[^>]*type="application/json"[^>]*>.*?</script>' | \
  grep -oP 'https?://[^\s"'"'"']+' | sort -u

# Common fields that leak sibling domains:
# - sentry.dsn → reveals internal hostname (e.g. sentry.prime.diftech.org)
# - apiUrls.* → API gateway on different subdomain
# - telegrafApiUrl / analytics.collectorUrl → telemetry endpoints
# - abApiUrl → A/B testing API (test unauth feature flag access)
```

After extracting sibling domains, run full subdomain enumeration on each:
```bash
for domain in diftech.net platacard.mx; do
  subfinder -d $domain -silent -timeout 3
  curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | awk -F',' '{print $1}'
done | sort -u
```

## 2. Cisco ASA VPN group enumeration

Cisco ASA VPN portals return an unauthenticated XML response on `GET /` that leaks all configured VPN group names. These reveal internal org structure and enable targeted brute-force attacks.

```bash
# Cisco ASA VPN (XML auth response)
curl -sk "https://vpn.$TARGET/" | grep -oP '<option value="[^"]+"'
# Returns: vpn-devops, vpn-developers, vpn-pentest-co, etc.

# Cisco AnyConnect VPN (HTML logon page)
curl -sk "https://cvpn.$TARGET/+CSCOE+/logon.html" | grep -oP 'action="[^"]*"'
# SAML endpoint: /+CSCOE+/saml/sp/login (test for CVE-2023-20269)

# Submit auth attempt to check response (does NOT login — wrong creds)
curl -sk -X POST -d "username=test&password=test&group_list=vpn-devops" "https://vpn.$TARGET/auth"
```

**VPN type fingerprinting:**
- Cisco ASA: XML response with `<config-auth>` root, `<option>` group list
- Cisco AnyConnect: HTML at `/+CSCOE+/logon.html`, SAML at `/+CSCOE+/saml/sp/login`
- Pritunl: HTML login page at `/login`, API at `/api` returns 401
- NetBird: Next.js dashboard, API at `/api/*` returns 401 JSON `{"message":"no valid authentication provided","code":401}`
- OpenVPN: typically returns HTML or redirects

## 3. Sentry DSN extraction and testing

Sentry DSNs in client-side configs reveal internal infrastructure hostnames and project IDs.

```bash
# Extract DSN from env config
# DSN format: https://{key}@{host}/{project_id}
curl -sk "https://$TARGET" | grep -oP 'sentry[^}]*"dsn"\s*:\s*"[^"]+"'

# Test if Sentry API is accessible
curl -sk "https://$SENTRY_HOST/api/0/" | head -5
curl -sk "https://$SENTRY_HOST/api/0/projects/" | head -5

# Test envelope endpoint (responds with auth validation messages)
curl -sk -X POST "https://$SENTRY_HOST/api/$PROJECT_ID/envelope/" \
  -H "Content-Type: text/plain" \
  -d '{"event_id":"test","sent_at":"2026-01-01T00:00:00Z"}'
# Response: {"detail":"bad envelope authentication header","causes":["missing field `dsn`..."]}
```

**Risk:** The Sentry hostname itself reveals internal infrastructure (e.g. `sentry.prime.diftech.org` → `diftech.org` domain). The DSN key could be used to inject crafted error events or query error data if project auth is weak.

## 4. S3 bucket via Cloudflare proxy

Some subdomains serve as Cloudflare proxies to non-public S3 buckets. The bucket returns `AccessDenied` on direct S3 access, but the Cloudflare proxy serves the listing and object contents.

```bash
# Check for S3 bucket listing on subdomain
curl -sk "https://$SUBDOMAIN/" | grep -i "ListBucketResult"
# Extract bucket name from XML
curl -sk "https://$SUBDOMAIN/" | grep -oP '<Name>[^<]+</Name>'
# Try direct S3 (should fail)
curl -sk "https://$BUCKET_NAME.s3.amazonaws.com/" | head -5
# The x-amz-bucket-region header on the 403 confirms bucket exists + leaks region
curl -sI "https://$BUCKET_NAME.s3.amazonaws.com/" 2>/dev/null | grep -i x-amz-bucket-region
```

**Lesson:** A `403 AccessDenied` on the direct S3 URL does NOT mean the bucket is private. Always check if a subdomain proxies to it. The `x-amz-bucket-region` header on the direct S3 response confirms the bucket exists and leaks its region even on denied requests.

## 5. NetBird dashboard API probing

NetBird is a WireGuard-based VPN solution with a Next.js dashboard and a REST API. The API returns 401 JSON for all endpoints without a valid token, but the endpoint structure is predictable.

```bash
# NetBird API endpoints (all return 401 without auth)
for ep in /api/users /api/peers /api/groups /api/setup-keys /api/policies /api/routes /api/networks /api/events /api/accounts; do
  curl -sk -m 5 "https://$NETBIRD_HOST$ep" | head -1
done
# All return: {"message":"no valid authentication provided","code":401}
```

**Pitfall:** NetBird's `/api/accounts` POST endpoint may allow registration if open registration is enabled. Test with an empty POST body — a 404 means registration is disabled, a 400 means the endpoint exists and is processing the request.

## Pitfalls

- Internal IPs in DNS records (e.g. `ip-10-192-1-116.diftech.net`) may not resolve externally — they are PTR records for internal RFC1918 addresses, not discoverable subdomains. Don't waste time probing them.
- VPN portals that return 000 (connection timeout) may be behind a security group that only allows specific source IPs. The fact that they resolve but don't connect is itself a finding (infrastructure existence confirmation).
- Multiple VPN solutions may coexist (Cisco ASA + Pritunl + NetBird + OpenVPN) — fingerprint each one independently as they have different CVEs and attack surfaces.
- `cvpn.*` subdomains typically use Cisco AnyConnect (redirects to `/+CSCOE+/logon.html`), while `vpn.*` subdomains use Cisco ASA (XML auth response).
