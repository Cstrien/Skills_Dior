# MCP Server Endpoint Reconnaissance

Session-derived from deep analysis of `mcp.neon.tech` and `preview-mcp.neon.tech`
(both Vercel-hosted Next.js apps serving Neon's MCP server). Capture proven so future
MCP-server hunts don't re-discover from scratch.

## What an MCP server looks like on the wire

MCP (Model Context Protocol) servers deployed as remote HTTP services expose their
transports through a single catch-all API route, not separate REST endpoints. On
Vercel/Next.js the tell-tale is `x-matched-path: /api/[transport]` with
`x-nextjs-rewritten-path` showing the actual path segment.

### Discovering endpoints from the 401 response

When you hit a protected MCP path unauthenticated, the `WWW-Authenticate` header
contains a **`resource_metadata`** URL — the MCP spec's OAuth protected-resource
indicator. This is the single most useful header for endpoint discovery:

```
WWW-Authenticate: Bearer error="invalid_token", error_description="No authorization provided",
  resource_metadata="https://mcp.neon.tech/.well-known/oauth-protected-resource/sse"
```

That URL reveals:
1. The path that was protected (`/sse`, `/mcp`, `/api/mcp`, any `/api/*`)
2. The `.well-known/oauth-protected-resource/{path}` convention
3. That this is a standard MCP OAuth public client

### Standard MCP paths to probe

| Path | Transport | Typical behavior |
|---|---|---|
| `/sse` | Legacy SSE transport | 401 without token; EventSource stream with |
| `/mcp` | Streamable HTTP (MCP spec 2025-03-26) | 401 without token; POST with `initialize` |
| `/api/mcp` | Same as above, explicit `/api/` prefix | 401 |
| `/messages` | Often SSE companion for client→server messages | 404 or 401 |
| `/api/messages` | Same, via catch-all | 401 (catch-all) |

### Key `.well-known/` paths

| Path | Purpose |
|---|---|
| `/.well-known/oauth-authorization-server` | Full OAuth metadata — issuer, endpoints, scopes, grant types |
| `/.well-known/oauth-protected-resource` | Resource server metadata (auth_servers, bearer_methods) |
| `/.well-known/oauth-protected-resource/{path}` | Per-path protected resource metadata |
| `/.well-known/openid-configuration` | OIDC discovery (usually NOT present on pure MCP servers) |

## OAuth flow analysis for MCP servers

### The authorization-server metadata response

```json
{
  "issuer": "https://mcp.neon.tech",
  "authorization_endpoint": "https://mcp.neon.tech/api/authorize",
  "token_endpoint": "https://mcp.neon.tech/api/token",
  "registration_endpoint": "https://mcp.neon.tech/api/register",
  "revocation_endpoint": "https://mcp.neon.tech/api/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["read", "write", "*"],
  "x-neon-scope-categories": ["projects", "branches", "schema", "querying", "neon_auth", "data_api", "docs"]
}
```

Key things to note:
- **`registration_endpoint` present** → dynamic client registration (RFC 7591) is
  enabled. Test it with an unauthenticated POST.
- **`none` in `token_endpoint_auth_methods_supported`** → public client support
  (PKCE-only flow, no client_secret needed at token exchange).
- **`*` in scopes_supported** → wildcard scope granting exists.
- **Custom `x-*` scope categories** → enumerate the server's API surface.

### Dynamic client registration test

If `registration_endpoint` exists, try unauthenticated registration:

```bash
curl -sS -X POST "https://$HOST/api/register" \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"test","redirect_uris":["http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}'
```

Neon's MCP server returns a client_id + client_secret. This is the standard
behavior of an RFC 7591-compliant server, not a vulnerability per se. See if
other servers accept wider redirect URIs (e.g., `http://evil.com/cb`).

### Authorization consent page

With registered client_id, `GET /api/authorize?response_type=code&client_id=xxx&redirect_uri=...&code_challenge=xxx&code_challenge_method=S256&scope=read&state=xyz`
returns an HTML consent page. Look for:
- Hidden form fields (state, scopes)
- Form action URL (where consent is POSTed)
- Whether state is visible/truncated in HTML
- Whether scope selection is user-controlled or fixed

## Assessing client functionality post-OAuth

1. Obtain OAuth token (server-side flow, requires valid user session at IdP).
2. Send MCP `initialize` request:

```bash
curl -X POST "https://$HOST/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'
```

3. Follow with `tools/list`, `resources/list`, `prompts/list` to enumerate capabilities.

## Gradual testing for unknown auth state

If you don't know whether a path is protected, probe these headers:

- **`x-matched-path`** — Vercel/Next.js leak showing the matched route pattern. Catch-all
  routes like `/api/[transport]` indicate everything under `/api/*` is treated as MCP
  transport.
- **`x-nextjs-rewritten-path`** — shows the rewritten destination (e.g., `/api/sse`).
- **`x-vercel-cache`** — `MISS` vs `Bypass` differentiates fresh responses.
- **`www-authenticate`** — presence confirms OAuth protection; `resource_metadata`
  reveals the discovery endpoint.

## Source maps on Vercel/Next.js

Check `.js.map` for every first-party chunk, not just those with `sourceMappingURL`:

```bash
while read js; do
  curl -skL --max-time 8 -o /tmp/mapcheck -w "%{http_code} %{size_download}" "${js}.map"
  echo ""
done < js_urls.txt
```

In practice on Neon's MCP servers:
- Most chunk maps return 404 (minified, no source maps deployed).
- One shared polyfill chunk (`a6dad97d9634a72d.js`) has a `.map` returning 200, but
  it's a Next.js polyfill (no application source).

Always verify the downloaded map is valid JSON with `version`/`sources`/`mappings`
fields — Vercel's SPA catch-all can return HTML 404 as 200 for `.map` paths.

## Prod vs Preview (Vercel) comparison

Key differences to look for:
- **Deployment IDs**: `?dpl=dpl_xxx` query parameter on all `_next/static/` URLs.
- Different build hashes → potentially different features or looser middleware.
- **Preview may have `age` header** (CDN cache age) indicating different cache policies.
- Always test both — preview environments sometimes have debug paths, looser CORS,
  or feature flags disabled.

## Scripts

Full analysis can be scripted with sequential probing:

```bash
HOSTS="mcp.neon.tech preview-mcp.neon.tech"

for h in $HOSTS; do
  echo "=== $h ==="
  # 1. Root redirect
  curl -sIL "https://$h/" | grep -i location | head -1
  # 2. OAuth metadata
  CURL "https://$h/.well-known/oauth-authorization-server" | tee $h.oauth.json
  # 3. Protected resource metadata
  curl -sS "https://$h/.well-known/oauth-protected-resource" | python3 -m json.tool  
  # 4. Dynamic client registration test
  curl -sS -X POST "https://$h/api/register" \
    -H 'Content-Type: application/json' \
    -d '{"client_name":"recon","redirect_uris":["http://127.0.0.1/callback"],"response_types":["code"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}'
  # 5. MCP transport probes
  for path in /sse /mcp /api/mcp; do
    curl -sI "https://$h$path" | grep -iE "HTTP|www-authenticate|x-matched-path"
  done
  # 6. Health check (often unauthenticated)
  curl -sS "https://$h/api/health" | python3 -m json.tool
  # 7. JS bundle URLs from 404 page
  curl -sSL "https://$h/nonexistent" | grep -oP '/_next/[^"]+\.js[^"]*' | sort -u
  # 8. Source map availability per bundle
  for url in $(curl -sSL "https://$h/nonexistent" | grep -oP 'src="(/_next/[^"]+\.js)[^"]*"' | sed 's/src="//;s/"//'); do
    code=$(curl -sLo /dev/null -w "%{http_code}" "https://$h${url}.map")
    echo "  ${url##*/}.map -> $code"
  done
done
```

## Reference: Neon MCP server specifics (2026-07-14)

Both `mcp.neon.tech` and `preview-mcp.neon.tech`:
- Vercel-hosted Next.js (v16.1.1)
- Next.js turbopack build
- Single catch-all route `/api/[transport]` → rewritten to `/api/sse`, `/api/mcp`, etc.
- OAuth 2.0 with authorization_code + refresh_token, PKCE required (S256)
- Dynamic client registration enabled (open, no auth required)
- Scopes: read, write, `*` (wildcard)
- Health endpoint: `/api/health` and `/health` (unauthenticated, returns version)
- `/callback` endpoint expects `code` + `state` query params
- No `.well-known/openid-configuration` (not OIDC, just OAuth)
- Prod deployment: `dpl_23A1rDVDrUUugEx77ECtVYqZRnBa`
- Preview deployment: `dpl_FuwKguhHvRhqJg7mL96UEahYNK2i`
- No source maps except a shared polyfill chunk (no app source exposed)
- Preview had identical security posture to prod (no looser restrictions found)
