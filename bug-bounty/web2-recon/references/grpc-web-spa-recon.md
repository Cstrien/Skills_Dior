# gRPC-web / protobuf SPA recon

Use this when a React/Vite/Lattice-style SPA ships a large minified bundle and normal URL crawling finds only `/login` or an unsupported-browser page.

## Signals

- Large first-party JS bundle (MBs) contains strings like `grpc`, `grpc-web`, `connectrpc`, `getMethodDesc`, `protobuf`, or package names such as `anduril.auth.v2.*`.
- POSTing to a guessed path with `Content-Type: application/grpc-web+proto` returns framed trailers such as `grpc-status:12` / `unknown service` instead of HTML.
- Login pages expose identity methods in bundle strings (`GetSSOURL`, `GetSPMetadata`, `LoginPassword`, `RefreshSessionToken`, `GenerateBearerToken`, `ListUsers`).

## Lightweight extraction

```bash
JS=js/app.js
python3 - <<'PY'
import re, sys
js=open(sys.argv[1], errors='ignore').read()
print('== namespaces ==')
for s in sorted(set(re.findall(r'[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+){2,}', js))):
    if any(x in s.lower() for x in ['auth','grpc','proto','lattice','api']): print(s)
print('\n== method descriptors ==')
for m in sorted(set(re.findall(r'\.prototype\.([A-Z][A-Za-z0-9]+)\.getMethodDesc', js))): print(m)
print('\n== auth strings ==')
for m in sorted(set(re.findall(r'\b[A-Za-z0-9_./:-]{0,80}(?:SAML|SSO|OIDC|Token|Password|Login|Client|Policy)[A-Za-z0-9_./:-]{0,80}\b', js, re.I)))[:300]: print(m)
PY "$JS"
```

## gRPC-web framing quick probe

For unary methods with an empty protobuf request, send a zero-length gRPC-web frame:

```bash
printf '\x00\x00\x00\x00\x00' > /tmp/grpc-empty.bin
curl -sk -X POST \
  -H 'Content-Type: application/grpc-web+proto' \
  -H 'x-grpc-web: 1' \
  --data-binary @/tmp/grpc-empty.bin \
  https://host.example.com/package.Service/Method | xxd
```

For a single string field (field 1, e.g. `email`):

```python
import struct
email=b'test@example.com'
pb=bytes([0x0a,len(email)])+email      # field 1, length-delimited string
open('/tmp/grpc-email.bin','wb').write(b'\x00'+struct.pack('>I',len(pb))+pb)
```

Then POST `/tmp/grpc-email.bin` as above.

## Interpreting responses

- `grpc-status:12` + `unknown service` or `unknown method` = you reached the gRPC-web gateway, but path/service/method is wrong.
- `grpc-status:0` with a data frame = unauthenticated method returned application data.
- Empty HTTP response can mean guessed service name is wrong, the route is not exposed on that host, or the gateway closed before writing trailers. Do not conclude auth is safe from this alone.
- `grpcurl` needs server reflection or local `.proto`/descriptor files. If reflection is disabled, browser bundle strings plus raw gRPC-web frames are often faster than forcing grpcurl.

## High-value unauth probes

Identity/login SPAs often expose safe-looking but sensitive metadata methods. Try only low-volume, non-destructive probes first:

- `*/GetSSOURL` with a test corporate email and a non-corporate email: can reveal accepted-domain oracle and IdP URLs.
- `*/GetSPMetadata`: can reveal SAML entity IDs, ACS URLs, X509 certs, signature requirements.
- `*/GetPrimaryIDP`: can reveal selected IdP mode.
- OIDC/Keycloak `/.well-known/openid-configuration`, realm JSON, and JWKS for any URL returned by the app flow.

## Pitfalls

- Method names in minified JS do not always reveal the service name; `ListUsers` may live under a generated service class whose name is not `Users`. Map service contexts from nearby client objects before mass testing.
- SAML/OIDC metadata disclosure is usually an info-disclosure finding unless chained to a concrete auth weakness (signature bypass, token confusion, dynamic registration abuse, password/device-flow weakness, or redirect/callback abuse).
- Do not large-scale enumerate real users. Use synthetic addresses to test domain-level behavior.
