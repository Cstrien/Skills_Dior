# gRPC-Web from minified JavaScript when reflection is disabled

Use this when a browser SPA talks to gRPC/gRPC-Web through Envoy/Connect but `grpcurl ... list` returns `server does not support the reflection API`.

## Trigger signals

- Envoy / API gateway frontend.
- `curl -X POST https://host/random.Service/Method -H 'content-type: application/grpc-web+proto'` returns a gRPC-web trailer such as `grpc-status:12` (`UNIMPLEMENTED`) rather than normal HTML.
- Browser JS bundle contains strings like `getMethodDesc`, `grpc-status`, `application/grpc-web`, `bearerToken`, or package names like `anduril.auth.v2.*`.

## Workflow

1. Download first-party JS bundles from the login/app page.
2. Extract method names and package namespaces from the minified bundle:

```bash
python3 - <<'PY'
import re, sys, pathlib
for path in sys.argv[1:]:
    js = pathlib.Path(path).read_text(errors='ignore')
    print('==', path, '==')
    print('\n# package/name strings')
    for s in sorted(set(re.findall(r'[a-z0-9_]+(?:\.[a-z0-9_]+)+', js, re.I)))[:200]:
        if any(k in s.lower() for k in ['auth','grpc','api','admin','user','token','saml','oidc']):
            print(s)
    print('\n# getMethodDesc method names')
    for m in sorted(set(re.findall(r'\.prototype\.([A-Z][A-Za-z0-9]+)\.getMethodDesc', js))):
        print(m)
PY bundle.js
```

3. Confirm transport with a known/bogus method. `grpc-status:12` means the path reached a gRPC server but the service/method is wrong.
4. For unary gRPC-Web binary (`application/grpc-web+proto`), build a frame manually:
   - 1 byte flag: `0x00` for data frame
   - 4-byte big-endian protobuf payload length
   - protobuf payload bytes
5. Hand-encode simple protobuf probes when the schema is obvious:
   - string field 1: `0a <len> <bytes>`
   - string field 2: `12 <len> <bytes>`
   - empty request: zero-length payload inside a 5-byte gRPC-web frame

```python
import struct, subprocess

def varint(n):
    out=b''
    while n > 0x7f:
        out += bytes([0x80 | (n & 0x7f)]); n >>= 7
    return out + bytes([n])

def str_field(num, val):
    b=val.encode()
    return varint((num << 3) | 2) + varint(len(b)) + b

def frame(pb):
    return b'\x00' + struct.pack('>I', len(pb)) + pb

payload = str_field(1, 'test@example.com')
cmd = [
  'curl','-sk','-X','POST',
  '-H','Content-Type: application/grpc-web+proto',
  '-H','x-grpc-web: 1',
  '--data-binary','@/dev/stdin',
  'https://TARGET/package.Service/Method',
]
print(subprocess.run(cmd, input=frame(payload), capture_output=True).stdout)
```

6. Parse responses as gRPC-Web frames, not as raw text. A response can contain one data frame followed by a trailer frame (`0x80`) with `grpc-status`.

```python
import struct

def parse_grpc_web(data):
    i=0
    while i + 5 <= len(data):
        flag=data[i]
        length=struct.unpack('>I', data[i+1:i+5])[0]
        body=data[i+5:i+5+length]
        kind='trailers' if flag & 0x80 else 'data'
        print(kind, length, body[:500].decode(errors='replace'))
        i += 5 + length
```

## What counts as signal

- `grpc-status:0` plus sensitive payload from an unauthenticated call is actionable.
- `grpc-status:0` plus public SSO metadata is an identity-fabric disclosure/enabler; chain it before reporting as high severity.
- `grpc-status:12` means the service/method name is wrong, not necessarily that the endpoint is protected.
- Empty response can be timeout, redirect/proxy behavior, or a wrong service name; confirm with verbose curl and alternative service name guesses.

## Common high-value anonymous methods to test

- SSO/identity: `GetSSOURL`, `GetSPMetadata`, `GetPrimaryIDP`, `GetAllowedEmailDomains`
- Public/system: `GetSystemUseMessage`, `GetSettings`, `WhoAmI`
- Admin-ish: `ListUsers`, `ListClients`, `RegisterClient`, `GenerateBearerToken`, `ListPoliciesForPrincipalInsecure`, `ImpersonateTestPermissions`

## Reporting discipline

For bug bounty, unauthenticated SAML/OIDC metadata and valid-domain oracle are usually not enough alone. Treat them as a chain primitive unless they directly enable:

- login bypass,
- tenant/user data access,
- account takeover,
- privileged action, or
- security control bypass with concrete impact.

Attach decoded SAML/AuthnRequest and SP metadata excerpts, but avoid overstating `AuthnRequestsSigned=false`; SP-initiated SAML commonly does not require signed AuthnRequests when assertions are signed.