# gRPC-Web auth-boundary probing notes

Use this as a companion to `grpc-web-from-js-reflection-disabled.md` when a SPA bundle exposes method names but not exact service names or `.proto` descriptors.

## Lessons from a reflection-disabled Envoy/Lattice target

- `curl` HTTP status alone is misleading. Browser-facing gRPC-Web often returns HTTP `200` for both success and application errors; parse the gRPC-Web trailer (`grpc-status`, `grpc-message`) before classifying the call.
- `HTTP 401` with a tiny 1-byte body generally means the public edge/proxy blocked the request before the backend method ran. This is different from `HTTP 200` + `grpc-status:16 no credentials present`, which means the request reached a valid gRPC service/method and backend auth rejected it.
- `grpc-status:12` / `unknown method X for service Y` means the service exists but the method path is wrong for that service; keep mapping rather than concluding the method is absent.
- `grpc-status:0` with public identity metadata (`GetSSOURL`, `GetSPMetadata`, `GetPrimaryIDP`) is a real anonymous surface but usually an enabler/Info-Low finding unless chained to auth bypass, user/tenant data, token theft, or privileged action.
- Service guessing from method names is useful but noisy. Try package-level candidates (`anduril.auth.v2.Auth`) and noun-specific candidates (`anduril.auth.v2.Tokens`, `...Users`, `...Idps`), then classify each response by edge vs backend error.

## Minimal probe script pattern

```python
#!/usr/bin/env python3
import re, struct, subprocess
from pathlib import Path

def frame(pb=b''):
    return b'\x00' + struct.pack('>I', len(pb)) + pb

def str_field(num, value):
    b=value.encode()
    # good enough for short field numbers/lengths used in email/domain probes
    return bytes([(num << 3) | 2, len(b)]) + b

Path('/tmp/empty_grpcweb.bin').write_bytes(frame(b''))
Path('/tmp/email_grpcweb.bin').write_bytes(frame(str_field(1, 'test@example.com')))

candidates = {
  'GetSSOURL': ['pkg.Idps'],
  'GetSPMetadata': ['pkg.Idps'],
  'ListUsers': ['pkg.Auth', 'pkg.Users'],
  'ListUserTokens': ['pkg.Auth', 'pkg.Tokens'],
  'GenerateBearerToken': ['pkg.Auth', 'pkg.Tokens'],
}

for method, services in candidates.items():
    for svc in services:
        binfile = '/tmp/email_grpcweb.bin' if method in {'GetSSOURL'} else '/tmp/empty_grpcweb.bin'
        url = f'https://TARGET/{svc}/{method}'
        p = subprocess.run([
          'curl','-sk','-m','10','-w','\nHTTP_CODE:%{http_code}',
          '-X','POST',
          '-H','Content-Type: application/grpc-web+proto',
          '-H','x-grpc-web: 1',
          '--data-binary',f'@{binfile}',url
        ], capture_output=True)
        out = p.stdout
        body, code = (out.rsplit(b'HTTP_CODE:',1) if b'HTTP_CODE:' in out else (out,b'?'))
        strings = re.findall(rb'[ -~]{4,}', body)
        print(method, svc, code.strip().decode(errors='ignore'), len(body), b' | '.join(strings[:6]).decode(errors='ignore'))
```

## Shell pitfall

Do not combine script creation and execution with an output redirect that points at the same script filename, e.g. `python3 - <<'PY' > probe.py ... PY; python3 probe.py`. That writes runtime output into `probe.py` instead of the Python source and corrupts the script. Use `write_file`/editor for the script, then run it separately or redirect runtime output to a distinct `.tsv` file.

## Classification table

| Observation | Meaning | Next step |
|---|---|---|
| HTTP 401, body length ~1 | Edge/proxy auth blocked before method execution | Not a finding; try only if a public client normally calls this method with auth metadata |
| HTTP 200 + `grpc-status:16 no credentials present` | Valid backend service/method reached; backend auth works | Note exact path; not a vuln without bypass |
| HTTP 200 + `grpc-status:12 unknown method` | Service exists but method wrong | Keep mapping service/method names |
| HTTP 200 + `grpc-status:0` + public SSO metadata | Anonymous identity-fabric metadata | Treat as chain primitive |
| HTTP 200 + `grpc-status:0` + private/user/admin data or state change | Authz bug | Validate twice and report |
