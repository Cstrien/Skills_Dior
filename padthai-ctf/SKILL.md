---
name: padthai-ctf
description: "PadThai CTF at IP 103.70.12.91:19090 - revisit notes here."
---

# PadThai CTF (103.70.12.91:19090)

## Target Summary
- nginx/1.31.5 + Java Spring Boot
- Endpoints: `/` (landing), `/dashboard` (GET only, requires session)
- Session: 176-byte blob = IV + 10 cipher blocks (AES-CBC, PKCS7 with `\x0a`×10)
- Plaintext format: Java XStream XML for class `com.challenge.padthai.Session`

## Plaintext Structure
```xml
<com.challenge.padthai.Session>
  <username>guest</username>
  <role>user</role>
  <issuedAt>1789045258835</issuedAt>
</com.challenge.padthai.Session>
```

## Attack Results
1. ✅ Padding Oracle decrypt - CONFIRMED WORKING
2. ❌ Session forgery - Server: "could not parse session state"
3. ❌ No hidden endpoints via dir brute (common.txt + big.txt)
4. ❌ No stego in `/padthai.jpg`

## Scripts Saved
- `/tmp/oracle_full.py` - full oracle decryption
- `/tmp/forge_v2.py` - forge role=root
- `/tmp/forge_user_admin.py` - forge username=admin
- `/tmp/forge_timestamp.py` - forge fresh issuedAt

## KEY BREAKTHROUGH: Oracle Encryption (Vaudenay's attack)
- Can encrypt ARBITRARY plaintext from scratch (not just bit-flip)
- Use `find_intermediate(prev, C_target)` to get D(C) for random cipher blocks
- Then cascade: C_(i-1) = D(C_i) XOR P_i_target

## Successful Forges
1. `role=root` via bit-flip → "Welcome back, guest (role=root)"
2. `role=admin` via oracle encryption → "Welcome back, guest (role=admin)"
3. `username=admin, role=admin` via oracle encryption → "Welcome back, admin (role=admin)"

## XStream Class Injection (server calls obj.toString() on deserialized object)
- ALLOWED: `<string>`, `<int>`, `<java.net.URL>`, `<java.io.File>`, `<org.springframework.core.env.StandardEnvironment>`, `<org.springframework.boot.context.properties.BoundConfigurationProperties>`
- BLOCKED: `<java.lang.ProcessBuilder>`, `<java.beans.EventHandler>`, `<com.sun.rowset.JdbcRowSetImpl>`, `<java.lang.Runtime>`
- Session extra fields (flag, secret, isAdmin, token) → all ignored

## Flag Status
- NOT FOUND in HTTP responses, headers, or hidden endpoints
- No Spring Boot actuator endpoints (all 404)
- SSH brute force failed
- No stego in padthai.jpg
- Flag may require: RCE (blocked by XStream allowlist), or submission at external platform
