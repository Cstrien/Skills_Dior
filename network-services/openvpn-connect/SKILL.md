---
name: openvpn-connect
description: "Connect OpenVPN from .ovpn file, verify tunnel status."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [vpn, openvpn, networking, tunnel, security]
---

# OpenVPN Connect

Automatically connect to an OpenVPN server from a `.ovpn` config file. Handles auth detection, background connection, verification, and teardown.

## Trigger
Use when the user provides an `.ovpn` file (path or content) and wants to connect to the VPN.

## Prerequisites
- `openvpn` binary installed (`which openvpn`)
- Root/sudo access (OpenVPN requires root for TUN/TAP interfaces)
- Linux host with `/dev/net/tun` available

## Workflow

### Step 1: Receive the .ovpn file

If user gives a **file path** → use directly.
If user **pastes content** → save to `/tmp/vpn-config.ovpn` via write_file.

### Step 2: Analyze the config

Check for auth requirements:
```bash
grep -i "auth-user-pass" /path/to/config.ovpn
```

- If `auth-user-pass` WITHOUT a file argument → needs username/password credentials
  - Ask user to provide a credentials file: `echo -e "username\npassword" > /tmp/vpn-auth.txt && chmod 600 /tmp/vpn-auth.txt`
  - Then patch the config: replace `auth-user-pass` with `auth-user-pass /tmp/vpn-auth.txt`
  - **NEVER type passwords yourself** — ask the user to create the auth file
- If `auth-user-pass /path/to/creds.txt` → already has creds, proceed
- If NO `auth-user-pass` → cert-only auth, proceed directly

Check for other issues:
```bash
grep -iE "remote |proto |dev " /path/to/config.ovpn
```

### Step 3: Record pre-connection state
```bash
# Save current public IP for later comparison
curl -s --max-time 5 ifconfig.me > /tmp/vpn-pre-ip.txt 2>/dev/null || echo "unknown" > /tmp/vpn-pre-ip.txt
ip route show default
```

### Step 4: Connect (background)

```bash
openvpn --config /path/to/config.ovpn --daemon --writepid /tmp/openvpn.pid --log /tmp/openvpn.log --verb 3
```

Wait 5-10 seconds for tunnel to establish:
```bash
sleep 8
```

### Step 5: Verify connection

Check if process is running:
```bash
cat /tmp/openvpn.pid 2>/dev/null && kill -0 $(cat /tmp/openvpn.pid) 2>/dev/null && echo "RUNNING" || echo "FAILED"
```

Check logs for success:
```bash
grep -iE "Initialization Sequence Completed|Connection established|AUTH_FAILED|CONNECT_FAILED|Error" /tmp/openvpn.log | tail -20
```

Check new IP:
```bash
curl -s --max-time 10 ifconfig.me
```

Check tunnel interface:
```bash
ip addr show | grep -A5 "tun\|tap"
```

### Step 6: Report status

Report to user:
- ✅ Connected: show old IP → new IP, tunnel interface, server location
- ❌ Failed: show relevant error lines from /tmp/openvpn.log

## Disconnect

When user wants to disconnect:
```bash
kill $(cat /tmp/openvpn.pid) 2>/dev/null
sleep 2
# Verify
ip addr show | grep -q "tun\|tap" && echo "STILL UP" || echo "DISCONNECTED"
curl -s --max-time 5 ifconfig.me
```

Clean up:
```bash
rm -f /tmp/openvpn.pid /tmp/openvpn.log /tmp/vpn-pre-ip.txt
```

## Status Check

When user asks for VPN status:
```bash
# Process alive?
kill -0 $(cat /tmp/openvpn.pid) 2>/dev/null && echo "VPN: CONNECTED" || echo "VPN: DISCONNECTED"
# Current IP
curl -s --max-time 5 ifconfig.me
# Tunnel interface
ip addr show | grep -A3 "tun\|tap" || echo "No tunnel"
# Routes
ip route show | grep -i "tun\|tap\|0.0.0.0.*via"
```

## Pitfalls

1. **DNS leak** — OpenVPN may not update `/etc/resolv.conf`. If DNS fails after connecting:
   ```bash
   # Check current DNS
   cat /etc/resolv.conf
   # Manual fix if needed (use VPN server's DNS):
   echo "nameserver 8.8.8.8" > /tmp/dns && sudo cp /tmp/dns /etc/resolv.conf
   ```
   Or use `resolvconf` / `systemd-resolved` if available.

2. **Existing OpenVPN process** — Kill before reconnecting:
   ```bash
   pkill -f "openvpn.*config" 2>/dev/null; sleep 2
   ```

3. **Config with inline certs** — Some `.ovpn` files have `<ca>`, `<cert>`, `<key>` blocks inline. These work as-is, no extra files needed.

4. **MTU issues** — If connection establishes but traffic doesn't flow:
   ```bash
   # Check MTU on tunnel
   ip link show tun0
   # Lower MTU if needed
   ip link set dev tun0 mtu 1400
   ```

5. **Split tunneling** — If config uses `route` directives (not `redirect-gateway`), only specific traffic goes through VPN. Check with `ip route show`.

6. **Background daemon** — Using `--daemon` mode means logs go to file, not stdout. Always check `/tmp/openvpn.log`.

7. **Permission denied on TUN** — If `/dev/net/tun` not accessible:
   ```bash
   ls -la /dev/net/tun
   # Should show crw-rw-rw- (world read/write)
   ```

## Files Used

| File | Purpose |
|------|---------|
| `/tmp/vpn-config.ovpn` | Saved config if user pastes content |
| `/tmp/vpn-auth.txt` | Credentials file (user creates, mode 600) |
| `/tmp/openvpn.pid` | PID of running OpenVPN daemon |
| `/tmp/openvpn.log` | OpenVPN connection log |
| `/tmp/vpn-pre-ip.txt` | Pre-connection public IP |

## Quick One-Liner (for simple cert-only configs)

```bash
openvpn --config config.ovpn --daemon --writepid /tmp/openvpn.pid --log /tmp/openvpn.log --verb 3 && sleep 8 && grep "Initialization Sequence Completed" /tmp/openvpn.log && curl -s ifconfig.me
```
