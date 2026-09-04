---
name: hermes-ops
description: "Diagnose and fix Hermes logs, resources, and gateway."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [hermes, ops, logs, gateway, systemd, troubleshooting, maintenance]
---

# Hermes Ops — Operational Maintenance

Diagnose and fix issues with a running Hermes installation: log inspection,
resource exhaustion, gateway service management. Use this when the user asks
to check Hermes logs, fix Hermes errors, restart the gateway, or troubleshoot
the running agent process.

## Log File Locations

All logs live under `~/.hermes/logs/` (or `$HERMES_HOME/logs/` for profiles).

| File | Contents |
|---|---|
| `agent.log` | Main agent conversation loop (rotates at ~5MB: `.1`, `.2`, `.3`) |
| `errors.log` | All ERROR/WARNING level messages (rotates at ~2MB) |
| `gateway.log` | Gateway platform integration — Telegram, Discord, etc. |
| `tui_gateway_crash.log` | TUI parent process crashes (Node.js SIGHUP/EIO) |
| `dashboard-auth.log` | Web dashboard authentication events |
| `gui.log` | Desktop GUI / web server logs |
| `gateway-restart.log` | Gateway restart diagnostics |
| `action-prompt-size.log` | Prompt size tracking (debugging context overflow) |

### Quick Diagnostic Commands

```bash
# Recent errors
tail -100 ~/.hermes/logs/errors.log

# Error patterns across all rotated logs
grep -i "error\|failed\|crash" ~/.hermes/logs/errors.log* | tail -30

# Gateway health
tail -50 ~/.hermes/logs/gateway.log
systemctl --user status hermes-gateway --no-pager | head -15

# TUI crash history
tail -50 ~/.hermes/logs/tui_gateway_crash.log

# Count open file descriptors of the gateway process
cat /proc/$(pgrep -f "hermes.*gateway" | head -1)/limits 2>/dev/null | grep "Max open files"
```

## Common Issues & Fixes

### 1. Too Many Open Files (Errno 24)

**Symptom:** `errors.log` shows `OSError: [Errno 24] Too many open files` on
`socket.accept()` — the gateway can't accept new connections.

**Root cause:** Process exceeds the file descriptor limit (default 1024 on
many Linux systems). Caused by socket/connection leaks or high connection
volume.

**Fix without sudo — systemd user service override:**

```bash
# Create override directory (user service — no root needed)
mkdir -p ~/.config/systemd/user/hermes-gateway.service.d

# Write limit override
cat > ~/.config/systemd/user/hermes-gateway.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=65536
EOF

# Reload systemd to pick up the override
systemctl --user daemon-reload

# Verify the override is loaded
systemctl --user show hermes-gateway | grep LimitNOFILE
# Should show: LimitNOFILE=65536

# Restart gateway (see below — CANNOT do this from inside the gateway)
hermes gateway restart
```

**Alternative (if not using systemd):** Add to `/etc/security/limits.conf`:
```
<username> soft nofile 65536
<username> hard nofile 65536
```
Then relogin or reboot. Requires sudo.

### 2. Cannot Restart Gateway From Inside the Gateway

**Critical pitfall:** If you are running inside a Hermes TUI/CLI session that
is itself connected to the gateway, `systemctl --user restart hermes-gateway`
will be **blocked** — the gateway kills child processes (including your
session) before the restart completes.

**Error message:**
```
Blocked: command or referenced script cannot restart or stop the gateway
from inside the gateway process.
```

**Fix:** Tell the user to run from a separate shell:
```bash
hermes gateway restart
```

Or use the `/restart` slash command in the TUI (if available).

### 3. Telegram Network Errors

**Symptom:** `gateway.log` shows `Bad Gateway` or `Timed out` from Telegram
API, then fallback to direct IP.

**Cause:** `api.telegram.org` is blocked/unreachable (common in Vietnam).

**Behavior:** Gateway auto-recovers using fallback IPs
(e.g. `149.154.166.110`). No action needed unless errors persist for 10+
minutes.

### 4. Tools Unavailable Warnings

**Symptom:** `errors.log` shows `check_fn <name> returned False; dependent
tools will be unavailable this turn`.

**Cause:** Optional tool requirements not met (missing API keys, browser not
installed, image generation backend absent).

**Fix:** Check which tools are affected and configure their requirements:
```bash
hermes tools          # List enabled tools
hermes config set <key> <value>   # Configure missing requirements
```

### 5. Gateway Crash Loop

```bash
# Reset failed state
systemctl --user reset-failed hermes-gateway

# Check for lingering processes
pgrep -fa hermes

# Restart
systemctl --user start hermes-gateway
```

### 6. Gateway Dies on SSH Logout

```bash
# Enable lingering so user services survive logout
sudo loginctl enable-linger $USER
```

## Gateway Service Management

The Hermes gateway runs as a **systemd user service** — no sudo needed for
most operations.

```bash
# Status
systemctl --user status hermes-gateway

# Start / stop / restart (from OUTSIDE the gateway process)
systemctl --user start hermes-gateway
systemctl --user stop hermes-gateway
systemctl --user restart hermes-gateway   # or: hermes gateway restart

# View service definition + overrides
systemctl --user cat hermes-gateway

# Real-time logs
journalctl --user -u hermes-gateway -f

# Edit service (creates override drop-in)
systemctl --user edit hermes-gateway
```

## Pitfalls

- **Never `systemctl --user restart hermes-gateway` from inside a Hermes
  session** — the gateway process will kill your session before completing.
  Always tell the user to restart from a separate shell.
- **`ulimit -n` in the current shell does NOT affect the already-running
  gateway** — only new processes spawned from that shell. Use the systemd
  override + restart approach for the gateway.
- **`sudo` may not be available** — prefer systemd user service overrides
  (no root needed) over editing `/etc/security/limits.conf`.
- **Log rotation:** `agent.log` and `errors.log` rotate at fixed sizes. Always
  check `.1`, `.2`, `.3` variants if the current file doesn't have what you
  need.
- **Profile paths:** If a profile is active, logs are under
  `$HERMES_HOME/logs/` not `~/.hermes/logs/`. Check `$HERMES_HOME` first.
