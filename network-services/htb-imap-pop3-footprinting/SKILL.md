---
name: htb-imap-pop3-footprinting
description: Solve HTB Footprinting labs on IMAP/POP3 mail services.
---

# HTB IMAP & POP3 Footprinting

## Overview

IMAP (TCP 143/993) and POP3 (TCP 110/995) mail services. Dovecot is typical Linux daemon. Key info is in:
1. **Banner greetings** — org name, custom version, flags
2. **TLS certificates** — FQDN (CN), org name (O), admin email (emailAddress)
3. **Email content** — flags hidden in mailbox folders

## Step-by-Step Methodology

### Step 1: Port Scan
```bash
nmap -Pn -sT -p110,143,993,995,25,465,587 -sV -sC <IP>
```
- Use `-Pn` (HTB boxes block ping) and `-sT` (TCP connect, not SYN).
- Full scan: `nmap -Pn -sT -p1-65535 --min-rate 1000 -T4 <IP>`

### Step 2: Grab Plaintext Banners (no auth needed)
```bash
# IMAP greeting — may contain flag directly
echo "a1 LOGOUT" | nc -w 5 <IP> 143

# POP3 greeting — org name + custom version
echo "QUIT" | nc -w 5 <IP> 110

# SMTP greeting
echo "QUIT" | nc -w 5 <IP> 25
```

### Step 3: Extract TLS Certificates (STARTTLS)
```bash
# IMAP STARTTLS (port 143)
echo "a1 LOGOUT" | openssl s_client -starttls imap -connect <IP>:143 2>/dev/null | openssl x509 -noout -text | grep -iE "Subject:|Issuer:|CN=|O=|emailAddress"

# POP3 STARTTLS (port 110)
(echo ""; sleep 1; echo "QUIT") | openssl s_client -starttls pop3 -connect <IP>:110 2>/dev/null | openssl x509 -noout -text | grep -iE "Subject:|Issuer:|CN=|O=|emailAddress"

# SMTP STARTTLS (port 25)
(echo ""; sleep 1) | openssl s_client -starttls smtp -connect <IP>:25 2>/dev/null | openssl x509 -noout -text | grep -iE "Subject:|Issuer:|CN=|O=|emailAddress"

# IMAPS direct TLS (port 993)
echo "a1 LOGOUT" | openssl s_client -connect <IP>:993 2>/dev/null | openssl x509 -noout -text | grep -iE "Subject:|Issuer:|CN=|O=|emailAddress"

# POP3S direct TLS (port 995)
echo "QUIT" | openssl s_client -connect <IP>:995 2>/dev/null | openssl x509 -noout -text | grep -iE "Subject:|Issuer:|CN=|O=|emailAddress"
```

**Note:** Different services may have DIFFERENT certificates with different emails!

### Step 4: SMTP User Enumeration (if SMTP open)
```bash
(echo "EHLO test"; sleep 1; for u in root admin postmaster robin devadmin; do echo "VRFY $u"; sleep 0.5; done; echo "QUIT") | nc -w 15 <IP> 25
```
- `252` = user exists, `550` = user unknown.

### Step 5: DNS SOA Record (admin email)
```bash
dig @<IP> <domain> SOA +short
```
- SOA `rname` field: `root.inlanefreight.htb` = `root@inlanefreight.htb`
- Also try AXFR zone transfer: `dig @<IP> <domain> AXFR +noall +answer`

### Step 6: Login IMAP via STARTTLS (KEY STEP)
Plaintext auth is usually blocked — MUST use STARTTLS.

**Credentials:** Try `robin:robin` (common in HTB labs).

```bash
(
echo "a1 LOGIN robin robin"
sleep 1
echo "a2 LIST \"\" *"
sleep 1
echo "a3 LOGOUT"
) | openssl s_client -starttls imap -connect <IP>:143 -quiet 2>/dev/null
```

### Step 7: Select Folder and Fetch Email
```bash
(
echo "a1 LOGIN robin robin"
sleep 1
echo "a2 SELECT DEV.DEPARTMENT.INT"
sleep 1
echo "a3 FETCH 1 ALL"
sleep 1
echo "a4 FETCH 1 BODY[]"
sleep 1
echo "a5 LOGOUT"
) | openssl s_client -starttls imap -connect <IP>:143 -quiet 2>/dev/null
```

**ENVELOPE** output contains sender email:
```
ENVELOPE (...(("CTO" NIL "devadmin" "inlanefreight.htb"))...)
```
→ admin email = `devadmin@inlanefreight.htb`

**BODY[]** contains the flag:
```
HTB{...}
```

## Key IMAP Commands
```
1 LOGIN <user> <pass>
1 LIST "" *              # List all folders
1 SELECT <folder>        # Select a folder
1 FETCH 1 ALL            # Fetch envelope (headers)
1 FETCH 1 BODY[]         # Fetch full email body
1 FETCH 1 BODY[TEXT]     # Fetch text only
1 LOGOUT
```

## Key POP3 Commands
```
USER <username>
PASS <password>
STAT                     # Number of emails
LIST                     # List email IDs
RETR <id>                # Retrieve email
DELE <id>                # Delete email
CAPA                     # Capabilities
QUIT
```

## Alternative: cURL
```bash
# IMAPS login + list
curl -k 'imaps://<IP>' --user robin:robin -v

# POP3S
curl -k 'pop3s://<IP>' --user robin:robin -v
```

## HTB Lab Answers Summary (IMAP & POP3 Footprinting)

| Question | Source | Answer |
|---|---|---|
| Org name | TLS cert `O=` field | InlaneFreight Ltd |
| FQDN | TLS cert `CN=` field | dev.inlanefreight.htb |
| IMAP flag | IMAP greeting banner | HTB{...} (in CAPABILITY line) |
| POP3 version | POP3 greeting banner | v9.188 |
| Admin email | IMAP email ENVELOPE (after login) | devadmin@inlanefreight.htb |
| Email flag | IMAP FETCH BODY[] (after login) | HTB{...} (in email body) |

## Pitfalls
- **Plaintext auth blocked:** Dovecot requires STARTTLS for login. Use `openssl s_client -starttls imap`.
- **Different certs per service:** IMAP/POP3 cert may differ from SMTP cert. Check ALL services.
- **Admin email NOT in cert or DNS:** Do NOT guess admin email from TLS cert emailAddress or DNS SOA. You MUST login to IMAP with `robin:robin` via STARTTLS, then `SELECT DEV.DEPARTMENT.INT` and `FETCH 1 ALL`. The admin email (`devadmin@inlanefreight.htb`) is in the email ENVELOPE, not in any cert or DNS record. This is the #1 mistake.
- **Credentials `robin:robin`:** These are provided/given in the HTB lab or found earlier in the footprinting path. Try them first.
- **Filter `strings` for binary:** POP3S/IMAPS cert output may have binary chars. Pipe through `strings`.
- **Use `-Pn -sT`:** HTB boxes block ping probes; SYN scans may show filtered. TCP connect scan works.
- **Folder structure:** HTB hides emails in subfolders like `DEV.DEPARTMENT.INT`, not just INBOX. Always `LIST "" *`.
- **FETCH syntax:** Use `FETCH 1 ALL` for headers/envelope, `FETCH 1 BODY[]` for full email, `FETCH 1 BODY[TEXT]` for body only.
