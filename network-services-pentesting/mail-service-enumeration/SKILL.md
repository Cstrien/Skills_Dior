---
name: mail-service-enumeration
description: Use when pentesting IMAP/POP3/SMTP for TLS cert intel.
---

# Mail Service Enumeration

Intelligence gathering from mail services (IMAP, POP3, SMTP, DNS) during pentesting. Extract organizational info — company name, FQDNs, admin emails, software versions, and hidden flags — from TLS certificates, greeting banners, and DNS records.

## When to Use

- Pentesting any mail server (IMAP, POP3, SMTP)
- HTB Academy / CTF challenges asking for "organization name", "FQDN", "admin email" from mail services
- Pre-credential reconnaissance on mail infrastructure
- Any target with ports 25, 110, 143, 465, 587, 993, 995 open

## Quick Reference

| Port | Service | STARTTLS | Direct TLS |
|------|---------|----------|------------|
| 25 | SMTP | `openssl s_client -starttls smtp` | — |
| 110 | POP3 | `openssl s_client -starttls pop3` | — |
| 143 | IMAP | `openssl s_client -starttls imap` | — |
| 465 | SMTPS | — | `openssl s_client -connect` |
| 587 | Submission | `openssl s_client -starttls smtp` | — |
| 993 | IMAPS | — | `openssl s_client -connect` |
| 995 | POP3S | — | `openssl s_client -connect` |

## Step 1: Banner Grabbing (All Services)

```bash
# SMTP
echo "QUIT" | nc -w 5 <target-ip> 25
# 220 InFreight ESMTP v2.11

# POP3
echo "QUIT" | nc -w 5 <target-ip> 110
# +OK InFreight POP3 v9.188

# IMAP
echo "a1 LOGOUT" | nc -w 5 <target-ip> 143
# * OK [CAPABILITY IMAP4rev1 ...] HTB{flag_here}
```

**What to look for:**
- Custom software name and version (e.g., "InFreight POP3 v9.188")
- Hidden flags in CAPABILITY or greeting lines
- Server hostname (e.g., "mail1")

## Step 2: STARTTLS Certificate Enumeration

The TLS certificate is the richest source of organizational intel. Different services may use **different certificates** — check ALL of them.

### One-Liner: Extract All Certs

```bash
# IMAP STARTTLS (143)
echo "a1 LOGOUT" | openssl s_client -starttls imap -connect <target-ip>:143 2>/dev/null | openssl x509 -noout -subject -issuer -email

# POP3 STARTTLS (110)
echo "QUIT" | openssl s_client -starttls pop3 -connect <target-ip>:110 2>/dev/null | openssl x509 -noout -subject -issuer -email

# SMTP STARTTLS (25)
echo "QUIT" | openssl s_client -starttls smtp -connect <target-ip>:25 2>/dev/null | openssl x509 -noout -subject -issuer -email

# IMAPS (993) — direct TLS
echo "a1 LOGOUT" | openssl s_client -connect <target-ip>:993 2>/dev/null | openssl x509 -noout -subject -issuer -email

# POP3S (995) — direct TLS
echo "QUIT" | openssl s_client -connect <target-ip>:995 2>/dev/null | openssl x509 -noout -subject -issuer -email
```

### Full Certificate Decode

```bash
echo "a1 LOGOUT" | openssl s_client -starttls imap -connect <target-ip>:143 2>/dev/null | openssl x509 -noout -text
```

### Key Cert Fields

| Field | Intel Value | HTB Question Example |
|---|---|---|
| `O=` | Organization name | "What is the organization name?" |
| `CN=` | FQDN assigned to the service | "What is the FQDN of the IMAP/POP3 server?" |
| `emailAddress=` | Admin / technical contact email | "What is the admin email address?" |
| `OU=` | Department / organizational unit | — |
| `C=`, `ST=`, `L=` | Country, state, city | — |

### Pitfalls

1. **Different services = different certs.** SMTP cert may show `infreight-admin@inlanefreight.htb` while IMAP cert shows `cto.dev@dev.inlanefreight.htb`. Don't assume one cert covers all services. When a question asks for "admin email", try all certs and DNS SOA — the expected answer may come from any of them.

2. **Binary/multibyte output breaks grep.** `openssl s_client` output can contain non-ASCII chars (e.g., UTF-8 department names like "DepÃartment"). Pipe through `strings`:
   ```bash
   echo "a1 LOGOUT" | openssl s_client -starttls imap -connect <target-ip>:143 2>&1 | strings | grep -i "subject="
   ```

3. **nmap shows "filtered" but ports are open.** HTB VPN targets may show filtered with default nmap. Use `-Pn -sT` with retries:
   ```bash
   nmap -Pn -sT -p25,110,143,465,587,993,995 --max-retries 3 -T4 <target-ip>
   ```

## Step 3: DNS SOA Record (Admin Email)

DNS SOA records encode an admin email — the first dot replaces @. Always check this alongside certs.

```bash
dig @<target-ip> <domain> SOA +short
# inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
# → root.inlanefreight.htb = root@inlanefreight.htb
```

## Step 4: SMTP User Enumeration (VRFY/RCPT TO)

```bash
# VRFY command
(echo "EHLO test"; sleep 1; for u in root admin postmaster cto dev; do echo "VRFY $u"; sleep 0.5; done; echo "QUIT") | nc -w 15 <target-ip> 25

# RCPT TO
(echo "EHLO test"; sleep 1; echo "MAIL FROM:<test@test.com>"; sleep 1; echo "RCPT TO:<root@domain>"; sleep 1; echo "QUIT") | nc -w 15 <target-ip> 25
```

Response codes: `250/252` = user exists, `550` = user unknown.

## Step 5: DNS Zone Transfer (AXFR)

If DNS (port 53) is open, attempt zone transfer to discover all subdomains and internal hosts:

```bash
dig @<target-ip> <domain> AXFR +noall +answer
```

Look for: subdomains (app, dev, internal, mail1, ns), TXT records (SPF, verification tokens), and SOA records.

## Step 6: IMAP ID Extension

```bash
(echo "a1 ID (\"name\" \"test\" \"version\" \"1.0\")"; sleep 1; echo "a2 LOGOUT") | nc -w 10 <target-ip> 143
# * ID ("name" "Dovecot")
```

Reveals server software name even when banner is customized.

## Complete Enumeration Workflow

```bash
# 1. Full port scan
nmap -Pn -sT -p1-65535 --min-rate 1000 -T4 <target-ip>

# 2. Grab all banners
echo "QUIT" | nc -w 5 <target-ip> 25    # SMTP
echo "QUIT" | nc -w 5 <target-ip> 110   # POP3
echo "a1 LOGOUT" | nc -w 5 <target-ip> 143  # IMAP

# 3. Extract all TLS certs
echo "a1 LOGOUT" | openssl s_client -starttls imap -connect <target-ip>:143 2>/dev/null | openssl x509 -noout -subject -issuer -email
echo "QUIT" | openssl s_client -starttls pop3 -connect <target-ip>:110 2>/dev/null | openssl x509 -noout -subject -issuer -email
echo "QUIT" | openssl s_client -starttls smtp -connect <target-ip>:25 2>/dev/null | openssl x509 -noout -subject -issuer -email

# 4. DNS SOA for admin email
dig @<target-ip> <domain> SOA +short

# 5. DNS AXFR for subdomains
dig @<target-ip> <domain> AXFR +noall +answer

# 6. SMTP VRFY for valid users
(echo "EHLO test"; sleep 1; for u in root admin postmaster cto dev; do echo "VRFY $u"; sleep 0.5; done; echo "QUIT") | nc -w 15 <target-ip> 25
```

## Answer Mapping (HTB Academy / CTF)

| Question | Source | Command |
|---|---|---|
| Organization name | TLS cert `O=` field | `openssl s_client -starttls imap ... \| openssl x509 -noout -subject` |
| FQDN of IMAP/POP3 | TLS cert `CN=` field | Same as above |
| Admin email | TLS cert `emailAddress=` or DNS SOA RNAME | Check ALL service certs + SOA |
| Customized POP3 version | POP3 greeting banner | `echo "QUIT" \| nc <ip> 110` |
| IMAP flag | IMAP greeting CAPABILITY line | `echo "a1 LOGOUT" \| nc <ip> 143` |

## Related Skills

- `imap-pentest` — IMAP-specific pentesting (auth, mailboxes, NTLM)
- `pop3-pentesting` — POP3-specific pentesting (auth, messages, brute force)
- `smtp-pentest` — SMTP-specific pentesting (open relay, VRFY, SPF/DKIM/DMARC)
- `dns-pentesting` — DNS zone transfers, subdomain enumeration
