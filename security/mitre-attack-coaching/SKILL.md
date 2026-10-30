---
name: mitre-attack-coaching
description: Use for ATT&CK questions, interview prep, mock interviews.
---

# MITRE ATT&CK — Explanation & Mock Interview Coaching

Context: VN-speaking user prepping for pentest interviews (e.g. Associate Cyber Security - Pentest). He often asks for answer scripts ("tra loi cho toi") and side-questions mid-interview ("X la gi"). Style: red-team framing, tables over prose, concise.

## Format rules (user-validated this session)

- Teach first with a structural model (`TACTIC → TECHNIQUE → SUB-TECH → PROCEDURE`), THEN return to the pending mock question.
- All mappings in tables, not paragraphs.
- End every teaching digression with a "câu chốt" — a 2-3 sentence verbatim script the user can say in the actual interview.
- If user says "khong biet", pivot to full explanation of that concept (not a failed grade); resume mock after.

## Core content bank (validated answers)

**ATT&CK vs CVE/CVSS (user's weak spot — correct wording):**
- ATT&CK = knowledge base of attacker BEHAVIOR (TTP), not a scoring system.
- CVE = catalog of known vulns (IDs); CVSS = severity scoring 0-10.
- Script: "CVE/CVSS trả lời 'lỗ hổng nào, nghiêm trọng bao nhiêu'; ATT&CK trả lời 'attacker sẽ đi đường nào'."

**Tactic vs Technique:** Tactic = WHY/mục tiêu (14 in Enterprise matrix), Technique = HOW (Txxxx), sub-technique (Txxxx.xxx), Procedure = specific group/malware implementation. Example: LSASS dump → Credential Access / T1003.001.

**IOC vs Behavior vs TTP (why SOC hunts behavior):**
- IOC = static artifacts (IP, hash, domain, filename) — TTL ngắn, attacker xoay trong vài ngày, chỉ bắt được cái đã biết.
- Behavior = actions/relations (process ancestry, e.g. WINWORD.EXE → powershell -enc IEX) — khó thay đổi, bắt được variant mới.
- TTP = behavior chuẩn hóa thành ID ATT&CK.
- Script: "IOC là dấu vết tĩnh — attacker xoay được trong một tuần. Behavior khó đổi vì muốn đạt mục tiêu buộc phải làm. Nên blue team hunt theo behavior + map ATT&CK để đo coverage."

**OWASP Top 10 ↔ ATT&CK quick map:** A01→T1190/T1068, A02→T1552/T1539, A03→T1059, A05→T1190/T1133, A07→T1110/T1556, A08→T1195, A09→T1562/T1070, A10→T1190/T1210. A04 (Insecure Design) has no direct mapping — say so, it scores points.

## Interview answer frame for AD attack questions

Every AD/Windows question answered in 4 layers: ATT&CK ID → Event/log ID on target → network signal → tool behavior. E.g.:

- **Kerberoasting:** Credential Access / T1558.003. Telemetry: DC Event 4769 (bulk TGS for many SPNs from one source, encryption 0x17 RC4 downgrade), Kerberos port 88 burst, preceding LDAP SPN enum (4662). Post-use: T1550.003 Pass-the-Ticket.
- **Golden vs Silver Ticket:** Golden = forged TGT signed with krbtgt hash → T1558.001, needs DCSync/NTDS.dit first, persistence (reset krbtgt pwd 2x to invalidate). Silver = forged TGS with service acct hash → T1558.002, limited to that service.
- **Lateral movement (target has Defender+EDR):** WinRM T1021.006 preferred (in-memory via wsmprovhost, no file drop; telemetry = 4624 Type 3, 4688 wsmprovhost, 4104 PS script block log) over psexec-style T1021.002+T1569.002 (drops service binary → Event 7045 "Service Installed" is red flag, Defender scans file on disk). Only hash available → PTH T1550.002 via WMI (T1047), not impacket psexec.
- **WinRM basics:** "SSH của Windows", SOAP over HTTP(S), 5985/5986. Pitfall: non-domain local admin is filtered by default (needs Remote Management Users group or DA) — explains Access denied with correct creds.

## Post-RCE workflow (maps to ATT&CK chain)

Execution → Discovery (whoami/priv, ip a, netstat) → Defense Evasion assessment (what's defending, BEFORE touching) → PrivEsc (Linux: sudo -l/GTFOBins/SUID; Windows: whoami /priv → SeImpersonate → Potato family, unquoted paths) → Credential harvest → internal discovery → Lateral vs deep-dive branch → tunnel/C2 setup early. Script: "RCE không phải đích — nó là cửa. Việc đầu là situation awareness, không phải tấn công tiếp."

## Open mock questions bank (reusable)

Q7 pending: 4 credential sources on a lateral-moved host + technique IDs (registry: T1552.002 Run/RunOnce keys + SAM T1003.002; LSASS: T1003.001; files: T1552.001 credentials in files, config/web.config; network shares: T1555 password stores, GPP T1552.006).
