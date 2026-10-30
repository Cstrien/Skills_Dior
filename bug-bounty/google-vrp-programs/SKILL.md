---
name: google-vrp-programs
description: Use when picking targets or filing on Google VRP.
---

# GOOGLE VRP PROGRAMS — navigation & reward economics (verified Oct 2026)

Pairs with `google-vrp-playbook` (attack patterns from writeup corpus). This skill covers WHERE to hunt and HOW rewards are computed.

## Navigation pitfall (scope is hidden)

The Rules & Rewards section has NO subdomain-list scope anymore — Google uses a **domain-tier model**. Scope pages hide behind expandable toggle buttons in the left tree, and each program's full rules live at a **numeric-ID URL** not linked from the top nav. If a page looks like a summary table with no scope, click the `(rules)` links in each program row or use the URLs below. Report submission requires a logged-in Google account at `bughunters.google.com/report` (the dropdown there lists all programs).

## Program rules URLs (numeric IDs)

Base: `bughunters.google.com/about/rules/`

| Program | URL suffix |
|---|---|
| Google & Alphabet VRP (web) | `6625378258649088/google-and-alphabet-vulnerability-reward-program-vrp-rules` |
| AI VRP | `5222232590712832/ai-vulnerability-reward-program-rules` |
| Cloud VRP | `4849867320328192/cloud-vulnerability-reward-program-rules` |
| Abuse VRP | `5238081279623168/abuse-vulnerability-reward-program-rules` |
| Chrome VRP | `5745167867576320/chrome-vulnerability-reward-program-rules` |
| ChromeOS VRP | `4919474699501568/chromeos-vulnerability-reward-program-rules` |
| Chrome Extensions VRP | `5668215344988160/chrome-extensions-vulnerability-reward-program-rules` |
| Android & Devices | `6171833274204160/android-and-google-devices-security-reward-program-rules` |
| Mobile VRP | `6618732618186752/google-mobile-vulnerability-reward-program-rules` |
| OSS VRP | `6521337925468160/google-open-source-software-vulnerability-reward-program-rules` |
| Bonus Awards (time-limited +75%) | `5429687846305792/bonus-awards-rules` |
| Research Grant | `5479188746993664/vulnerability-research-grant-rules` |

On hold (Oct 2026): Tsunami, InternetCTF Tsunami, OSV-SCALIBR patch rewards. Verily runs separately on HackerOne.

## Google VRP scope (domain-tier)

In principle: ANY Google-owned / Alphabet (Bet) web service handling reasonably sensitive user data. Named domains: `*.google.com`, `*.youtube.com`, `*.blogger.com`, `*.deepmind.com`, `*.waymo.com`, `*.wing.com` + Google/Waymo apps on the Apple App Store.

Hard exclusions:
- Google Cloud CUSTOMER apps — not VRP-authorized.
- `*.googleusercontent.com` sandbox domains — JS execution there is not a bug absent demonstrated impact on sensitive data.
- `*.blogspot.com`, known redirectors, Google Translate.
- Newly acquired companies: 6-month blackout.

## Reward table (T2 = normal *.google.com)

| Category | T2 | T0/T1 domain |
|---|---|---|
| Server RCE (S0) | $75,000 | $101,010 |
| Logic flaw / IDOR — IT0 data or Critical Actions (S2a) | $31,337 | $50,000 |
| Logic flaw / IDOR — IT1 or Impactful (S2b) | $13,337 | $31,337 |
| Logic flaw / IDOR — IT2 or Moderate (S2c) | $3,133.7 | $7,500 |
| Client code exec / XSS (C0) | $10,000 | $20,000 |
| CSRF / XS-Leak — IT0 or Critical (C1a) | $7,500 | $15,000 |
| CSRF / XS-Leak — IT1 (C1b) | $3,133.7 | $5,000 |
| CSRF / XS-Leak — IT2 (C1c) | $1,337 | $1,337 |

- **Quality multiplier 0.8x / 1x / 1.2x.** 1.2x needs: complete impact analysis, automated PoC when possible, full target info, reproduction output, responses <3 workdays. Slow or "AI slop" responses → 0.8x.
- Reward is frozen at triage — get quality right in the FIRST submission; later additions don't raise it.
- Appeal window: 1 month from reward notification, via the appeal button on the report; must cite rules + new information (fix bypasses discovered later are exempt from the deadline).

## Downgrades (each = one step down, stackable)
Impact (minor), Prior access, Project access, User interaction (significant victim interaction), Exploitability (impractical), Drive ID knowledge (ID retrieval not demonstrated), OAuth consent standard / sensitive / restricted (restricted = TWO downgrades when app-verification path not demonstrated).

## Upgrades
Novelty +$1k–$5k (discretionary); time-limited bonus +75% (published on Bonus Awards page); swag (mystery). Precedents: incidents $500, 3rd-party system $100-500, security-impacting doc fix $100-500.

## Hunting priorities
1. AI VRP products (Gemini/NotebookLM/agentic) — hottest surface, bugSWAT live events with bonus awards.
2. GCP services with owner-vs-viewer credential splits (Looker/Looker Studio pattern — see google-vrp-playbook).
3. Abuse VRP — under-hunted; info-leak/deanonymization pays $5k-20k when chained cross-product.
4. Watch Bonus Awards page: +75% multipliers on specific targets.
