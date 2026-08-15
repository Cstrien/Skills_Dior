# Casino / Gambling Platform Business Logic

Hunting patterns specific to online casino, sports betting, and gambling platforms.
These targets have unique financial primitives — bonuses, wagering requirements,
free spins, deposit matches, crashback, loyalty programs — that create a rich
business-logic attack surface beyond standard e-commerce.

## Crown Jewel Targets

| Surface | Why it pays |
|---------|-------------|
| **Bonus activation/claim endpoints** | Bonus ID enumeration → activate bonuses not entitled to, or stack chainable bonuses |
| **Wagering requirement bypass** | Reduce/eliminate wager multiplier before withdrawing bonus-derived winnings |
| **Deposit-bonus matching** | Trigger deposit match without actual deposit, or at inflated match rate |
| **Free spins / free money** | Claim free spins/money not entitled to, or replay claim |
| **Game launch (demo vs real)** | Access real-money game mode without balance, or manipulate bet amount |
| **Balance / wallet operations** | Race condition on balance debit/credit, double-spend on withdrawal |
| **Loyalty / VIP program** | Bypass tier requirements for cashback/crashback rewards |
| **Raffle / lottery** | Manipulate entry, predict outcome, or claim without qualification |

## Attack Surface Signals

**Endpoint naming conventions (microservice architecture):**
- `MS-BONUS-BALANCES/*` — bonus catalog, activation, claiming
- `FREE-MONEY/*` — free money, raffle, PWA bonus
- `MS-SMALL-THINGS/*` — banners, rules, support chat
- `PROXY-SERVICE-CDP/*` — landing pages, exchange rates, tracking
- `USER-SERVICE-API/*` — OAuth config, user profile, balance
- `internal/casino-*` — game categories, sections, game data
- `web/v1/user` — user state (authed vs unauthed)

**Unauth data exposure (common on casino platforms):**
- `GET /api/MS-BONUS-BALANCES/v2-bonus-list?currency=USD` — returns full bonus
  catalog: bonusId, depositPercent, minDeposit, maxBonusAmount, percent,
  wagerMultiplier, status, eligible/chainable flags, S3 image URLs
- `GET /api/internal/casino-categories` — returns all game categories + IDs + counts
- `GET /api/internal/casino-game-sections` — returns all games + IDs + providers +
  hasDemo flags
- `GET /api/USER-SERVICE-API/api-v3-oauth-config` — returns OAuth client_ids +
  internal redirect domain

These are **attack-surface maps** — the data itself is Low/Medium (bonus structure
disclosure), but the bonusId values enable IDOR attempts on authenticated
activation/claim endpoints.

## Hunting Methodology

### 1. Enumerate bonus catalog unauthenticated

```bash
# Fetch bonus list — no auth required on many casino platforms
curl -sk "https://target.com/api/MS-BONUS-BALANCES/v2-bonus-list?currency=USD" \
  | python3 -m json.tool

# Extract bonusId values for IDOR testing
curl -sk "https://target.com/api/MS-BONUS-BALANCES/v2-bonus-list?currency=USD" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for section in ['chainable', 'eligible', 'available', 'activated']:
    for b in d.get(section, []):
        bid = b.get('bonusId') or b.get('id')
        print(f'{section}: bonusId={bid} type={b.get(\"type\")} label={b.get(\"label\")}')
"
```

### 2. Register account → test authenticated bonus operations

After registering a normal account, test:
- **Bonus IDOR**: Can I activate bonusId 1348 (intended for another user/tier)?
- **Bonus stacking**: Can I activate multiple chainable bonuses simultaneously?
- **Wager bypass**: Can I withdraw without meeting wagerMultiplier (30x)?
- **Deposit match without deposit**: Can I trigger the bonus without the minDeposit?
- **Bonus replay**: Can I claim the same bonusId multiple times?

```bash
# Test bonus activation with leaked bonusId
curl -sk -A "$UA" -H "Content-Type: application/json" \
  -H "Cookie: <authed_session>" \
  -X POST "https://target.com/api/MS-BONUS-BALANCES/v2-bonus-activate" \
  -d '{"data":{"bonusId":1348,"currency":"USD"}}'
```

### 3. Test game launch / demo mode

Many casino platforms have demo (free-play) and real-money modes:
- Can I access real-money game launch without sufficient balance?
- Can I manipulate bet amount below minimum or above balance?
- Is there a race condition between balance check and bet placement?

### 4. Race conditions on wallet/balance

```bash
# Parallel withdrawal requests — does balance debit only once?
for i in $(seq 1 20); do
  curl -sk -A "$UA" -H "Cookie: <authed>" \
    -X POST "https://target.com/api/MS-BILLING/v2-withdraw" \
    -d '{"amount":100,"currency":"USD"}' &
done
wait
```

### 5. S3 bucket name disclosure

Casino platforms often leak S3 bucket names in:
- Bonus image URLs: `visual-archive-bucket-prod.s3.eu-north-1.amazonaws.com/static/...`
- Forum upload paths: `web-k8s-forum-prod.s3.eu-central-1.amazonaws.com/uploads/...`
- Game asset CDN: `v3.bundlecdn.com/casino-images/...`

Test bucket listing:
```bash
curl -sk "https://<bucket-name>.s3.<region>.amazonaws.com/?list-type=2&max-keys=50"
# 403 = listing denied but individual objects may be accessible
curl -sk "https://<bucket-name>.s3.<region>.amazonaws.com/uploads/"
```

## Validation

✅ Bonus IDOR: Activated a bonus not entitled to my account tier — show before/after
✅ Wager bypass: Withdrew bonus-derived winnings without meeting wagerMultiplier
✅ Deposit match without deposit: Received bonus credit without making minDeposit
✅ Balance race: Withdrew more than total balance via parallel requests
✅ Game demo→real: Access real-money game without balance/risk

**Severity:**
- Bonus IDOR / wager bypass / deposit match without deposit: High (direct financial impact)
- Balance race condition: Critical (direct fund theft)
- Unauth bonus catalog disclosure: Medium (attack-surface mapping, enables IDOR)
- Unauth game catalog disclosure: Low-Medium (internal API naming, game ID enumeration)

## Pitfalls

- **ZodError on POST**: Many casino APIs use Zod validation. A 400 with ZodError
  message reveals the expected schema — use it to craft correct payloads, don't
  treat it as a dead end.
- **Rate-limit after initial success**: Cloudflare Bot Management on casino
  platforms will 403 after 10-20 rapid requests. Capture the first successful
  response immediately — it's your evidence. Later 403s don't invalidate earlier 200s.
- **BonusId in query param ignored**: Some endpoints accept `bonusId` as a query
  param but ignore it (return same data regardless). The IDOR is in the POST
  activation endpoint, not the GET listing.
- **Demo mode ≠ real mode**: Demo mode access is usually intended. The bug is
  accessing real-money mode without auth/balance, not demo mode access.

## Session Example: 1win.com

From an authorized private engagement:

**Unauth bonus catalog** (`MS-BONUS-BALANCES/v2-bonus-list?currency=USD`):
Returned bonusId 1347-1350, depositPercent 100-150%, minDeposit $10,
maxBonusAmount $500, wagerMultiplier 30x, status, eligiblePreviewImage
(S3 URL: `visual-archive-bucket-prod.s3.eu-north-1.amazonaws.com`).

**Unauth game catalog** (`internal/casino-game-sections`):
Returned 16,774 games across 16 categories with game IDs (`v_1wingames:luckyjet`,
`v_pragmatic:*`, `v_evolution:*`), provider names, hasDemo flags.

**Next steps (required account)**:
- Register → test bonusId 1348 activation (IDOR on another user's bonus)
- Test wager multiplier bypass on withdrawal
- Test deposit match trigger without minDeposit
- Test game launch in real-money mode without balance
- Test balance race condition on withdrawal

Report saved: `~/bounties/private-1win/reports/hunt-2026-07-26-casino.md`
