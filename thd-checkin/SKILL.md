---
name: thd-checkin
description: "Manage THD check-in server. Use for attendance or restart."
---

# THD Check-in HRM App

## Location
- App dir: `/home/kali/Desktop/Checkin`
- DB: `/home/kali/Desktop/Checkin/prisma/dev.db` (SQLite)
- Logs: `/home/kali/Desktop/Checkin/logs/server.log`
- Port: 3000

## Quick Commands

### Build + Restart
```bash
cd /home/kali/Desktop/Checkin
./run.sh stop    # Kill existing server
./run.sh build   # npm install + prisma generate + tsc + migrate
./run.sh start   # Start production server (nohup, background)
```

### Check Status (no login needed)
```bash
curl -s http://localhost:3000/health  # → {"ok":true}
ss -tlnp | grep 3000                  # → node process
tail -20 /home/kali/Desktop/Checkin/logs/server.log
```

### Generate JWT Token (admin)
Python script — needs JWT_ACCESS_SECRET from `.env`:
```python
import json, time, hmac, hashlib, base64
def b64url(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
header = {"alg":"HS256","typ":"JWT"}
payload = {"sub":"50969e89-2b2f-480e-8299-5011065e204a","email":"admin@thdcybersecurity.com","role":"ADMIN","iat":int(time.time()),"exp":int(time.time())+3600}
secret = "tHlE+bGIkPmWTLLa3bZe/m5GCw909EVy4Lj9iH6ve6ebwQjmlYGtwbyBPnbsj4+C"  # from .env
h = b64url(json.dumps(header).encode())
p = b64url(json.dumps(payload).encode())
sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
token = f"{h}.{p}.{b64url(sig)}"
```

### Check Logs via API
```bash
TOKEN=<generated_token>
curl -s http://localhost:3000/api/hrm/logs?limit=15 -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:3000/api/hrm/schedule -H "Authorization: Bearer $TOKEN"
```

### Manual Checkin/Checkout
```bash
curl -s -X POST http://localhost:3000/api/hrm/checkin \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"checkin","latitude":"10.7812318","longitude":"106.6687496"}'
```

### Direct DB Query (no API needed)
```bash
sqlite3 /home/kali/Desktop/Checkin/prisma/dev.db \
  "SELECT type, success, httpStatus, message, createdAt FROM CheckinLog ORDER BY createdAt DESC LIMIT 10;"
```

## Architecture
- **Stack**: Node.js 22 + Express + Prisma + SQLite
- **Auth**: JWT (access + refresh tokens), HS256
- **Crypto**: AES-256-GCM for HRM credentials (password, TOTP secret, photos)
- **TOTP**: otplib (base32 secret, normalized: strip spaces + uppercase)
- **Scheduler**: node-cron, runs every minute, checks autoEnabled credentials
- **HRM API**: `https://hrm.thdcybersecurity.com/checkinapi/`
  - Flow: POST /auth/login then POST /auth/2fa/login (TOTP) then POST /attendance/checkin|checkout (multipart with photo)

## User Info
- HRM User: trien.l@thdcybersecurity.xyz (THD056, Le_Van_Trien)
- Admin panel user: admin / admin@thdcybersecurity.com
- Latitude: 10.7812318, Longitude: 106.6687496

## Schedule Config
- Auto checkin: random 08:15-08:30 (Asia/Ho_Chi_Minh)
- Auto checkout: 17:30
- Days: all (0-6)
- Retry until: 08:44 if checkin fails
- Skip checkout dates: env AUTO_CHECKOUT_SKIP_DATE (CSV of YYYY-MM-DD)

## Common Issues
1. **"fetch failed"**: Usually TOTP code expired or network issue to HRM. Check if fetch to HRM works from Node.
2. **409 Conflict**: Already checked in/out today. This is success, not error.
3. **Seed fails (ENOENT tsx)**: Ignorable. Admin already exists in DB.
4. **Photo decryption**: Photos stored as AES-256-GCM encrypted base64, decrypted to base64 string, then Buffer.from(base64) gives JPEG bytes (starts with ffd8ffe0).

## API Endpoints
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /health | none | Health check |
| POST | /api/auth/login | none | Login (identifier + password) |
| POST | /api/auth/refresh | cookie | Refresh access token |
| GET | /api/auth/me | JWT | Get current user |
| POST | /api/hrm/checkin | JWT | Trigger checkin/checkout |
| POST | /api/hrm/test-login | JWT | Test HRM credentials |
| GET | /api/hrm/schedule | JWT | Get auto schedule |
| PUT | /api/hrm/schedule | JWT | Update schedule |
| GET | /api/hrm/logs | JWT | Get checkin logs |
| PUT | /api/credentials | JWT | Save HRM credentials |
| GET | /api/credentials | JWT | Get credentials config |
