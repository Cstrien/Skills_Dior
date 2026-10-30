# Yjs / CRDT collaborative-editor WebSocket testing — detailed notes

Session-verified against whiteboard.platacard.mx (Plata, 2026-09-28). PoC scripts from that session: ~/recon/bancoplata.mx/{wb_room_poc.py, wb_sync_async.py, ws_probe.py, ws_variants.py, ws_corrupt.py} and /tmp/ywstest/{raw_test.js, sync_test.js}.

## 1. Recon entry: how the sync layer hides in the bundle

URL crawlers find nothing; the API lives in the JS chunk. Grep targets (minified names vary):

| Grep | Meaning |
|---|---|
| `"/api/rooms"` | REST room lifecycle (create/status) |
| `new WebsocketProvider(` | y-websocket client ctor |
| `Sec-WebSocket-Protocol` | the swsp (subprotocol-as-sync) pattern |
| `window.location.origin.replace(/^http/,"ws")+"/ws"` | same-origin ws endpoint |
| `get_text("monaco")` / `get_map("settings")` | shared Yjs types |

Provider ctor decoded (minified): `new WebsocketProvider(\`${origin}/ws\`, roomName, doc, {params:{room: roomName}})` → endpoint `wss://host/ws?room=<name>`; the *room name doubles as the sync channel*, and the client's `bcChannel = serverUrl + "/" + roomname`.

## 2. The swsp handshake (verified)

The client puts `base64(<syncStep1 message>)` into the WebSocket upgrade's `Sec-WebSocket-Protocol` header. The server decodes it as the client's first sync message — the handshake response carries the initial empty-SV syncStep2 (`00 00 01 00`) in the first binary frame.

Verified behaviors:
- **Single token only**: a multi-token `Sec-WebSocket-Protocol` header → HTTP 403 on upgrade.
- Padding `=` is accepted by Node's ws server (curl_cffi sends it fine); Python `websockets` client validates token charset and refuses to SEND such a token client-side.
- After handshake the server pings awareness `[1,1,0]` (awareness update with 0 states) every ~20s.

## 3. Wire format (byte-level, verified)

Top-level frame: `[msgtype u8][varuint len][sub]`

- msgtype **0** = sync; sub = `[subtype u8][varuint len][payload]`
  - subtype **0** = syncStep1(stateVector)
  - subtype **1** = syncStep2(update)
- msgtype **1** = awareness; sub = varuint count + per state `(varuint client, varuint clock, varuint len, json-bytes)`
- msgtype **3** = syncStep1-only query variant seen in lib (`_q4=3` constant)

State vector binary: varuint count + `(varuint client, varuint clock)*` (readStateVector decodes from the rest decoder; server-side sv from a fresh client = single `00`).

Yjs update binary (from `y_py`): starts `[0x01][varint clientid][varint clock]...` with embedded type guids (e.g. `066d6f6e61636f` = "monaco"); awareness-carrying update frames also embed `2801 08737474696e6773...` markers. Always generate with `y_py`/`yjs` — hand-encoding CRDT binary is error-prone.

## 4. Room-API attack surface (all verified unauth on the reference target)

```
POST /api/rooms            → 201 {"id":"16hex"}    no session required
GET  /api/rooms/{id}       → 200 {"id","status":"open|closed"}
GET  /room/{id}            → 200 SPA HTML
GET  /api/rooms/nonexistent→ 404 "room not found"
GET  /ws (no room)         → 400 "invalid or missing room"
GET  /api/rooms/{id}/bad-id→ 400 "invalid room id"  (regex [a-zA-Z0-9._-]{1,256})
```

Key findings:
- **id space = 2^64** → link-as-secret; brute force is a false positive class. Hunt link leakage instead (referrer, logs, API responses echoing room ids).
- **Closed-room resurrection candidate**: closed rooms still return 200 + `status:"closed"`; the app treats "closed" as dead client-side only. The /ws sync path may not re-check status — test by syncing into a closed room (needs server-side confirm; unfinished in the source session).
- **No owner concept** at creation: no identity binding, no rate limit observed pre-CF.
- Room status check on JS side: `status==="open"||status==="closed"` else error — so any server value outside that set breaks the app (DoS-ish, low).

## 5. Sync-path tests that matter

1. **Write propagation**: client A sends syncStep2(update with text) while client B is connected → B receives step2 containing the text. Definitive confirmation of server-side persistence/relay.
2. **Closed-room write**: same as (1) but room status = closed.
3. **Awareness spoofing**: awareness states are client-asserted JSON `{user:{name,color,isCreator}}`; server accepted and would relay. `isCreator` is a client-side flag — check whether server enforces any creator-only actions against it.
4. **Malformed frames**: corrupt step2/awareness payloads → server swallowed errors silently (no crash, no error reply) in the reference case; distinguish swallow from reject.
5. **Malformed awareness JSON with HTML/script chars**: app renders remote user names into CSS `content:"..."` with some sanitization (`cp4` strips `\"'();{}\\n\\r\\t`) — residual CSS-content injection surface (unverified in session).

## 6. Tooling results table

| Client | swsp support | ping/pong | verdict |
|---|---|---|---|
| Node `ws` + raw framing | yes (lib accepts any token) | proper | **best for protocol work** |
| Node `y-websocket` WebsocketProvider | built-in | proper | **best for genuine-client confirmation** |
| curl_cffi `ws_connect` | yes (with `=` padding) | unreliable — silent death 20–40s | handshake confirm only |
| Python `websockets` lib | rejects `=` padding, rejects multi-token | proper | bad fit |

Node specifics learned:
- `websockets` (Python) and `ws` (Node) reject multi-protocol arrays client-side; Node's ws lib accepts a single-element array even with `=`.
- `y-websocket` in Node: polyfill `global.WebSocket = require('ws')` before use; the provider retries on failed connect (backoff) — watch `'connection-error'` events.
- `y_py` pip install: needs `--break-system-packages` on Kali.

## 7. Cloudflare bot-management hard block (verified)

After ~30 min of WS/POST testing on the same host/IP: `POST /api/rooms` → 403 CF challenge page ("Checking your browser"); then `GET /` also 403. Persists across UA rotation (chrome120/chrome131 TLS-fps), 5-min, 30-min cooldowns. Recovery observed/planned: rotate IP (VPN/Tor) or use a real desktop browser (chromium via computer_use) — headless chromium in a non-display terminal session fails with "Missing X server or $DISPLAY".

Lesson: budget WS/API requests up front; once CF bot-management blocks the session, protocol work stops until IP rotation.

## 8. Room-status API + client gating detail (for the resurrection test)

JS `e16` room-status checker: `GET /api/rooms/{id}` → 404 "not_found"; 200 + `status` must be exactly `open|closed` else "malformed response". Join gate `yH4` blocks closed. **All client-side.** The ws server side is a separate y-websocket process — resurrection is plausible but was unconfirmed at session end.
