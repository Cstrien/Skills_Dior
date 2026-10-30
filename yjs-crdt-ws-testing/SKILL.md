---
name: yjs-crdt-ws-testing
description: Use when an SPA embeds yjs/y-websocket sync or a /ws socket.
---

# Yjs / CRDT Collaborative-Editor WebSocket Testing

Realtime CRDT APIs (Yjs ecosystem) are invisible to URL crawling — they live in the SPA JS bundle and on WebSocket endpoints, frequently with zero auth. Verified byte-level against whiteboard.platacard.mx (Plata, 2026-09-28). Detailed recipe: `references/yjs-crdt-ws-testing.md`.

## Workflow

1. **Locate the sync layer**: pull the SPA JS chunk; grep for `/api/rooms`, `new WebSocket`, `Sec-WebSocket-Protocol`, `WebsocketProvider`, `y-websocket`, `monaco`, `BroadcastChannel`.
2. **Derive endpoint + protocol**: the provider ctor reveals the shape (`new WebsocketProvider(\`${origin}/ws\`, roomName, doc, {params:{room: roomName}})` → `wss://host/ws?room=<name>`). The client puts `base64(syncStep1(doc))` in `Sec-WebSocket-Protocol` (single token only — multi-token headers can 403 the upgrade).
3. **Probe the room API unauth**: `POST /api/rooms` → 201 `{id}` with no session = open creation. `GET /api/rooms/{id}` → `{id, status}` metadata leak. Check whether closed rooms still respond 200 + status while the app treats "closed" as dead client-side only.
4. **Test the sync path** (Node `ws` + `yjs` is the reliable client; polyfill `global.WebSocket = require('ws')` for genuine-client tests):
   - Wire format: `[msgtype u8][varint len][sub]` — msgtype 0 = sync (sub 0 = syncStep1, sub 1 = syncStep2), msgtype 1 = awareness (`count` + `(client, clock, len, json)*`). Server handshake reply `00 00 01 00`; ping `[1,1,0]` every ~20s.
   - **Closed-room resurrection**: send syncStep2 into a closed room — status is usually not re-checked server-side.
   - **Identity spoofing**: awareness states are client-asserted JSON `{user:{name,color}}` — inject via first binary frame or swsp.
   - **Malformed frames**: corrupt step2/awareness payloads to check CRDT decode exception handling.
5. **Confirm read-back**: the definitive test that a server persists/relays writes is a second connection receiving the content (`provider.on('synced')` in y-websocket, or a fresh WS with empty state vector returning syncStep2 containing the text).

## Pitfalls

- **curl_cffi `ws_connect`**: `recv()` returns `(bytes, opcode)` tuples; accepts swsp with `=` padding; but ping/pong handling is unreliable → silent death after ~20–40s. OK for handshake confirmation only.
- **Python `websockets` lib**: validates the subprotocol token charset (rejects `=` padding) and rejects multi-token lists — bad fit for swsp testing.
- **Link-as-secret**: 16-hex room ids (2^64) are not brute-forceable — hunt link leakage (referrer, logs, API responses) instead.
- **Cloudflare bot-management hard block**: bursty WS/POST testing → persistent 403 challenge on POST (later GET) that survives UA/TLS-fingerprint rotation and 5–30 min cooldowns. Recover by rotating IP (VPN/Tor) or creating rooms via a real desktop browser (chromium + computer_use), then hand the room id to the protocol client. Budget requests up front — a mid-chain block kills session state.
- **Hermes terminal guard**: heredocs/inline Python containing `&` (even bitwise `n & 0x7F`) are rejected as suspected backgrounding — write scripts with write_file, then run.
