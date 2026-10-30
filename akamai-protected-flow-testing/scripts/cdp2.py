# A reusable CDP driver for Akamai-protected SPA testing

Copy to the engagement's recon dir and adapt. Requires: Xvfb, chromium, python websocket-client.

Launch (background):
```bash
xvfb-run -a chromium --remote-debugging-port=9222 --remote-allow-origins='*' \
  --user-data-dir=/tmp/<prof> --no-first-run --no-sandbox --disable-gpu 'https://<target>/'
```

# cdp2.py — evaluate expressions in the live page

import json, urllib.request, websocket, time, sys

class CDP:
    def __init__(self, ws_base="http://127.0.0.1:9222"):
        pages = json.load(urllib.request.urlopen(ws_base + "/json"))
        page = [p for p in pages if p.get("type") == "page"][0]
        self.ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=90,
                                              origin="http://127.0.0.1:9222")
        self.i = 0
    def send(self, method, params=None):
        self.i += 1
        self.ws.send(json.dumps({"id": self.i, "method": method, "params": params or {}}))
        return self.i
    def wait_for(self, rid, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            m = json.loads(self.ws.recv())
            if m.get("id") == rid:
                return m
        return None
    def eval(self, expr, await_promise=False, timeout=60):
        rid = self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True,
                                              "awaitPromise": await_promise})
        m = self.wait_for(rid, timeout)
        if not m:
            return None
        r = m.get("result", {})
        if r.get("exceptionDetails"):
            return "EXC: " + json.dumps(r["exceptionDetails"])[:500]
        return r.get("result", {}).get("value")
    def nav(self, url):
        self.send("Page.enable")
        rid = self.send("Page.navigate", {"url": url})
        return self.wait_for(rid, 60)
    def set_react_input(self, el, value):
        """The only reliable method for React-controlled inputs (OTP boxes, phone fields)."""
        self.send("Runtime.evaluate", {"expression": f"""
        (() => {{
          const el = {el};
          const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
          el.focus();
          setter.call(el, {json.dumps(value)});
          el.dispatchEvent(new InputEvent('input', {{bubbles: true, data: {json.dumps(value)}, inputType: 'insertText'}}));
          el.dispatchEvent(new KeyboardEvent('keyup', {{key: {json.dumps(value)}, bubbles: true}}));
          return el.value;
        }})()""", "returnByValue": True})
    def close(self):
        self.ws.close()

# Usage notes:
# - statuses come from performance.getEntriesByType('resource') → .responseStatus
# - OTP components auto-submit on the Nth digit; set all boxes then sleep and read network
# - webpack module extraction probe:
#   let captured=null; window.webpackChunk.push([['probe_'+Date.now()],{},r=>{captured=r;}]);
#   const mod = captured(<module_id>);
