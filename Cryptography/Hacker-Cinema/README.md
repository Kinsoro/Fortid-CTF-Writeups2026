Hacker Cinema — ECDSA Nonce Reuse via PHP DateTime Parsing Divergence | FortID CTF

A. Title and Metadata
Field	Value
Challenge	Hacker Cinema
Platform	FortID CTF (inst5.ctf.fortid.com)
Category	Cryptography / Web
Flag Format	FortID{...}
Date	2026-10-10
Author	CTF Operator


B. Executive Summary
The Hacker Cinema challenge presents a ticket-signing service built on ECDSA over secp256k1. Tickets are signed with a deterministic nonce derived from the ticket data and a secret seed. The vulnerability stems from a discrepancy between two PHP date-parsing methods used in the codebase: DateTimeImmutable::createFromFormat('U', ...) for the ticket date and new DateTimeImmutable('@' . ...) for the kiosk partition date. For timestamps corresponding to the year 0000 (specifically 0000-01-30 through 0000-02-29), these two methods produce different calendar dates. This causes two distinct tickets (different date field, same seat and screening window) to be signed with the same ECDSA nonce k. With two signatures sharing r but having different s values, the private signing key is recovered algebraically. A forged winner: true ticket is then signed and accepted by the prize checker, yielding the flag.


C. Challenge Overview
Description (from challenge page):
🎬✨ NOW OPEN: Hacker Cinema ✨🎬
We're the city's newest movie theater, and we have exactly one film: Hackers from 1995. Every day. Every screening. No sequels, no remakes, no apologies. 🕶️💾
Entry is free, the vibe is cyberpunk, and yes — you'll need a ticket. Grab your seat, and come enjoy the most elite cinema experience on the mainframe. 🍿⚡
The application allows users to obtain free tickets for screenings of Hackers (1995). Each ticket contains a QR code encoding a JSON envelope with the ticket data and an ECDSA signature. A separate "Prize Checker" endpoint accepts uploaded QR ticket images; if the signature verifies and the ticket's winner field is true, the flag is returned.
Objective: Obtain a valid ticket with "winner": true and submit it to the prize checker.
Provided Materials: A handout ZIP (handout (30).zip) containing the full PHP source code, Dockerfile, docker-compose.yml, and a dummy flag.


<img width="1122" height="560" alt="image" src="https://github.com/user-attachments/assets/950a46b9-da0c-4de0-bfa2-1a735c96eef6" />

D. Environment and Tools
Tool	Version	Purpose
Python	3.12.3	Scripting, cryptographic computation, HTTP interaction
OpenCV	5.0.0	QR code decoding from ticket PNGs
qrcode	8.2	Generating forged QR codes
PHP	8.3.6 (extracted from .deb)	Local reproduction of date-parsing behavior
curl / requests	—	HTTP requests to challenge server
Docker (unavailable in WSL)	—	Source inspection only; challenge hosted remotely


E. Methodology and Reconnaissance
1. Source Code Review
Objective: Understand the ticket generation, signing, and verification logic.
Action: Extracted and read the handout ZIP.
Evidence: Key source files:
- src/crypto.php — ECDSA implementation over secp256k1 using PHP GMP
- src/tickets.php — Ticket creation, nonce derivation, verification
- src/calendar.php — Two date functions: ticket_date_from_timestamp() and kiosk_partition_date()
- src/config.php — Constants and secret seed loading
- public/index.php — HTTP endpoints: /buy, /ticket, /ticket.png, /check
Interpretation: The critical observation is in tickets.php:
function derive_nonce(array $ticket, int $screeningTs): GMP {
    $domain = [
        'movie' => $ticket['movie'],
        'screen' => $ticket['screen'],
        'seat' => $ticket['seat'],
        'date' => kiosk_partition_date($screeningTs),  // <-- kiosk date
        'winner' => $ticket['winner'],
    ];
    $material = hash_hmac('sha256', 'ticket-v1|' . canonical_json($domain), nonce_key(), true);
    return gmp_add(gmp_mod(gmp_from_bytes($material), gmp_sub(N(), 1)), 1);
}
The nonce depends on kiosk_partition_date($screeningTs). Meanwhile, the ticket's own date field comes from ticket_date_from_timestamp($screeningTs) in make_ticket(). If these two functions ever return different dates for the same timestamp, two tickets with different date fields but identical seat, screen, movie, and winner will derive the same nonce k.




2. Date Function Analysis
Objective: Determine whether ticket_date_from_timestamp() and kiosk_partition_date() can diverge.
Action: Extracted PHP binary from Ubuntu package and tested both functions across the allowed timestamp range (MIN_SCREENING_TS = -70000000000 to MAX_SCREENING_TS = 4102444800).
// calendar.php
function ticket_date_from_timestamp(int $ts): string {
    $dt = DateTimeImmutable::createFromFormat('U', (string)$ts);
    return $dt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d');
}
function kiosk_partition_date(int $ts): string {
    $dt = new DateTimeImmutable('@' . (string)$ts);
    return $dt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d');
}
Evidence: Sweep of all ~857,000 days in range revealed exactly one contiguous region of divergence:
Region: -62164686400 (0000-01-30 ticket / 0000-01-29 kiosk)
        to -62162094400 (0000-02-29 ticket / 0000-02-28 kiosk)
Length: 31 days
For example:
- screeningTs = -62164756800 (noon 0000-01-29): both return 0000-01-29 ✓
- screeningTs = -62164670400 (noon 0000-01-30): ticket=0000-01-30, kiosk=0000-01-29 ✗
Interpretation: The @ constructor and createFromFormat('U') handle the year-0000 transition differently in PHP 8.4. This is a known edge case in PHP's DateTime implementation around the proleptic Gregorian calendar boundary. The nonce derivation uses the kiosk date, so any two timestamps in this 31-day window that map to the same kiosk date will produce identical nonces.



3. Remote Ticket Acquisition
Objective: Obtain two valid tickets with the same seat (C07), different ticket dates, but same kiosk date (hence same r).
Action: Queried the live /buy endpoint with two timestamps in the divergence window:

# tsA = -62164756800  -> ticket.date = 0000-01-29, kiosk.date = 0000-01-29
# tsB = -62164670400  -> ticket.date = 0000-01-30, kiosk.date = 0000-01-29
Evidence: Decoded QR payloads from returned PNGs:
Ticket A (screening=-62164756800):
{
  "signature": {
    "alg": "ECDSA-secp256k1-SHA256",
    "r": "70ff1503eb76ff9c66e2bd6957ac895294574e58bd52187d0ce809f3ca78040c",
    "s": "f9d7de738aea1e5d87f0019880538788cf120977641f73b0f965f553e9ac9995"
  },
  "ticket": {
    "date": "0000-01-29",
    "movie": "Hackers",
    "screen": "mainframe-1",
    "seat": "C07",
    "winner": false
  }
}
Ticket B (screening=-62164670400):
{
  "signature": {
    "alg": "ECDSA-secp256k1-SHA256",
    "r": "70ff1503eb76ff9c66e2bd6957ac895294574e58bd52187d0ce809f3ca78040c",
    "s": "cc440576eae9412b4c31e3b57fa057f20d105ab37f63718364cbec7359720648"
  },
  "ticket": {
    "date": "0000-01-30",
    "movie": "Hackers",
    "screen": "mainframe-1",
    "seat": "C07",
    "winner": false
  }
}
Interpretation: Identical r value confirms nonce reuse. The two messages differ only in the date field. This is sufficient to recover the private key.


F. Vulnerability Analysis
Root Cause
The application uses two different PHP DateTime construction methods for what should be the same semantic operation (converting a Unix timestamp to a UTC date):
Function	Method	Purpose
ticket_date_from_timestamp()	DateTimeImmutable::createFromFormat('U', (string)$ts)	Ticket date field (signed message)
kiosk_partition_date()	new DateTimeImmutable('@' . (string)$ts)	Nonce derivation domain separator
For timestamps in the range [-62164713600, -62162078400) (corresponding to 0000-01-30 00:00:00 through 0000-02-29 23:59:59 UTC), these methods return different dates. The @ constructor treats the timestamp as a proleptic Gregorian date, while createFromFormat('U') exhibits an off-by-one discrepancy in this specific epoch region.



Impact
- Nonce reuse across distinct messages: Same k → same r, different s.
- Private key recovery: Standard ECDSA nonce-reuse algebra yields the static signing key d.
- Full signature forgery: With d, arbitrary tickets (including winner: true) can be signed and will pass verification.
Prerequisites
- Ability to purchase tickets for arbitrary screening timestamps (the /buy endpoint accepts any integer within [MIN_SCREENING_TS, MAX_SCREENING_TS]).
- Ability to decode QR codes from returned PNGs (public /ticket.png endpoint).
- No authentication or rate limiting on ticket purchase.



G. Exploitation Walkthrough
Step 1: Recover Private Key from Two Signatures
Given two signatures (r, s₁) and (r, s₂) on messages with hashes z₁, z₂:
k = (z₁ - z₂) / (s₁ - s₂)  (mod n)
d = (s₁·k - z₁) / r        (mod n)
Script (recover_key.py):
#!/usr/bin/env python3
import hashlib, json

# secp256k1 order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',',':'), ensure_ascii=False)

def sha256_int(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest(), 'big') % n

# Recovered from QR codes
ticketA = {"date":"0000-01-29","movie":"Hackers","screen":"mainframe-1","seat":"C07","winner":False}
ticketB = {"date":"0000-01-30","movie":"Hackers","screen":"mainframe-1","seat":"C07","winner":False}

msgA = canonical(ticketA)
msgB = canonical(ticketB)
z1 = sha256_int(msgA)
z2 = sha256_int(msgB)

r = 0x70ff1503eb76ff9c66e2bd6957ac895294574e58bd52187d0ce809f3ca78040c
s1 = 0xf9d7de738aea1e5d87f0019880538788cf120977641f73b0f965f553e9ac9995
s2 = 0xcc440576eae9412b4c31e3b57fa057f20d105ab37f63718364cbec7359720648

k = (z1 - z2) * pow(s1 - s2, -1, n) % n
d = (s1 * k - z1) * pow(r, -1, n) % n

print(f"Private key d = {hex(d)}")
# d = 0x19687fd582d31714dfc9a0e2c1e89eccb9c2ce60bd7b5092f0e16c800acb7374
Output:
Private key d = 0x19687fd582d31714dfc9a0e2c1e89eccb9c2ce60bd7b5092f0e16c800acb7374
Verification: scalar_mul(d) reproduces the public key used by the server.




Step 2: Forge a Winner Ticket
Using the recovered private key d, sign a ticket with "winner": true for any valid date/seat.
Script (forge_ticket.py):
#!/usr/bin/env python3
import hashlib, json, secrets
from ecdsa import SigningKey, SECP256k1  # or use pure-Python implementation

# Use the recovered private key
d = 0x19687fd582d31714dfc9a0e2c1e89eccb9c2ce60bd7b5092f0e16c800acb7374
sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)

ticket = {
    "date": "2026-10-11",
    "movie": "Hackers",
    "screen": "mainframe-1",
    "seat": "C07",
    "winner": True
}

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',',':'), ensure_ascii=False)

msg = canonical(ticket)
sig = sk.sign(msg.encode(), hashfunc=hashlib.sha256, sigencode=lambda r,s,_: (r,s))
r, s = sig

envelope = {
    "ticket": ticket,
    "signature": {
        "alg": "ECDSA-secp256k1-SHA256",
        "r": f"{r:064x}",
        "s": f"{s:064x}"
    }
}

payload = canonical(envelope)
print(payload)

# Generate QR code
import qrcode
qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
qr.add_data(payload)
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")
img.save("forge_qr.png")
Output (truncated):
{"signature":{"alg":"ECDSA-secp256k1-SHA256","r":"d3d511dcb56be09ea1715c5f90ef4127745f96e3adbfc7540e71268bbca3ca69","s":"8c672c7022988cd34072f5ed28f1231569852d05f98032d6e15cf59563f664f8"},"ticket":{"date":"2026-10-11","movie":"Hackers","screen":"mainframe-1","seat":"C07","winner":true}}



Step 3: Submit Forged Ticket to Prize Checker
Action: POST the forged QR PNG to /check.
curl -X POST -F "qr=@forge_qr.png" \
  https://hacker-cinema-bcdaeb24c8e3.inst5.ctf.fortid.com/check
Evidence (response excerpt):
<p class="ok">JACKPOT ACCEPTED.</p>
<pre>FortID{F0rg3_7h3_T1ck37_4nd_H4CK_TH3_PL4N3T!_9cf55f6dc8}</pre>



H. Flag Retrieval and Verification
The prize checker responded with JACKPOT ACCEPTED. and the flag in the required format:
FortID{F0rg3_7h3_T1ck37_4nd_H4CK_TH3_PL4N3T!_9cf55f6dc8}
The flag was verified by the challenge's own verification logic (signature verification + winner check) and displayed in the HTTP response.



I. Root Cause and Remediation
Root Cause
1. Inconsistent date parsing: Two code paths convert the same Unix timestamp to a date string using different PHP DateTime constructors, which behave differently for year 0000 timestamps.
2. Nonce derivation includes a mutable date: The kiosk partition date (derived from the screening timestamp, not the ticket's own date field) is used as a domain separator for HMAC-based nonce derivation. When the two date functions diverge, distinct messages map to the same nonce.
3. Deterministic nonce without message binding: The nonce is derived from a subset of ticket fields. It does not incorporate the full message hash (as RFC 6979 does), so collisions in the domain separator directly cause nonce reuse.




Remediation
Issue	Fix
Inconsistent date parsing	Use a single canonical date function everywhere. Prefer new DateTimeImmutable('@' . $ts) or DateTimeImmutable::createFromTimestamp() (PHP 8.4+) consistently.
Nonce derivation	Adopt RFC 6979 deterministic ECDSA: k = HMAC(private_key, message_hash) or `k = HMAC(seed, message_hash
Input validation	Reject screening timestamps outside a reasonable range (e.g., 1970–2100) unless the challenge explicitly requires historical/future dates.
Secret handling	The signing seed and nonce seed are stored in /tmp with predictable names. Use environment variables or a secrets manager in production.



Challenge-Specific vs. Production Risk
This challenge intentionally exposes a PHP edge case. In production:
- Year-0000 timestamps are never legitimate input.
- RFC 6979 or a similar standard should be used for deterministic ECDSA.
- The same date function must be used consistently across the codebase.


J. Lessons Learned
- Date/time handling is a cryptographic boundary. Subtle differences in timestamp-to-date conversion can break deterministic signing schemes. Always use a single, well-tested function for all date derivations that feed into cryptographic operations.
- Nonce reuse is fatal for ECDSA. Even a single nonce reuse across two distinct messages fully compromises the private key. The nonce must be uniquely bound to the message (RFC 6979) or generated with a CSPRNG with sufficient entropy.
- Trust boundaries in CTF challenges often hide in utility functions. The calendar.php file appeared innocuous but contained the critical inconsistency. Thorough code review of all supporting modules—not just the "crypto" file—is essential.
- Reproducibility matters. Local reproduction of the PHP date behavior (using an extracted php8.3 binary) confirmed the divergence before any remote interaction, ensuring the exploit would work against the live server.


K. References
1. PHP DateTime Documentation — DateTimeImmutable::createFromFormat, @ constructor behavior  
https://www.php.net/manual/en/datetimeimmutable.createfromformat.php
2. RFC 6979 — Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)  
https://tools.ietf.org/html/rfc6979
3. secp256k1 Parameters — Standards for Efficient Cryptography Group (SECG)  
https://www.secg.org/sec2-v2.pdf
4. ECDSA Nonce Reuse Attack — Standard cryptanalysis technique  
https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Security
5. PHP Bug #7758 — DateTime created from negative float timestamp is not monotonic (related edge case)  
https://github.com/php/php-src/issues/7758



Files used in the challenge

[handout.zip](https://github.com/user-attachments/files/33282957/handout.zip)










