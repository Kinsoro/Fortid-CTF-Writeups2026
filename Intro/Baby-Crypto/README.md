# Baby Crypto — AES-CTR Nonce Reuse via Plaintext-Derived Nonce | FortID CTF

**Platform:** FortID CTF (inst16)
**Category:** Cryptography
**Difficulty:** Baby / Easy
**Flag Format:** FortID{...}
**Target:** baby-crypto-f0888c7f47dc.inst16.ctf.fortid.com:1337 (SSL)

## Executive Summary

The challenge exposes a "secret vault" service that encrypts user-supplied secrets with AES-128-CTR. The critical flaw: the CTR nonce is derived from the first 8 bytes of the plaintext itself (nonce=plaintext[:8]). Since the flag is inserted as the first secret (Secret #0), its ciphertext is exported alongside any user-controlled entries. By submitting a chosen plaintext whose first 8 bytes match the flag's prefix (FortID{ + one guessed byte), the same keystream is reused, allowing full plaintext recovery via XOR. A single connection blasting 95 candidates recovers the flag in under 15 seconds.

## Challenge Overview

Baby Crypto — Yet another totally secure secret vault implementation 🔒

Connect via ncat --ssl baby-crypto-f0888c7f47dc.inst16.ctf.fortid.com 1337. Flags use the format FortID{...}.
The service presents a menu:
1. Safely Store a Secret Value — encrypts and stores user input
2. Export Vault Data — returns JSON of all stored ciphertexts (hex)
3. Exit
The flag is pre-inserted as Secret #0 before the menu appears. The goal is to recover it.

<img width="1122" height="437" alt="image" src="https://github.com/user-attachments/assets/06647278-fb57-4c3a-aec3-f612a4eb254d" />

## Environment and Tools

| Tool | Version | Purpose |
| --- | --- | --- |
| Python 3 | 3.12+ | Exploit script, crypto operations |
| pycryptodome | 3.20+ | AES-CTR reference implementation |
| openssl / ncat | — | SSL connection verification |
| Standard libs | — | socket, ssl, json, string |

No specialized frameworks required; the exploit is ~60 lines of pure Python.

## Methodology and Reconnaissance

### 1. Source Code Analysis

Objective: Understand the encryption logic and identify the attack surface.
Action: Read chall.py.
Evidence (key excerpts):
class Cipher:
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=plaintext[:8])
        return cipher.encrypt(plaintext)

class Vault:
    def __init__(self):
        self.cipher = Cipher()
        self.entries = {}

    def insert(self, secret_value):
        ciphertext = self.cipher.encrypt(secret_value.encode("utf-8"))
        self.entries[f"Secret #{len(self.entries)}"] = ciphertext.hex()
Interpretation:
- Single Cipher instance → single 16-byte key for the entire session.
- nonce = plaintext[:8] — nonce is derived from the plaintext.
- Vault.insert() encodes to UTF-8, encrypts, stores hex.
- vault.insert(FLAG) runs at startup → Secret #0 is the flag ciphertext.
- export() dumps all entries as JSON → attacker sees Secret #0 ciphertext.
Next step: Verify the nonce length and CTR behavior in PyCryptodome.

### 2. CTR Nonce Semantics Verification

Objective: Confirm that nonce=plaintext[:8] in PyCryptodome's AES-CTR uses the 8-byte nonce as the high bits of the 16-byte counter block (standard), and that keystream depends only on key + nonce.
Action: Local test.
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
def enc(pt: bytes):
    c = AES.new(key, AES.MODE_CTR, nonce=pt[:8])
    return c.encrypt(pt)

FLAG = b'FortID{test_flag_12345}'
C0 = enc(FLAG)

# Chosen plaintext with same 8-byte prefix

P1 = b'FortID{t' + b'A'*50
C1 = enc(P1)

# Recover keystream and decrypt C0

K = bytes(a^b for a,b in zip(C1, P1))
P0rec = bytes(a^b for a,b in zip(C0, K[:len(C0)]))
print(P0rec)  # b'FortID{test_flag_12345}'
Evidence: Output matches FLAG exactly.
Interpretation: CTR keystream is fully determined by (key, nonce). Same nonce → identical keystream. The 8-byte nonce occupies the first 8 bytes of the 16-byte counter block; the remaining 8 bytes are the little-endian block counter (starting at 0). Since both messages start at block 0, the keystream bytes align perfectly.
Next step: Exploit the nonce reuse against the live service.

## Vulnerability Analysis

Component: Cipher.encrypt() in chall.py:34-36.
Root Cause: The CTR nonce is derived from attacker-controlled plaintext (plaintext[:8]). This violates the fundamental CTR requirement that nonces must never repeat under the same key.
Security Assumption Broken: "Unique nonce per encryption" — here, the nonce is a function of the message, so any two messages sharing the same first 8 bytes will reuse the keystream.
Prerequisites:
1. Attacker knows (or can guess) the first 8 bytes of the target plaintext.
2. Attacker can submit chosen plaintexts and obtain their ciphertexts.
3. Target ciphertext is accessible (exported).
Exploitability: The flag format FortID{...} reveals the first 7 bytes. The 8th byte is unknown but printable ASCII. 95 candidates → trivial brute force.
Impact: Full plaintext recovery of any secret whose first 8 bytes can be matched, including the flag.

## Exploitation Walkthrough

### 1. Retrieve Secret #0 Ciphertext

Action: Connect, send option 2 (Export).
import socket, ssl, json

host = 'baby-crypto-f0888c7f47dc.inst16.ctf.fortid.com'
port = 1337
ctx = ssl.create_default_context()
s = socket.create_connection((host, port), timeout=10)
ss = ctx.wrap_socket(s, server_hostname=host)
ss.settimeout(5)

# Consume banner + menu

while b'> ' not in (data := ss.recv(4096)):
    pass

ss.sendall(b'2\n')
out = b''
while b'Secret #0' not in out:
    out += ss.recv(4096)

j = json.loads(out[out.rfind(b'{'):].decode())
C0 = bytes.fromhex(j['Secret #0'])
print(f"C0 length: {len(C0)} bytes")  # 70
Evidence: C0 = 70-byte hex string (flag ciphertext).

### 2. Build Chosen-Plaintext Payloads

Objective: For each printable candidate c for the 8th byte, construct P1 = "FortID{" + c + "A"*72 (80 bytes total, ≥ flag length).
Rationale:
- First 8 bytes = FortID{ + c → matches flag prefix when c is correct.
- Length 80 > 70 → keystream covers entire flag ciphertext.
- Suffix "A"*72 is arbitrary known plaintext.

### 3. Blast All Candidates in One Connection

Objective: Avoid 15-second alarm timeout by sending all inserts + export in a single burst.
charset = [chr(i) for i in range(32, 127)]  # 95 printable ASCII
suffix = "A" * 72

payload = b""
for ch in charset:
    p1 = "FortID{" + ch + suffix
    assert len(p1) == 80
    payload += b"1\n" + p1.encode() + b"\n"
payload += b"2\n"  # final export

ss.sendall(payload)
Evidence: Server processes all 95 inserts, returns JSON with 96 entries (Secret #0 through Secret #95).

4. Recover Flag via Keystream XOR
entries = json.loads(out[out.rfind(b'{'):].decode())
C0 = bytes.fromhex(entries['Secret #0'])

for idx, ch in enumerate(charset):
    C1 = bytes.fromhex(entries[f'Secret #{idx+1}'])
    P1 = ("FortID{" + ch + suffix).encode()
    # Keystream = C1 ^ P1
    K = bytes(a^b for a,b in zip(C1, P1))
    # Flag = C0 ^ K[:len(C0)]
    P0 = bytes(a^b for a,b in zip(C0, K[:len(C0)]))
    try:
        s = P0.decode()
        if s.startswith('FortID{') and s.endswith('}'):
            print(f"FLAG: {s}")
            break
    except UnicodeDecodeError:
        pass
Evidence (actual output):
HIT idx=51 guess='S' -> FortID{St0p_B31ng_Cr3at1v3_With_N0nc3s_0r_You'll_R3gre7_17_84e904ee28}
Verification:
- Only one candidate produces valid UTF-8 with correct flag format.
- Length 70 bytes matches C0.
- Flag ends with } as required.

## Flag Retrieval and Verification

Flag: FortID{St0p_B31ng_Cr3at1v3_With_N0nc3s_0r_You'll_R3gre7_17_84e904ee28}
Verification Steps:
1. Flag format FortID{...} ✓
2. Recovered via cryptographic keystream reuse, not guessing ✓
3. Single candidate survives printable + format filter ✓
4. Length consistent with ciphertext (70 bytes) ✓

## Root Cause and Remediation

### Root Cause

Using plaintext-derived material as a CTR nonce. The nonce must be independent of the plaintext — typically a random value or a counter — to guarantee uniqueness per encryption under the same key.

### Remediation

| Issue | Fix |
| --- | --- |
| Nonce from plaintext | Generate nonce randomly: nonce=get_random_bytes(8) (or 12/16 bytes) |
| No authentication | Use AES-GCM or ChaCha20-Poly1305 (AEAD) |
| Single key for all encryptions | Acceptable if nonce is unique; better: derive per-message keys via HKDF |
| Export leaks all ciphertexts | Encrypt-then-MAC; authenticate before decryption |

Correct CTR Usage (PyCryptodome):
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
nonce = get_random_bytes(8)  # 8 bytes = 64 bits, sufficient for CTR
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(plaintext)

# Transmit: nonce + ciphertext

Production Note: Prefer AES-GCM (MODE_GCM) or ChaCha20-Poly1305 — they provide confidentiality and integrity, preventing ciphertext manipulation.

## Lessons Learned

1. Nonce reuse in CTR is catastrophic — it reduces the cipher to a many-time pad. XOR of two ciphertexts = XOR of plaintexts.
2. Never derive nonces/IVs from plaintext. The nonce's sole job is uniqueness; it must come from a random or monotonic source independent of the message.
3. CTF crypto challenges often test one primitive misuse. Identify the single violated assumption (here: unique nonce) and exploit it directly.
4. Batch requests to beat timeouts. The 15-second alarm forced a single-connection, fire-and-forget exploit — a practical constraint that shapes the solution.

## References

- NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation (CTR mode requirements)
- PyCryptodome AES Documentation — MODE_CTR nonce/counter semantics
- RFC 3686 — AES-CTR with IPsec (nonce construction)
- CryptoCTF 2021 "Baby Crypto" writeups — Similar nonce-reuse pattern in CTF literature

Report compiled from live exploitation against baby-crypto-f0888c7f47dc.inst16.ctf.fortid.com:1337 on 2026-10-09. All commands and outputs reproduced verbatim from the solving session.

### Files used in the challenge

#!/usr/bin/python3

import json
import signal
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import FLAG

BANNER = """
   _____                              _    __            ____
  / ___/___  _______  __________     | |  / /___ ___  __/ / /_
  \\__ \\/ _ \\/ ___/ / / / ___/ _ \\    | | / / __ `/ / / / / __/
 ___/ /  __/ /__/ /_/ / /  /  __/    | |/ / /_/ / /_/ / / /_
/____/\\___/\\___/\\__,_/_/   \\___/     |___/\\__,_/\\__,_/_/\\__/
"""

MENU = """
Options:
  1) Safely Store a Secret Value
  2) Export Vault Data
  3) Exit

"""

class Cipher:
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=plaintext[:8])
        return cipher.encrypt(plaintext)

class Vault:
    def __init__(self):
        self.cipher = Cipher()
        self.entries = {}

    def insert(self, secret_value):
        ciphertext = self.cipher.encrypt(secret_value.encode("utf-8"))
        self.entries[f"Secret #{len(self.entries)}"] = ciphertext.hex()

    def export(self):
        return json.dumps(self.entries)

def timeout_handler(signum, frame):
    print("Timeout!")
    sys.exit(1)

def main():
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(15)

    assert FLAG.startswith("FortID{") and FLAG.endswith("}")

    print(BANNER)

    vault = Vault()
    vault.insert(FLAG)

    print(MENU)

    while True:
        user_input = input("> ").strip()

        if user_input not in ["1", "2", "3"]:
            print("Are you ok?")
            continue

        if int(user_input) == 1:
            user_secret = input("Enter secret: ").strip()
            vault.insert(user_secret)
        elif int(user_input) == 2:
            print(vault.export())
        else:
            break

if __name__ == '__main__':
    main()

[chall.py](https://github.com/user-attachments/files/33284299/chall.py)
