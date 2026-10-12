# DESBox — 3DES Complementation Attack via Multiset Collision | FortID CTF

**Category:** Cryptography
**Platform:** FortID CTF (inst4.ctf.fortid.com)
**Flag Format:** FortID{...}

## Executive Summary

The DESBox challenge presents a TLS-wrapped service simulating a DOS-era "cryptographic shell" that encrypts a 48-byte flag under 3DES-ECB with a user-supplied key. The key undergoes a random permutation and XOR with a secret mask before parity adjustment. The service enforces multiple key-equivalence checks but overlooks the DES/3DES complementation property when the two keys form a multiset complement rather than a position-wise complement. By crafting two 24-byte keys whose effective bytes (LSB cleared) are complements except for a single misaligned byte, the random permutation yields a full effective complement with probability 1/24. When this occurs, the service's debug decryption oracle under Key B decrypts the bitwise complement of the flag ciphertext, recovering the flag via the complementation identity. The exploit requires ~24 attempts and completes in seconds.

## Challenge Overview

Description (from handout):
I tried to install a famous MS-DOS emulator, but ended up installing this program. I don't think this can run DOOM...

ncat --ssl desbox-6e5f8f949656.inst4.ctf.fortid.com 1337

Use handout (5) file. Flags use the format FortID{...}
The provided handout contains DESBox.py (the service) and secret.py (containing the flag and mask, redacted). The service implements a minimal shell with commands DIR, TYPE, KEYB, DOOM, EXIT. The KEYB command accepts two 24-byte hex keys, loads them through the permutation/XOR/mask pipeline, encrypts the flag under Key A, and offers a debug decryption under Key B for arbitrary ciphertexts.

## Environment and Tools

| Tool | Version | Purpose |
| --- | --- | --- |
| Python | 3.12.3 | Exploit development, local simulation |
| pycryptodomex | 3.23.0 | 3DES implementation (Cryptodome.Cipher.DES3) |
| OpenSSL / ncat | System | TLS connection to challenge service |
| Standard library | socket, ssl, secrets, re | Network I/O, randomness, parsing |

No reverse engineering or binary analysis tools were required; the challenge is pure Python cryptography.

## Methodology and Reconnaissance

### 1. Service Enumeration

Objective: Understand the service interface and key-handling logic.
Action: Connect via TLS and explore the shell.
python3 -c "
import socket, ssl
host='desbox-6e5f8f949656.inst4.ctf.fortid.com'
port=1337
ctx=ssl.create_default_context()
s=socket.create_connection((host,port), timeout=10)
ss=ctx.wrap_socket(s, server_hostname=host)
ss.settimeout(5)
print(ss.recv(4096).decode())
ss.sendall(b'DIR\n')
print(ss.recv(4096).decode())
ss.sendall(b'TYPE README.TXT\n')
print(ss.recv(4096).decode())
"
Evidence (truncated):
C:\> DIR
 Volume in drive C has no label.
 Volume Serial Number is 1337-BEEF
 Directory of C:\
KEYB     COM        3,584  06-24-26  12:00p
README   TXT          640  06-24-26  12:00p
FLAG     BIN           48  06-24-26  12:00p
DESBox README.TXT
-----------------
KEYB.COM accepts two different 24-byte 3DES keys, written as hex.
Before a key is loaded, the keyboard controller randomly permutes its bytes
and xors the result with a resident secret table.
Commands: DIR, TYPE README.TXT, KEYB, DOOM, EXIT
Interpretation: Three files exist; FLAG.BIN is 48 bytes (6 DES blocks). The KEYB command is the attack surface. The README confirms the permutation + XOR + mask pipeline.

### 2. Source Code Analysis

Objective: Recover the exact key derivation and identify constraints.
Action: Read DESBox.py from handout (5).zip.
Key functions:
def permute(a):
    p = list(range(len(a)))
    RNG.shuffle(p)
    return bytes(a[i] for i in p)

def load_key(user_key):
    key = xor(permute(user_key), MASK)
    return DES3.adjust_key_parity(key)

def effective_bytes(k):
    return [b & 0xFE for b in k]

def is_effective_complement(a, b):
    def complement(k):
        return bytes(x ^ 0xff for x in k)
    return effective_bytes(a) == effective_bytes(complement(b))
Checks in read_keys():
if key_a == key_b:                          # raw equality
if effective_bytes(key_a) == effective_bytes(key_b):  # effective equality
if sorted(effective_bytes(key_a)) == sorted(effective_bytes(key_b)):  # multiset equality
if is_effective_complement(key_a, key_b):   # position-wise complement
Interpretation:
- MASK is a fixed 24-byte secret; permute uses fresh randomness per key.
- effective_bytes clears the LSB (DES parity bit). DES3.adjust_key_parity then sets odd parity per byte.
- The complement check is position-wise: it requires a_eff[i] == b_eff[i] ^ 0xFE for all i. It does not check whether the multisets are complements.
- If Ka_eff = complement(Kb_eff) (as multisets after permutation), the DES complementation property applies.
3. Cryptographic Background
DES/3DES Complementation Property:
For any key K and plaintext P:
E_K(P) ^ 0xFF... = E_{K ^ 0xFF...}(P ^ 0xFF...)
In ECB mode this holds per-block. For 3DES-EDE with 24-byte key K = K1||K2||K3, the complement K ^ 0xFF... has each DES subkey complemented, and the property still holds because each DES round obeys it.
Parity Interaction:
DES3.adjust_key_parity forces odd parity on each byte. If x has odd parity, x ^ 0xFF also has odd parity (8-bit complement preserves parity because 8 is even). Therefore, if K_eff = K & 0xFE and Kc_eff = K_eff ^ 0xFE, then adjust_key_parity(Kc_eff) = adjust_key_parity(K) ^ 0xFF. The parity adjustment commutes with complementation.
Key Derivation Under Random Permutation:
Let M_eff = MASK & 0xFE. After permutation π:
Ka_eff[i] = a_eff[π_a(i)] ^ M_eff[i]
Kb_eff[i] = b_eff[π_b(i)] ^ M_eff[i]
M_eff cancels when comparing Ka_eff and Kb_eff. We need Ka_eff[i] = Kb_eff[i] ^ 0xFE for all i, i.e.:
a_eff[π_a(i)] = b_eff[π_b(i)] ^ 0xFE  ∀i
This holds exactly when the permuted sequences are element-wise complements.

### 4. Constructing Keys That Bypass Checks

Objective: Find A, B (24 bytes each) such that:
1. A != B (raw)
2. effective(A) != effective(B) (element-wise)
3. sorted(effective(A)) != sorted(effective(B)) (multiset)
4. is_effective_complement(A, B) == False (position-wise)
5. But after independent random permutations, Pr[sorted(eff(A)) == sorted(eff(B)^FE)] > 0
Design: Use two distinct effective values X and Y (even bytes, so LSB=0).
- A = [Y] + [X]*23  (one Y at position 0, rest X)
- B = [X^FE] + [Y^FE] + [X^FE]*22  (one Y^FE at position 1, rest X^FE)
Verification:

| Check | Result |
| --- | --- |
| A == B | False |
| eff(A) == eff(B) | False (Y vs X^FE at pos 0) |
| sorted(eff(A)) == sorted(eff(B)) | False (multisets differ: {Y, X×23} vs {Y^FE, X^FE×23}) |
| is_effective_complement(A, B) | False (position-wise: A[0]=Y, B[0]^FE = X ≠ Y) |

After independent permutations π_a, π_b, the multisets become complements iff the unique Y in A and unique Y^FE in B land at the same index — probability 1/24.

### 5. Local Simulation

Objective: Confirm the attack works end-to-end with a known flag/mask.
Action: Simulate MASK, FLAG, the key loading, and the complementation decryption.
from Cryptodome.Cipher import DES3
import secrets, os
RNG = secrets.SystemRandom()

# ... (permute, load_key, effective_bytes as above)

MASK = os.urandom(24)
FLAG = b'FortID{' + os.urandom(40) + b'}'
X, Y = 0x00, 0x02
Xp, Yp = X ^ 0xFE, Y ^ 0xFE
A = bytes([Y] + [X]*23)
B = bytes([Xp, Yp] + [Xp]*22)

for _ in range(2000):
    ka = load_key(A, MASK)
    kb = load_key(B, MASK)
    if all((x^y)==0xFE for x,y in zip(effective_bytes(ka), effective_bytes(kb))):
        C = DES3.new(ka, DES3.MODE_ECB).encrypt(FLAG)
        Cstar = bytes(x^0xFF for x in C)
        Pstar = DES3.new(kb, DES3.MODE_ECB).decrypt(Cstar)
        P = bytes(x^0xFF for x in Pstar)
        assert P == FLAG
        break
Result: Complement collision occurs at expected rate (~1/24). Decryption recovers the flag perfectly.

## Vulnerability Analysis

Affected Component: DESBox.py — load_key and read_keys validation logic.
Root Cause: The service checks for position-wise effective complement (is_effective_complement) but not multiset effective complement. The random permutation decorrelates positions, so a multiset complement becomes a position-wise complement with non-negligible probability.
Trust Boundary: The MASK is intended to blind the user keys. However, because the same MASK is XORed after independent permutations, it cancels out in any relation between Ka and Kb that depends only on the multiset of effective bytes.
Prerequisites:
- Attacker can supply two 24-byte keys.
- Service returns Cflag = Enc_{Ka}(FLAG) and provides a decryption oracle under Kb.
- 3DES-ECB mode (no IV, deterministic per-block).
Impact: Full flag recovery (48 bytes) with ~24 attempts. No interaction with MASK or FLAG required beyond observing Cflag.
Why the Observed Behavior Is Exploitable:
The complementation property is a mathematical property of DES/3DES, not an implementation bug. The service's debug oracle (Debug ciphertext>) is the enabler: it decrypts attacker-chosen ciphertext under Kb. By sending Cflag ^ 0xFF..., the oracle returns Dec_{Kb}(Cflag ^ FF) = FLAG ^ FF exactly when Kb = Ka ^ FF (effective). The final ^ FF is computed client-side.

## Exploitation Walkthrough

Exploit Script

# /tmp/opencode/desbox_exploit.py

import socket, ssl, re, time

HOST = 'desbox-6e5f8f949656.inst4.ctf.fortid.com'
PORT = 1337

# Key construction: 23×X + 1×Y  vs  23×X^FE + 1×Y^FE (misaligned)

X, Y = 0x00, 0x02
Xp, Yp = X ^ 0xFE, Y ^ 0xFE
A = bytes([Y] + [X]*23)
B = bytes([Xp, Yp] + [Xp]*22)
A_HEX, B_HEX = A.hex(), B.hex()

def complement(b): return bytes(x ^ 0xFF for x in b)
EXPECTED_PREFIX = b'FortID{'
EXPECTED_COMP = complement(EXPECTED_PREFIX)

def connect():
    ctx = ssl.create_default_context()
    s = socket.create_connection((HOST, PORT), timeout=10)
    return ctx.wrap_socket(s, server_hostname=HOST)

def recv_until(ss, marker, timeout=5):
    ss.settimeout(timeout)
    data = b''
    m = marker.encode() if isinstance(marker, str) else marker
    while m not in data:
        try:
            chunk = ss.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 16384:
            break
    return data

def exploit(max_trials=200):
    ss = connect()
    recv_until(ss, "C:\\> ")

    for trial in range(1, max_trials + 1):
        try:
            ss.sendall(b"KEYB\n")
            d = recv_until(ss, "KEY A> ")
            if b"KEY A>" not in d:
                ss.close()
                ss = connect()
                recv_until(ss, "C:\\> ")
                continue

            ss.sendall((A_HEX + "\n").encode())
            d = recv_until(ss, "KEY B> ")
            if b"KEY B>" not in d:
                print(f"Rejected: {d.decode(errors='replace')}")
                return

            ss.sendall((B_HEX + "\n").encode())
            d = recv_until(ss, "Debug ciphertext> ")
            txt = d.decode(errors='replace')

            if any(kw in txt for kw in ("Bad", "equivalent", "multiset", "symmetric", "size")):
                print(f"Rejected: {txt}")
                return

            # Extract Cflag (96 hex chars = 48 bytes)
            m = re.search(r"[0-9a-fA-F]{96}", txt)
            if not m:
                continue
            Cflag = bytes.fromhex(m.group(0))
            Cstar = complement(Cflag)

            ss.sendall((Cstar.hex() + "\n").encode())
            d2 = recv_until(ss, "C:\\> ")
            txt2 = d2.decode(errors='replace')

            hexes = re.findall(r"[0-9a-fA-F]{32,}", txt2)
            if not hexes:
                continue
            Pstar = bytes.fromhex(hexes[0])
            P = complement(Pstar)

            if P.startswith(EXPECTED_PREFIX):
                print(f"SUCCESS trial {trial}")
                print(f"Flag: {P.decode()}")
                ss.close()
                return P

            if trial % 10 == 0:
                print(f"Trial {trial}: no match")

        except (socket.timeout, ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
            print(f"Network error, reconnecting: {e}")
            ss.close()
            time.sleep(0.5)
            ss = connect()
            recv_until(ss, "C:\\> ")

    ss.close()
    return None

if __name__ == "__main__":
    exploit(300)
Execution Log (Selected)
Trial 1–24: No complement collision; decryption output is random.
Trial 25 (first run):
SUCCESS trial 25
Cflag 6b82f05888b3e9772818995d4105050143b2be088f1c513d296899a926981b020744d0261d00f486ca7703377beb1154
Pstar b9908d8bb6bb84bccfb2af93ce92ccb1c8caa0cfb1a0cca78fcecfcec8ceb1c9a0bccf92af93ccb29a918b8cdedece82
P b'FortID{C0MPl1m3N75_0N_3Xp10171N6_C0mPl3Ments!!1}'
Trial 4 (second run, reconfirmation):
SUCCESS trial 4
Cflag ee52c8bb72d19774600eedadee09086b341e989c2e6cfa19887591d1f4d7cac74279151755c0ed6feba48c8d9a061fd2
Pstar b9908d8bb6bb84bccfb2af93ce92ccb1c8caa0cfb1a0cca78fcecfcec8ceb1c9a0bccf92af93ccb29a918b8cdedece82
P b'FortID{C0MPl1m3N75_0N_3Xp10171N6_C0mPl3Ments!!1}'
Note: Pstar is identical across runs (deterministic given complement collision), confirming the attack's reliability.

## Flag Retrieval and Verification

Flag: FortID{C0MPl1m3N75_0N_3Xp10171N6_C0mPl3Ments!!1}
Verification:
- Length: 48 bytes (matches FLAG.BIN size).
- Format: FortID{...} exactly.
- Content: Printable ASCII, describes the vulnerability ("COMPLEMENTS ON EXPLOITING COMPLEMENTS").

## Root Cause and Remediation

Root Cause: The validation logic assumes that checking position-wise complementation is sufficient to prevent the DES complementation attack. It fails to consider that independent random permutations can align a multiset complement into a position-wise complement with probability 1/n (here 1/24).
Remediation (for a production system using a similar construct):
1. Eliminate the debug oracle. Never decrypt attacker-chosen ciphertext under a related key.
2. Use authenticated encryption (AES-GCM, ChaCha20-Poly1305) instead of raw 3DES-ECB.
3. If key-blinding is required, derive independent keys via a KDF (e.g., HKDF) rather than XOR-with-mask-after-permutation.
4. Check multiset relations if the threat model includes complementation: reject keys where sorted(eff(A)) == sorted(eff(B) ^ 0xFE).
5. Prefer larger keys and modern ciphers. 3DES is deprecated (NIST SP 800-131A); its 64-bit block size also enables sweet32-style collisions.
Challenge-Specific Note: This is an intentionally vulnerable CTF construct. The complementation property is a known DES characteristic since 1977; the puzzle is recognizing that the checks are incomplete.

## Lessons Learned

- Complementation is a multiset property, not just positional. When keys are independently permuted, position-wise checks are insufficient.
- Debug oracles are force multipliers. A single chosen-ciphertext decryption under a related key reduces a mathematical property to a practical exploit.
- Parity adjustment commutes with complementation for 8-bit bytes — a subtle but critical detail that makes the attack work end-to-end without parity errors.
- Probability 1/24 is high enough for a reliable CTF exploit (expected ~24 attempts, <30 seconds over TLS).
The challenge elegantly combines a classic cipher property with a modern "key blinding" implementation flaw. The fix is not to patch the check but to remove the oracle and use authenticated encryption.

## References

- DES Complementation Property:
Diffie, W., & Hellman, M. (1977). Exhaustive Cryptanalysis of the NBS Data Encryption Standard. Computer, 10(6), 74–84.
- NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths (deprecates 3DES).
- pycryptodomex Documentation: Cryptodome.Cipher.DES3.adjust_key_parity behavior.
- Sweet32 Attack: Bhargavan, K., & Leurent, G. (2016). On the Practical (In-)Security of 64-bit Block Ciphers. ACM CCS.
