# Baby Rev — T9 Touchtone Decoding with SHA256 Validation | CTF

## Executive Summary

The challenge provides a Python 3.10 bytecode file (chall.pyc) that validates a flag through a multi-stage check: length verification, format enforcement (FortID{...}), word-level character-class constraints, T9 touchtone encoding of the inner content (reversed), and a final SHA256 hash comparison. Static analysis of the bytecode reveals the expected reversed T9 sequence and target hash. Mapping each T9 segment to dictionary words yields a coherent sentence referencing the Nokia 3310 — a classic T9-era device — which satisfies all constraints and produces the correct hash.

## Challenge Overview

Name: Baby Rev
**Platform:** Unspecified CTF (local file challenge)  
**Category:** Reverse Engineering  
**Flag Format:** FortID{...}  
Provided File: chall.pyc (CPython 3.10, 816 bytes source)
The challenge description hints at texting and a flag request: "I've been texting a lot recently, but can't seem to strike a conversation with this person. They keep asking about some kind of flag..."

<img width="1130" height="406" alt="image" src="https://github.com/user-attachments/assets/1a90f26b-16ca-4d02-a7b0-71e93cd22719" />

## Environment and Tools

| Tool | Version | Purpose |
| --- | --- | --- |
| xdis | 6.3.0 | Cross-version Python bytecode disassembly |
| t9text | PyPI | T9 touchtone encoding/decoding library (used by challenge) |
| hashlib | stdlib | SHA256 verification |
| curl | — | Fetching English wordlist for T9 mapping |
| Python | 3.12.3 | Analysis runtime (bytecode compatible with 3.10) |

## Methodology and Reconnaissance

Objective: Recover source logic from chall.pyc
Action: Disassemble bytecode using xdis (supports Python 3.10 MARSHAL format).
python3 -m xdis chall.pyc
Evidence: Full disassembly of <module>, nope(), and two <listcomp> functions. Key constants extracted:
- Length check: 81
- Prefix: "FortID{", Suffix: "}"
- Separator: "_"
- Reversed T9 target: "33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566"
- SHA256 target: "3576c495f89236515fbbfbfb519dceb9899122e92460d418d2ce37a1ff357e0c"
Interpretation: The program:
1. Reads input, verifies len == 81
2. Checks FortID{ prefix and } suffix
3. Extracts inner 73 chars, splits on _
4. Each word must be all lowercase letters OR all digits
5. Joins words with -, computes t9.get_touchtone(joined)[::-1], compares to constant
6. Computes sha256(input) and compares to constant

### 7. Prints success message only if all checks pass

Objective: Understand T9 encoding used by challenge
Action: Inspect t9text source (pip install t9text).

# t9text.t9.get_touchtone mapping

tone_dict = {
    'a':'2','b':'2','c':'2', 'd':'3','e':'3','f':'3',
    'g':'4','h':'4','i':'4', 'j':'5','k':'5','l':'5',
    'm':'6','n':'6','o':'6', 'p':'7','q':'7','r':'7','s':'7',
    't':'8','u':'8','v':'8', 'w':'9','x':'9','y':'9','z':'9',
    '-':'-', '#':'#', '*':'*', '0':'0', ... '9':'9'
}
Interpretation: Standard ITU E.161 T9 mapping. Digits and - pass through unchanged. The challenge reverses the full touchtone string after encoding.

Objective: Reverse the target T9 string to get forward encoding
Action: Reverse the constant.
rev = "33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566"
fwd = rev[::-1]

# "66542-3310-47-78455-843-6678-762878-74323-63-8324665649-4-4283-3837-69633"

Evidence: 14 dash-separated segments, lengths [5,4,2,5,3,4,6,5,2,10,1,4,4,5].

Objective: Map each T9 segment to candidate English words
Action: Fetch wordlist, compute T9 for each word, index by tone string.
curl -sL https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt \
  -o /tmp/words_alpha.txt
from t9text.t9 import get_touchtone
from collections import defaultdict

tone_to_words = defaultdict(list)
for w in open('/tmp/words_alpha.txt'):
    w = w.strip().lower()
    if not w.isalpha(): continue
    if len(w) not in needed_lengths: continue
    tone_to_words[get_touchtone(w)].append(w)
Evidence (segment → candidates):

| Segment | Length | Candidates |
| --- | --- | --- |
| 66542 | 5 | [] (no dictionary match) |
| 3310 | 4 | [] (contains digits 0,1 — must be literal digits) |
| 47 | 2 | is |
| 78455 | 5 | still |
| 843 | 3 | the |
| 6678 | 4 | most |
| 762878 | 6 | robust |
| 74323 | 5 | piece |
| 63 | 2 | of |
| 8324665649 | 10 | technology |
| 4 | 1 | i |
| 4283 | 4 | have |
| 3837 | 4 | ever |
| 69633 | 5 | owned |

Interpretation: 12 of 14 segments map uniquely to common English words. Two segments have no dictionary candidates:
- 3310 → contains 0 and 1 (no T9 letters) → must be the digit word "3310"
- 66542 → maps to nokia (n6 o6 k5 i4 a2), a proper noun absent from standard wordlists

Objective: Assemble candidate flag and verify all constraints
Action: Construct inner string from mapped words, validate character-class rule, compute T9 and hash.
inner = "nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned"
flag = f"FortID{{{inner}}}"
Evidence:
- len(flag) == 81 ✓
- Each _-split word: all(lowercase) or all(digits) ✓
- t9.get_touchtone(inner.replace('_','-'))[::-1] matches reversed constant ✓
- sha256(flag.encode()).hexdigest() matches target hash ✓
3576c495f89236515fbbfbfb519dceb9899122e92460d418d2ce37a1ff357e0c

## Vulnerability Analysis / Key Discovery

The challenge is not a vulnerability in the traditional sense but a reverse-engineering puzzle where the "secret" is embedded as constants in bytecode:
- The reversed T9 string acts as a commitment to the expected plaintext.
- The SHA256 hash provides a second, independent commitment.
- The T9 encoding is lossy (many-to-one), but the dictionary constraint and character-class rule (all alpha or all digits) collapse the solution space to a single meaningful sentence.
Root cause of solvability: hardcoded verification constants in client-side bytecode. No server-side oracle or secret key is involved; all validation logic and expected values are present in the distributed artifact.

Solution Walkthrough
1. Disassemble chall.pyc with xdis to recover constants and logic.
2. Reverse the T9 constant to obtain forward touchtone sequence.
3. Split on - into 14 segments.
4. Build T9→word map from a large English wordlist using t9text.get_touchtone.
5. Resolve each segment: 12 map to unique dictionary words; 3310 is literal digits; 66542 maps to nokia (known T9-era phone model).
6. Join with _, wrap in FortID{...}, verify length, character classes, T9 round-trip, and SHA256.
7. Submit flag.

## Flag Retrieval and Verification

$ python3 -c "
flag='FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}'
import hashlib, t9text.t9 as t9
assert len(flag)==81
assert flag.startswith('FortID{') and flag.endswith('}')
inner=flag[7:-1]
assert all(all(c.islower() for c in w) or all(c.isdigit() for c in w) for w in inner.split('_'))
assert t9.get_touchtone(inner.replace('_','-'))[::-1]=='33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566'
assert hashlib.sha256(flag.encode()).hexdigest()=='3576c495f89236515fbbfbfb519dceb9899122e92460d418d2ce37a1ff357e0c'
print('*\\0/* I knew you could do it! ^5')
"
Output:
*\0/* I knew you could do it! ^5
Flag:
FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}

## Root Cause and Remediation

| Issue | Description | Remediation |
| --- | --- | --- |
| Secrets in client-side bytecode | Expected T9 string and SHA256 hash embedded in distributed .pyc | Move validation to server; use keyed HMAC or asymmetric verification; never ship verification constants to client |
| Deterministic encoding without key | T9 is public, reversible, and keyless | Use authenticated encryption or keyed MAC for integrity checks |
| No anti-analysis | Bytecode stripped only of source; no obfuscation, packing, or anti-debug | Apply bytecode obfuscation (e.g., pyarmor), control-flow flattening, or distribute as native binary |

For a CTF challenge, these properties are intentional. In production, any client-side secret validation is fundamentally broken.

## Lessons Learned

- Python bytecode (.pyc) retains full semantic structure — constants, control flow, and function boundaries — making xdis/uncompyle6 highly effective for reverse engineering.
- T9 encoding is a weak commitment scheme: many-to-one, no key, trivially inverted with a dictionary.
- When a challenge enforces both a structural constraint (T9) and a cryptographic one (SHA256), the structural constraint typically reduces the search space enough to make the cryptographic check a simple verification rather than a barrier.
- Proper nouns (brand/model names) are often missing from standard wordlists; domain knowledge fills the gap.

## References

- xdis — Python cross-version bytecode library: https://github.com/rocky/python-xdis
- t9text — T9 touchtone encoding library: https://pypi.org/project/t9text/
- ITU E.161 — Standard telephone keypad letter assignments
- words_alpha.txt — English wordlist: https://github.com/dwyl/english-words
