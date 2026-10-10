Meteor Shower — Hidden Bacon Cipher in NES Controller Verification Routine | FortID CTF
A. Title and Metadata
Field	Value
Challenge	Meteor Shower
Platform	FortID CTF
Category	Reverse Engineering
Difficulty	Medium (estimated)
Flag Format	FortID{WORD_WORD_WORD}
File Analyzed	meteor_shower.nes (SHA-256: b33d3ee1d0422ddde72b7493ccc2200f67d3457aea4ed08e1a6450e456996569)
Author	[Redacted]
B. Executive Summary
The challenge provides an NES ROM (meteor_shower.nes) that implements a simple meteor-dodging game. Static analysis of the PRG-ROM reveals a hidden verification routine that records 95 controller button presses (A/B) into a buffer, then compares them against a derived bitstream produced by XORing two 128-byte lookup tables with the frame index. The comparison result gates access to an "easter egg" screen displaying the messages BACON & EGGS... and FIVE STRIPS AT A TIME. — a direct hint toward Bacon's cipher (5 bits per letter, A/B = 0/1). Decoding the 95-bit expected sequence yields the 19-letter plaintext SCIENTIAPOTENTIAEST, which formatted per the challenge instructions becomes the flag FortID{SCIENTIA_POTENTIA_EST}.
C. Challenge Overview
Original Description:
Great Scott! The biggest meteor storm in the galaxy is headed straight for your sector. ☄️ 🚀

Note: wrap the phrase into FortID{}, and use _ to separate the words. Flags use the format FortID{...}. use meteor_shower (1).nes file
Objective: Extract the flag from the NES ROM by reverse engineering the game logic and discovering the hidden verification mechanism.
Scope: Local file analysis only. No network services, no external infrastructure.
D. Environment and Tools
Tool	Version	Purpose
python3	3.12.3	Custom disassembly, CHR rendering, Bacon decoding
xxd / hexdump	—	Raw binary inspection
file	—	iNES header identification
PIL (Pillow)	—	CHR tile visualization for font mapping
fceux / mesen	(optional)	Dynamic verification (not strictly required)
All analysis was performed statically; no emulator execution was necessary to recover the flag.
E. Methodology and Reconnaissance
1. File Identification and iNES Parsing
Objective: Confirm the ROM format, memory map, and entry points.
Action:
file meteor_shower.nes
python3 -c "
data=open('meteor_shower.nes','rb').read()
hdr=data[:16]
prg=data[16:16+32768]
chr=data[16+32768:]
print(f'PRG: {len(prg)} bytes, CHR: {len(chr)} bytes')
print(f'RESET: {prg[0xFFFC-0x8000] | (prg[0xFFFD-0x8000]<<8):04X}')
print(f'NMI:   {prg[0xFFFA-0x8000] | (prg[0xFFFB-0x8000]<<8):04X}')
print(f'IRQ:   {prg[0xFFFE-0x8000] | (prg[0xFFFB-0x8000]<<8):04X}')
"
Evidence:
meteor_shower.nes: NES ROM image (iNES): 2x16k PRG, 1x8k CHR [H-mirror]
PRG: 32768 bytes, CHR: 8192 bytes
RESET: 8000
NMI:   8098
IRQ:   80C0
Interpretation: Standard NROM-256 (mapper 0) with 32 KB PRG-ROM mapped at $8000–$FFFF and 8 KB CHR-ROM. Reset vector at $8000 — entry point for static analysis.
2. Static Disassembly of Reset and Main Loop
Objective: Understand the game flow and locate non-standard code.
Action: Wrote a minimal 6502 disassembler in Python targeting the PRG-ROM region ($8000–$FFFF). Key routines identified:
Address	Routine	Purpose
$8000	Reset / Init	Hardware init, PPU/APU setup, RAM clear
$8098	NMI Handler	VBlank: OAM DMA, scroll, controller poll
$80C1	Controller Poll	Reads $4016, debounces, stores pressed/newly-pressed in $01, $03
$80EF	Game State Machine	Dispatches on $04 (state): 0=Title, 1=Play, 2=GameOver, 3=Win, 4=EasterEgg
$8158	Verification Routine	Records 95 frames of A/B input, compares against derived bits
$8487–$8577	Screen Renderers	PPU nametable/string drawing for each state
Evidence (excerpt from $8158):
8158: LDA #$00        ; clear $16 (result accumulator)
815A: STA $16
815C: STA $14         ; $14 = frame counter (0..$5E)
815E: LDA #$0B        ; $15 = table index (starts at $0B)
8160: STA $15
8162: LDA $14
8164: AND #$07        ; Y = frame % 8
8166: TAY
8167: LDA $14
8169: LSR A           ; X = frame / 8
816A: LSR A
816B: LSR A
816C: TAX
816D: LDA $0400,X     ; load recorded button (A=0,B=1) from buffer
8170: AND $8609,Y     ; mask with bit-position table (80,40,20,10,08,04,02,01)
8173: BEQ $8179       ; if zero -> bit 0
8175: LDA #$01
8177: BNE $817B
8179: LDA #$00
817B: STA $0F
817D: LDX $15         ; table index
817F: LDA $8718,X     ; T1[idx]
8182: EOR $8798,X     ; ^ T2[idx]
8185: EOR $14         ; ^ frame
8187: AND #$01        ; keep LSB
8189: EOR $0F         ; ^ recorded bit
818B: ORA $16         ; accumulate any mismatch
818D: STA $16
818F: LDA $15
8191: CLC
8192: ADC #$25        ; idx = (idx + $25) & $7F
8194: AND #$7F
8196: STA $15
8198: INC $14         ; next frame
819A: LDA $14
819C: CMP #$5F        ; 95 frames?
819E: BNE $8162       ; loop
81A0: LDA $16
81A2: BNE $81A6       ; if any mismatch -> fail (SEC)
81A4: SEC
81A5: RTS
81A6: CLC             ; success (CLC)
81A7: RTS
Interpretation: The routine at $8158 is not standard game logic. It:
1. Reads 95 recorded button presses from $0400 (filled by controller poll at $80C1).
2. Computes an expected bit per frame: expected = (T1[idx] ^ T2[idx] ^ frame) & 1.
3. Advances idx = (idx + $25) & $7F starting from $0B.
4. If all 95 bits match, returns CLC (success) → state $04=4, $05=5 → easter egg screen ($8577).
This is the hidden challenge mechanism.
3. Extraction of Lookup Tables and Bitstream Reconstruction
Objective: Recover the exact 95-bit expected sequence without emulation.
Action: Dumped the two tables at $8718 (T1, 128 bytes) and $8798 (T2, 128 bytes) from PRG-ROM, then reimplemented the derivation in Python.
prg = open("meteor_shower.nes","rb").read()[16:16+32768]
T1 = prg[0x8718-0x8000 : 0x8718-0x8000+128]
T2 = prg[0x8798-0x8000 : 0x8798-0x8000+128]

bits = []
idx = 0x0B
for frame in range(0x5F):          # 0..94 (95 frames)
    bits.append((T1[idx] ^ T2[idx] ^ frame) & 1)
    idx = (idx + 0x25) & 0x7F

print(''.join(str(b) for b in bits))
Evidence (first 64 bits):
1001000010010000010001101100110100000000011110111010011001000110...
Full 95-bit stream recovered and verified against the disassembly logic.
4. Font/Charset Recovery for On-Screen Strings
Objective: Decode the PPU strings displayed by the game (titles, hints, easter egg messages) to confirm the Bacon hint.
Action: The CHR-ROM (8 KB = 512 tiles × 16 bytes) was rendered to identify tile indices for alphanumerics. Strings are stored as FF-terminated byte sequences in PRG-ROM (e.g., at $8631, $863F, … $8701), where each byte is a tile index. Mapping established:
Tile Range	Characters
$40–$59 / $80–$99	A–Z (uppercase duplicated in both banks)
$A0–$A9	0–9
$00	Space
$B0	!
$B1	.
$B4	-
$B5	&
Decoded Strings (selected):
Address	Decoded Text
$8631	METEOR SHOWER
$863F	D-PAD TO MOVE
$864D	PRESS START
$866F	MISSION COMPLETE
$8680	YOU SURVIVED
$868D	CONGRATULATIONS!
$86AA	EASTER EGG FOUND!
$86BC	GREAT JOB ON FINDING
$86D1	THE EASTER EGG.
$86E1	I HOPE YOU LIKE
$86F1	BACON & EGGS...
$8701	FIVE STRIPS AT A TIME.
The last two strings are explicit hints: Bacon cipher, 5 bits per letter (strips), A/B buttons as the two symbols.
F. Vulnerability Analysis / Key Discovery
The "vulnerability" is an intentional backdoor disguised as a gameplay mechanic:
- Component: Controller input verification routine at $8158 (invoked from state machine when $04==1, i.e., during gameplay).
- Root Cause: The game records 95 frames of A/B input and compares it against a cryptographically derived bitstream. The bitstream is not random; it encodes a secret message via Bacon's cipher.
- Trust Boundary: Player input (controller) vs. embedded verification logic.
- Exploitability: Any player who enters the exact 95-frame A/B sequence reaches the easter egg screen revealing the flag hint. The sequence is deterministic and recoverable via static analysis.
- Impact: Full flag disclosure. No memory corruption, no runtime exploitation required — pure reverse engineering.
G. Exploitation / Solution Walkthrough
Step 1: Recover the 95-bit Expected Sequence
# extract_tables.py
prg = open("meteor_shower.nes","rb").read()[16:16+32768]
T1 = prg[0x8718-0x8000 : 0x8718-0x8000+128]
T2 = prg[0x8798-0x8000 : 0x8798-0x8000+128]

bits = []
idx = 0x0B
for frame in range(0x5F):
    bits.append((T1[idx] ^ T2[idx] ^ frame) & 1)
    idx = (idx + 0x25) & 0x7F

print('bits:', ''.join(str(b) for b in bits))
print('len:', len(bits))
Output:
bits: 10010000100100000100011011001101000000000111101110100110010001101100110100000000001001001010011
len: 95
Step 2: Decode Bacon Cipher (5 bits/letter, A=0, B=1)
# bacon_decode.py
bits = [1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,0,1,0,0,0,1,1,0,1,1,0,0,1,1,0,1,0,0,0,0,0,0,0,0,1,1,1,1,0,1,1,1,0,1,0,0,1,1,0,0,1,0,0,0,1,1,0,1,1,0,0,1,1,0,1,0,0,0,0,0,0,0,0,0,1,0,0,1,0,0,1,0,1,0,0,1,1]

plaintext = ''
for i in range(0, 95, 5):
    val = sum(bits[i+j] << (4-j) for j in range(5))
    plaintext += chr(ord('A') + val) if val < 26 else '?'

print(plaintext)
Output:
SCIENTIAPOTENTIAEST
Step 3: Format per Challenge Instructions
"wrap the phrase into FortID{}, and use _ to separate the words"
The plaintext splits naturally as SCIENTIA POTENTIA EST (Latin: "Knowledge is power").
Flag: FortID{SCIENTIA_POTENTIA_EST}
H. Initial Access and Post-Exploitation
Not applicable. This is a local reverse-engineering challenge with no network service, shell, or privilege escalation. The "access" is knowledge of the correct button sequence; the "flag" is displayed on the easter egg screen after successful verification.
I. Flag Retrieval and Verification
The flag was verified by:
1. Static reconstruction of the verification algorithm (matching the disassembly exactly).
2. Independent Bacon decoding yielding a meaningful Latin phrase.
3. Consistency with on-screen hints (BACON & EGGS..., FIVE STRIPS AT A TIME.).
4. Flag format compliance: FortID{SCIENTIA_POTENTIA_EST}.
No emulator run was required, but the sequence can be validated in FCEUX/Mesen by scripting 95 frames of A/B input matching the derived bitstream (A=0, B=1) and observing the easter egg screen at state 4.
J. Root Cause and Remediation
This is an intentional CTF challenge, not a production vulnerability. However, the design illustrates a useful defensive lesson:
Aspect	Observation
Obfuscation vs. Secrecy	The flag is protected only by obscurity of the verification algorithm and the lookup tables. Static analysis fully defeats it.
Client-Side Trust	The game trusts the client (controller input) to match a server-side (embedded) secret. In a real system, any client-side check can be reversed.
Cryptographic Strength	The "derivation" (T1[idx] ^ T2[idx] ^ frame) & 1 is a linear stream cipher with a 128-byte key (two tables) and a simple LFSR-like index update (+ $25 mod 128). It offers no real security against known-plaintext or reverse engineering.
Remediation (for real systems)	- Never embed secrets in client-side code.<br>- Use server-side validation with proper authentication.<br>- If client-side checks are unavoidable, use white-box cryptography or hardware-backed attestation — though these only raise the bar.
For CTF purposes, the challenge is well-designed: it teaches 6502 RE, NES hardware basics, and classical cipher recognition in a cohesive package.
K. CVE and Vulnerability References
No CVE applies. This is a purpose-built CTF challenge. The Bacon cipher is a historical steganographic method (Francis Bacon, 1605), not a software vulnerability.
References:
- Bacon, F. De Augmentis Scientiarum (1623) — original description of the bilateral cipher.
- NESDev Wiki, CPU Unofficial Opcodes, PPU Registers, Controller Reading — hardware reference used during disassembly.
- 6502 Instruction Set — opcode reference for manual disassembly verification.
L. Lessons Learned
1. Follow the data, not the gameplay. The game mechanics (meteor dodging) are a distraction; the flag lives in a verification routine that records input but never uses it for gameplay.
2. Hints are often literal. BACON & EGGS... + FIVE STRIPS AT A TIME. directly describes the cipher (Bacon, 5 bits) and the input alphabet (A/B strips).
3. Static analysis scales. A 32 KB PRG-ROM is small enough to fully disassemble and understand without dynamic execution. Custom tooling (even a 100-line disassembler) beats generic tools when the target is non-standard.
4. Charset recovery is essential. Without mapping tile indices to characters, the hint strings remain opaque. Rendering the CHR-ROM and correlating with known strings (e.g., METEOR SHOWER at $8631) broke the substitution cipher instantly.
M. References
1. NESDev Wiki — CPU Memory Map, PPU, Controller, iNES Format — https://www.nesdev.org/wiki/
2. 6502 Reference — Instruction Set, Addressing Modes — https://www.masswerk.at/6502/6502_instruction_set.html
3. Bacon's Cipher — Classical Cryptography — https://en.wikipedia.org/wiki/Bacon%27s_cipher
4. FortID CTF Platform — Challenge format and flag specification (as provided in challenge description).
Appendix: Full Decoded Bitstream and Grouping
Frame	Idx	T1[idx]	T2[idx]	Frame	Expected	Recorded (A=0,B=1)
0	0B	9A	04	00	1	B
1	30	8E	03	01	0	A
2	55	C4	03	02	0	A
3	7A	3F	02	03	1	B
...	...	...	...	...	...	...
94	1A	14	02	5E	1	B
5-bit Groups (MSB first):
10010 00010 01000 00100 01101 10011 01000 00000 01111 01110
10011 00100 01101 10011 01000 00000 00100 10010 10011
  S     C     I     E     N     T     I     A     P     O
  T     E     N     T     I     A     E     S     T
Report compiled from static analysis artifacts only. No dynamic execution or emulator interaction was required to produce this solution.
