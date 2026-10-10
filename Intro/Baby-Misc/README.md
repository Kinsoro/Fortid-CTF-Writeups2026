Baby Misc — Trie-Based Steganography in PNG Archive | CTF

Executive Summary
The challenge provided a 344 MB ZIP archive containing 7,000 PNG files organized in a deep directory trie. Each directory level encoded one ASCII character as its decimal value. Decoding 33 leaf paths produced FortID{...} strings, but all were decoys. Pixel-level comparison revealed 6,999 images were visually identical (a "haystack" image reading "REAL FLAG SOMEWHERE IN HERE"), while exactly one image—the file whose path decoded to FortID{D0_or_D0_N07_Th3r3_15_n0_Tri3}—was visually distinct (a "hacker" image). The flag was the decoded path itself: FortID{D0_or_D0_N07_Th3r3_15_n0_Tri3}.

Challenge Overview
Attribute	Value
Name	Baby Misc
Platform	Unknown (Google Drive hosted)
Category	Misc / Forensics / Steganography
Flag Format	FortID{...}
Description	"Heard you're a M4st3r H4ck3r, can you retrieve the flag from this archive?"
Archive URL	https://drive.google.com/file/d/1wO1AjeWmnOqxzDoucXueFLPdpLEi_ZHb/view
The challenge name "Baby Misc" and the eow.png filename (End-Of-Word) suggested a trie-based structure where each directory level represents one character.

<img width="1100" height="252" alt="image" src="https://github.com/user-attachments/assets/55d6508c-1375-4484-a934-41bfab3b7d7d" />



Environment and Tools
Tool	Purpose
curl	Download archive from Google Drive (handles virus-scan redirect)
python3 + zipfile	Enumerate, extract, and analyze archive contents
Pillow (PIL)	Compute perceptual hashes of PNG pixel data
struct	Parse PNG chunk structure (IHDR, PLTE, IDAT, tEXt, IEND)
hashlib	SHA-256 for file and pixel-data deduplication
All analysis performed locally on Linux; no network interaction beyond the initial download.


Methodology and Reconnaissance
1. Download and Initial Triage
Objective: Obtain the archive and determine its structure.
Action:
curl -L "https://drive.usercontent.google.com/download?id=1wO1AjeWmnOqxzDoucXueFLPdpLEi_ZHb&export=download&confirm=t" \
  -o baby_misc_archive --max-time 60 -k -s
Evidence:
baby_misc_archive: Zip archive data, at least v2.0 to extract, compression method=store
344824242 bytes (344 MB)
Interpretation: Large store-compressed ZIP (no compression). Size suggests many similar files.




2. Archive Enumeration
Objective: Understand the internal layout without full extraction.
Action:
import zipfile
z = zipfile.ZipFile('baby_misc_archive')
infos = z.infolist()
len(infos)  # 7000
Evidence: 7,000 entries, all named retrieve/<numbers>/eow.png. Every file 48,857 bytes exactly.
Interpretation: Uniform size implies padding or identical payloads with minor metadata differences. The retrieve/ prefix and numeric path components suggest ASCII decimal encoding.


3. Path Decoding
Objective: Recover the string represented by each path.
Action:
def decode(path):
    inner = path[len('retrieve/'):-len('/eow.png')]
    return ''.join(chr(int(p)) for p in inner.split('/'))

decoded = [decode(i.filename) for i in infos]
Evidence:
- All paths decode to printable strings (depths 24–70 levels).
- 1,833 paths begin with FortID{.
- 33 match ^FortID\{[^}]+\}$ exactly.
Interpretation: The trie encodes many candidate flags. The 33 well-formed FortID{...} strings are likely decoys (confirmed by challenge hint: the_flag_is_a_lie_but_the_png_is_not).




4. Pixel-Level Deduplication
Objective: Determine whether image content differs across files.
Action: Compute SHA-256 of RGB pixel data for all 7,000 images.
from PIL import Image
import hashlib, io

def pixel_hash(data):
    im = Image.open(io.BytesIO(data))
    return hashlib.sha256(im.convert('RGB').tobytes()).hexdigest()

hashes = [pixel_hash(z.read(i.filename)) for i in infos]
Counter(hashes)
Evidence:
'a91322ce33f1c366...': 6999   # haystack
'19fe4610d8b43bb7...': 1      # unique
Interpretation: 6,999 images are pixel-for-pixel identical. Exactly one image is visually different. The unique image is the only one that matters.


5. Locate the Unique Image
Objective: Identify which path corresponds to the unique pixel hash.
Action:
for info in infos:
    if pixel_hash(z.read(info.filename)) == '19fe4610d8b43bb7...':
        print(decode(info.filename))
Evidence:
FortID{D0_or_D0_N07_Th3r3_15_n0_Tri3}
Interpretation: The unique "hacker" image lives at the path that decodes to this flag. The flag is the path.




6. PNG Structure Analysis (Verification)
Objective: Confirm why file sizes are identical despite different pixel content.
Action: Parse PNG chunks for both haystack and unique files.
def chunks(data):
    off = 8  # skip magic
    while off < len(data):
        ln = struct.unpack('>I', data[off:off+4])[0]
        typ = data[off+4:off+8]
        yield typ, ln, data[off+8:off+8+ln]
        off += 8 + ln + 4
Evidence:
Chunk	Haystack (×6999)	Unique (×1)
IHDR	13 B	13 B
PLTE	192 B	192 B
IDAT	48,340 B	37,405 B
tEXt (Comment)	244 B	11,179 B
IEND	0 B	0 B
Total	48,857 B	48,857 B
Interpretation: The author padded the unique file by shrinking IDAT (actual image data) and expanding the tEXt comment chunk with 11 KB of hex-encoded filler (likely encrypted/random data) to maintain constant file size and defeat simple hash-based deduplication.
The tEXt payload in the unique file is 11,171 hex characters (odd length → last nibble truncated), decoding to 5,585 bytes of high-entropy binary data—irrelevant to the flag.



Key Discovery
The trie is the flag carrier, not the image pixels.  
The challenge title "Baby Misc", the eow.png naming (standard trie end-of-word marker), and the decoy flag the_flag_is_a_lie_but_the_png_is_not all indicate that the directory structure itself encodes the solution. The single visually distinct image serves only as a beacon to identify the correct leaf node.



Solution Walkthrough
1. Download archive → baby_misc_archive (344 MB ZIP, store compression).
2. Enumerate entries → 7,000 files at retrieve/<decimals>/eow.png, all 48,857 bytes.
3. Decode paths → split numeric components, chr(int) each, join.
4. Identify candidate flags → 33 paths decode to FortID{...} format.
5. Hash pixel data → 6,999 images share one perceptual hash; 1 image differs.
6. Match unique hash to path → FortID{D0_or_D0_N07_Th3r3_15_n0_Tri3}.
7. Verify flag format → Matches FortID{...} exactly.
No exploitation, no privilege escalation, no post-exploitation required. Pure forensic analysis of archive structure and image content.


Flag Retrieval and Verification
FortID{D0_or_D0_N07_Th3r3_15_n0_Tri3}
Confirmed by:
- Path decoding of the sole visually unique PNG.
- Conformance to declared flag format FortID{...}.
- Consistency with challenge narrative ("M4st3r H4ck3r", "D0_or_D0_N07" leet-speak for "Do or Do Not There Is No Try").


Root Cause and Remediation
This is an intentionally designed CTF artifact, not a software vulnerability. However, the technique demonstrates steganography via filesystem metadata (directory names) combined with visual collision resistance (identical file sizes, perceptual hashing defeat).
In a real-world context, similar methods could hide data in:
- Cloud storage directory structures
- Version control histories
- Container image layers
- Backup archives
Detection/mitigation:
- Monitor for unusually deep, uniform directory trees with numeric names.
- Compare perceptual hashes of image assets at scale.
- Treat filesystem paths as potential data channels in data-loss-prevention policies.



Lessons Learned
- Enumerate structure before content. The flag lived in the naming scheme, not the file payloads.
- Perceptual hashing > file hashing. Identical file sizes and differing metadata chunks (tEXt) defeated SHA-256 deduplication; pixel hashing succeeded.
- Decoys are signal. The 33 well-formed FortID{...} paths and the hint the_flag_is_a_lie_but_the_png_is_not correctly directed attention to the image content.
- Constant-size padding is a tell. The IDAT/tEXt tradeoff preserving total file size is a classic anti-deduplication technique—its presence confirms intentional construction.


References
- PNG Specification (ISO/IEC 15948:2004) — chunk structure, tEXt chunk semantics
- Trie (prefix tree) data structure — end-of-word markers
- Perceptual hashing / difference hashing for image deduplication
- Steganography in filesystem metadata (prior art: NCTU CTF "Hidden in Plain Sight", 2019)






 









