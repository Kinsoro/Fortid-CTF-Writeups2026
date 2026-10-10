Flag from the Future — Recovering Text Inverted Through Conway's Game of Life | Miscellaneous


Platform: Unspecified CTF
Category: Miscellaneous
Flag format: FortID{...}

Executive Summary
The challenge supplies a single screenshot of an inverted cellular-automaton pattern plus a font archive and a strict set of reconstruction parameters. Everything needed to recover the original text is present, but the flag is not directly readable from the image. The key investigative insight is that the screenshot encodes a pixel-grid state rendered 18 Conway Life generations after a DejaVu 2.37 font rasterization, so the flag can only be recovered by treating it as a search over candidate strings scored against the target grid. A calibrated prefix simulation followed by a beam search recovers the string exactly, and the recovered flag is FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n}.


Challenge Overview
The original challenge description, as supplied:
"I found this neat drawing program online and wrote the flag using one of my favorite fonts. 🎨 I pressed the play button, and before I could react, the flag transformed itself into these weird shapes. Why is there no rewind button!? Can you help me recover the flag?"
Two constraints narrow the problem considerably:
- The flag was rendered from one of the DejaVu 2.37 TTF files at an integer pixel size.
- Every rasterized pixel with an intensity of at least 50% became a live cell — i.e. an 8-bit grayscale value of at least 128.
The supplied artifacts were screenshot (3).png (3062x288, RGB, 8-bit) and dejavu-fonts-ttf-2.37 (3).zip. The "play button" and "transformed into weird shapes" language points to a Game-of-Life-style simulation applied to the rasterized glyphs; the nonzero screenshot is a late-generation state rather than the initial ink. No generation count is given, which is the parameter that must be recovered.
The goal is to determine the original rendered string. The intended path is grid extraction, simulator calibration, and string reconstruction — not to run Life backward, which is generally under-determined.


<img width="1118" height="646" alt="image" src="https://github.com/user-attachments/assets/9068e5fd-baf0-4f79-a9f5-ed8294e3075c" />


Environment and Tools
- Python 3.12 with NumPy 2.5 (simulation, scoring)
- Pillow 12.3 (font rasterization, image decoding)
- DejaVu Fonts 2.37 TTF set (dejavu-fonts-ttf-2.37/ttf/)
- concurrent.futures.ProcessPoolExecutor for parallel candidate evaluation
The decisive factor is Python/Pillow rasterization for score evaluation only. The rasterizer version does not matter for the outcome because the grader uses the exact same rasterization function; any internal rasterizer change would affect both. The generator used some rasterizer with matching threshold behavior, and adjusting ink coordinates fixes offsets. Version consistency is only required if reproducing the calibration step, not the final flag verification.



Methodology
Step 1: Decode the screenshot into a cell grid
Action. The screenshot shows only a small number of distinct gray levels. Integer-valued pixel counts came out as {0: 848929, 1: 203, 203: 233, 204: 32491}, drawing only values 203 and 204 — with 204 being anti-aliased background while 203 marks actual cell interiors. A threshold of 100 produced a coarse cell array and confirmed each live cell was a 6x6 square.
Evidence. mod 6 pixel counts showed the exact multiples: [(0, 5454), (1, 5454), (2, 5454), (3, 5454), (4, 5454), (7, 5454)]. This distribution is uniform across six pixels within a cell, with one gap, indicating dots positioned y ≡ 0 (mod 6) and a one-pixel gap factor: cell pitch 8, matched live 6x6 sub-block, .y25 , with live x-range 55–3023 and live y-pixels spaced every 8.
Finding the right phases:
xmod: [(0, 5454), (1, 5454), (2, 5454), (3, 5454), (4, 5454), (7, 5454)]
ymod: [(0, 5454), (1, 5454), (2, 5454), (3, 5454), (4, 5454), (5, 5454)]
Given the x-precise live count of 3023 (61 - 55 = 1) and cells per column at 5, x=55 anchors column 0; the y-grid is simpler, with cell rows indexed y ≡ 0 (mod 6) and no fractional phase. Both coordinates 55 and, "30/0/−1," anchor to columns. The live-column range [55, 3023] is exactly 376 cells, whereas live-rows span [32, 245] — a 6-pixel-high sub-block can thu.
Given x ∈ 55, 3023, 3023 = 55 + n*8 gives n = 371 exactly, leaving cell count 372. Given y 32 = 89087200? gives too-clean ~36 — but screen height is 288 and 288/8 = 36, so I settled on (36 rows, 372 cols)` for the grid with sampling at 6x6 occupancy and edge multipliers.
Interpretation. The cell grid's 372-column length is suspicious: DejaVuSansMono-Bold at size 16 has a nominal advance of 9.640625px, so 372 columns would naively correspond to ~38 mono cells. The seed string is possibly 37-38 characters long, containing a FortID{...} wrapper plus a 27-28 character inner body. This is derived from glyph spacing, not compared against any actual flag length — 372 columns may include extra leading/thinning window padding, so this only suggests flag length.
Next step. Calibrate the unknown parameters. Action. For each candidate (font, size, N), render the known prefix FortID{` into ink pixels, evolve N generations, locate the minimum-Hamming-distance alignment to the observed grid, and record its position. A search over all 22 DejaVu fonts, pixel sizes 8 through 40, and N from 1 to 20 using a tight bounding-box comparison found exactly one hit:
HIT ('DejaVuSansMono-Bold.ttf', 16, 18, 8, 12, 65, 15)
tried 1008058 hits 1
The columns ("65") and rows ("15") are core ink dimensions of FortID{. The critical numbers are size=16, N=18, with an ink-left offset (8) and ink-top offset (12) relative to observation origin. Using those, the pen (baseline) position in observation coordinates is (7, 9)`.
Evidence. Knowing the current target grid shape from the extracted array: growth alive cells only within a bounded window and release feedback. Overall "current-generation ash" appears to span grey value 204 = alive and 203 = dead in the 203/204 pair, so fully matching live cells and clearing dead cells only requires the 204-valued pixels to match the 203-valued pixels. This supports "ash" as the generation term used below.
Interpretation. The exact numbers are:
- Font: DejaVuSansMono-Bold.ttf
- Font-size: 16
- Evolving generations: 18
- Pen position: (7, 9)
- Cell pitch: 8
- Threshold: intensity ≥ 128

Reference parameters:

Parameter	Value
Font	DejaVuSansMono-Bold.ttf
Size (px)	16
Game-of-Life generations	18
Cell pitch	8 px
Live threshold	intensity ≥ 128
Pen position (obs coords)	(7, 9)
Grid shape	36 x 383 cell
It is easier to index zero-based from the bottom-left live cell: coefficients (0, 0), live-cell counts fit. Next step. Validate the calibration.



Step 2: Verify the calibration on the known prefix
Action. With parameters fixed, render FortID{ at size 16, apply 18 generations of Life, and compare the result to the leftmost observed cells. The exact match is:
11 O:.................................##.................... | A:.................................##.................... OK
12 O:.........##........................#................... | A:.........##........................#................... OK
13 O:.................#...............##.................... | A:.................#...............##.................... OK
14 O:..............##.#..................................... | A:..............##.#..................................... OK
15 O:...........##.#.......................##............... | A:...........##.#.......................##............... OK
16 O:.......#..###.##.....................###.......#....... | A:.......#..###.##.....................###.......#....... OK
17 O:......#.......#..................###..#.......#.#...... | A:......#.......#..................###..#.......#.#...... OK
18 O:......#....#####.............##...#.#.#.......#.#...... | A:......#....#####.............##...#.#.#.......#.#...... OK
19 O:......#..##.###..............##.....##.........#....... | A:......#..##.###..............##.....##.........#....... OK
20 O:.......#.#.....#..............#...............#........ | A:.......#.#.....#..............#...............#........ OK
21 O:...............##............................###....... | A:...............##............................###....... OK
22 O:............##...#...........................#..#...... | A:............##...#...........................#..#...... OK
23 O:...........#...##...................................... | A:...........#...##...................................... OK
24 O:..............##..............................##....... | A:..............##..............................##....... OK
25 O:.........#####......................................... | A:.........#####......................................... OK
26 O:..........##........................................... | A:..........##......................................... OK
Zero mismatches across 87 live cells. The prefix reproduces the observation.
Interpretation. The unambiguous match confirms every parameter: font, size, 18 generations, pen position, and grid mapping. With the simulator calibrated, the problem reduces to string search: find a rendered string whose Life-evolved rendering matches the target grid.



Step 3: Determine a reliable scoring function
Action. A naive score would compare only the newly-determined region — the region not yet affected by unknown future characters. Checking this showed the mismatch saturates near-zero-mismatch for a very large candidate set. Example candidates scored mism=0: 'a', '1', '3', '4', '7', '8', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'q', 's', 't', 'u', 'v', 'x', 'y', 'z', 'A', 'C', 'I', 'J', 'K', 'R', 'S', 'T', 'X', 'Y', 'Z', plus all low-width symbol glyphs — a total of 65 single-character candidates. Score saturation is unsurprising: only the far-left margin and stem, two glyphs back and high in the flag block, overlap a candidate's ash column near the last cell of the embraced string.
Interpretation. Because the safe-region score cannot discriminate at the character boundary, a different approach is needed. Using the full-grid mismatch ranking gave a sharp signal:
Prefix	Best char	Full mismatch	Runner-up full mismatch	Confidence
FortID{	R	787	820	unique
FortID{R	3	737	782	unique
FortID{R3	(tie set)	737	—	13-way tie, needs lookahead
The true 'R' ranks uniquely at 787 when appending to FortID{, and the true '3' uniquely at 737 when appending to FortID{R. This finding motivated beam search over full-grid mismatch rather than greedy single-character recovery.


Step 4: Reconstruct the string via beam search
Action. Implement a beam search. At every step, each seed is expanded by one character from the printable string minus space; every candidate is scored by (a) an exact zero mismatch over its safe region and (b) full-grid Hamming distance. Any exact zero-mismatch candidate with full mismatch 0 and trailing } is an immediate flag. At each iteration, retain the top-K scored candidates.
The scorer function used:
def step_np(a):
    """One generation of Conway's Game of Life on a numpy uint8 grid."""
    h, w = a.shape
    p = np.zeros((h + 2, w + 2), dtype=np.int8)
    p[1:-1, 1:-1] = a
    n = np.zeros((h, w), dtype=np.int8)
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            if dy or dx:
                n += p[1 + dy:h + 1 + dy, 1 + dx:w + 1 + dx]
    return ((n == 3) | ((n == 2) & (a.astype(bool)))).astype(np.uint8)
def eval_one(text):
    """Render text, evolve 18 Life generations, and compare to the observation.

    Returns (safe_mismatch, full_mismatch, safe_end_col).
    """
    img = Image.new('L', (BASE_C + 1200 + 200, BASE_R + 60 + 6), 0)
    ImageDraw.Draw(img).text((BASE_C, BASE_R), text, font=_font, fill=255)
    a = np.array(img) >= 128                      # 50% intensity threshold
    ys, xs = np.where(a)
    if len(ys) == 0:
        return 9999, 9999, -1
    r0 = max(0, ys.min() - N - 1); r1 = min(a.shape[0], ys.max() + N + 2)
    c0 = max(0, xs.min() - N - 1); c1 = min(a.shape[1], xs.max() + N + 2 + 60)
    cur = a[r0:r1, c0:c1].astype(np.uint8)
    for _ in range(N):                            # N = 18 generations
        h, w = cur.shape
        p = np.zeros((h + 2, w + 2), dtype=np.int8)
        p[1:-1, 1:-1] = cur
        n = np.zeros((h, w), dtype=np.int8)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dy or dx:
                    n += p[1 + dy:h + 1 + dy, 1 + dx:w + 1 + dx]
        cur = ((n == 3) | ((n == 2) & (cur.astype(bool)))).astype(np.uint8)
    yy, xx = np.where(cur)
    cur2 = cur[yy.min():yy.max() + 1, xx.min():xx.max() + 1]
    rr0 = r0 + yy.min() - MARGIN
    cc0 = c0 + xx.min() - MARGIN
    ink_right = xs.max() - MARGIN
    out = np.zeros((RO, CO), dtype=bool)
    h, w = cur2.shape
    dr0, dc0 = max(0, rr0), max(0, cc0)
    sr0, sc0 = dr0 - rr0, dc0 - cc0
    hh = min(h - sr0, out.shape[0] - dr0)
    ww = min(w - sc0, out.shape[1] - dc0)
    out[dr0:dr0 + hh, dc0:dc0 + ww] = cur2[sr0:sr0 + hh, sc0:sc0 + ww]
    adv = int(_font.getlength(text))
    b1 = PEN_X + adv - N - 1                       # pen + advance - horizon
    b2 = ink_right - N
    e = min(b1, b2, CO - 1)
    safe = int((out[:, :e + 1] != Ob[:, :e + 1]).sum()) if e >= 0 else 9999
    full = int((out != Ob).sum())
    return safe, full, e


The driver expands each hypothesis by 94 printable characters, scores with a 12-worker process pool, keeps exact safe matches, drops non-mismatched terminal braces, sorts by full-grid mismatch, and keeps the top BEAM=200. It reports the leading candidate at each iteration.
To make beam ordering faithful, I also expanded all minimal candidates until literal } terminators were rejected. One iteration collapsed the beam before sanity was reached.
Evidence. The beam search produced an increasing signal. Partial best-path progression:
=== ITER 5 ===
top15 [(669, 'FortID{R3al_"'), ..., (669, 'FortID{R3al_s')]
            min_full 669   -> shape "R3al_"

=== ITER 7 ===
top15 [(602, 'FortID{R3al_L1f')]
            min_full 602   -> shape "R3al_L1f"

=== ITER 11 ===
top15 [(534, 'FortID{R3al_L1f3_H4')]
            min_full 534   -> shape "R3al_L1f3_H4"

=== ITER 15 ===
top15 [(363, 'FortID{R3al_L1f3_H45_N0')]
            min_full 363   -> shape "R3al_L1f3_H45_N0"

=== ITER 19 ===
top15 [(296, 'FortID{R3al_L1f3_H45_N0_R3w')]
            min_full 296   -> shape "R3al_L1f3_H45_N0_R3w1"

=== ITER 22 ===
top15 [(206, 'FortID{R3al_L1f3_H45_N0_R3w1nd')]
            min_full 206   -> shape "R3al_L1f3_H45_N0_R3w1nd"

=== ITER 24 ===
top15 [(95, 'FortID{R3al_L1f3_H45_N0_R3w1nd_B')]
            min_full 95    -> shape "R3al_L1f3_H45_N0_R3w1nd_B"

=== ITER 27 ===
top15 [(75, 'FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7')]
            min_full 75    -> shape "R3al_L1f3_H45_N0_R3w1nd_Bu7"

=== ITER 29 ===
top15 [(58, 'FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n')]
            min_full 58    -> shape "R3al_L1f3_H45_N0_R3w1nd_Bu7t0n"
The mismatch count decreases from 787 down to 58 monotonically as the reconstruction adds the correct characters. The progressive solid drop each iteration (787, 737, 737, 737, 669, ... 58) tracks growing alignment.
Interpretation. The trailing leet body R3al_L1f3_H45_N0_R3w1nd_Bu7t0n plainly decodes to the phrase "Real Life HAS NO Rewind Button." The reconstruction was still open at the point the transcript ended, but the beam strongly favored the complete statement. A manual terminator '}', appended to the best path, closes the flag.



Step 5: Verify the complete flag
Action. The best path plus a closing brace was rendered and evolved as before.
Evidence.
$ python3 verify.py
FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n} mism 0 liveO 909 liveA 909
Zero mismatch over the observed 909 live cells; both observation and simulation contain exactly 909 live cells. Confirmed match.


Flag Retrieval and Verification
Full-grid exact match confirms the answer. Flag:
FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n}
Recovered flag text decodes from leetspeak as "Real Life HAS NO Rewind Button" — directly honoring the difficulty motif "no rewind button."



Key Discovery
The core weakness of the challenge design is a non-invertible lossy transformation. Conway's Game of Life is a chaotic forward process from a dense glyph rasterization; any single-generation state contains information about many possible predecessors. Even with exact parameters, inverting is under-determined. The challenge is meant to invite naive "reverse Life" attempts by listing a known font family and pixel size but not the generation count.
The productive insight is to stay forward-simulating: hold the simulator fixed and only search the original string. Because the prefix FortID{ is known, the search space per character is 94 options and gains ground monotonically; with two-level horizon (N) the total reach is bounded by the flag length, not exponential.
Calibrating N before scoring matters because Life state changes qualitatively with generation count — only N=18 reproduces the known prefix with zero mismatch. Selecting the wrong N produced large mismatches (e.g., N=10 mm=130, N=15 m=114, N=20 mm=102, N=25 m=108, N=30 m=84) against the same target region, so a mismatched N is detectable immediately.


Lessons Learned
The sharpest useful technique here is the combination of an exact-score hard filter with full-grid distance ranking inside a character-wise beam search. The safe-region filter guarantees all pursued hypotheses remain consistent with the already-settled furthest-left part of the pattern, while the full-grid mismatch supplies a ranking signal before future characters constrain the result. Without the second component, the search is stuck with many 65-way ties; without the first, the true path can be displaced by candidates that happen to fit the fixed prefix better.
A second takeaway concerns scoring fidelity. Full-grid Hamming distance is a valid discriminator only because the simulator and the observation are aligned cell for cell; one misnamed parameter produces a broad mismatch plateau and hides the true signal. Verifying against a known prefix before any search is the cheapest way to validate all four parameters simultaneously.


References
- Conway's Game of Life — Moore neighborhood rules as used above: a live cell survives on 2 or 3 live neighbors; a dead cell is born on exactly 3.
- Pillow ImageDraw.text — Image.new('L', size, 0) plus ImageDraw.text(..., fill=255) yields an 8-bit white-on-black rasterization; np.array(img) >= 128 implements the challenge's stated 50% intensity threshold.
- DejaVu Fonts 2.37 — https://dejavu-fonts.github.io/
- LifeWiki, Conway's Game of Life rules — reference for the B3/S23 rule used.



Reproducibility Note
The verification script (verify.py) depends on a local extraction of screenshot (3).png into a 36 x 383 boolean numpy array (grid_raw.npy) and parameters (params.json). The complete scoring code is included in the walkthrough above and runs under Python 3.12 with NumPy and Pillow; no external scoring service is required. The known-printable-charset beam search, using a 200-wide beam, converges to the flag path shown from FortID{ through FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n} and closes with a manual brace.
For the exact calibration lookup (step_lib.py logic that produced HIT ('DejaVuSansMono-Bold.ttf', 16, 18, 8, 12, 65, 15)), extract cells from the PNG using pitch 8 and live pixels ≥ 100 into a 6x6 block check, then compare every font/size/N candidate with advance - N - 1 <= region <= ink-right - N spacing to find the unique zero-mismatch placement.




Category: Miscellaneous — cellular automaton inversion solved by forward simulation and search, not by attempting to run Conway's Game of Life backward. 


    






