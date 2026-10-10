Flag from the Future — Recovering Text Evolved Through Conway's Game of Life | Miscellaneous

Platform: Unspecified CTF  
Category: Miscellaneous  
Flag format: FortID{...}

Executive Summary
The challenge provides a single PNG screenshot showing a cellular-automaton pattern and a DejaVu 2.37 font archive. The flag was rendered in DejaVuSansMono-Bold.ttf at 16 px, thresholded at 50% intensity, then evolved 18 generations of Conway's Game of Life. The only viable path is forward: calibrate the simulator against the known prefix FortID{, then search the string space with a beam search scored by full-grid Hamming distance. The recovered flag is FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n} (leetspeak for "Real Life HAS NO Rewind Button"). Exact match on all 909 live cells confirms the result.

Challenge Overview
Original description:

"I found this neat drawing program online and wrote the flag using one of my favorite fonts. 🎨 I pressed the play button, and before I could react, the flag transformed itself into these weird shapes. Why is there no rewind button!? Can you help me recover the flag?"
Two concrete constraints narrow the problem:
- The flag was rendered from one of the DejaVu 2.37 TTF files at an integer pixel size.
- Every rasterized pixel with intensity ≥ 50% (i.e., ≥ 128 in 8-bit grayscale) became a live cell.
Supplied artifacts: screenshot (3).png (3062 × 288, RGB, 8-bit) and dejavu-fonts-ttf-2.37 (3).zip. The "play button" / "weird shapes" language indicates a Game-of-Life simulation applied to the ink; the screenshot is a late-generation state, not the initial rasterization.

<img width="1118" height="646" alt="Capture d&#39;écran 2026-10-10 123155" src="https://github.com/user-attachments/assets/6ca283d5-89a8-4f3e-9cfc-5b7eb1e92c75" />


Environment and Tools
Tool	Version	Purpose
Python	3.12	Core logic, search orchestration
NumPy	2.5.3	Grid operations, Life simulation
Pillow	12.3.0	Font rasterization, PNG decoding
DejaVu Fonts 2.37	—	TTF source (DejaVuSansMono-Bold.ttf)
concurrent.futures	stdlib	12-worker parallel candidate evaluation
No external services, binary analysis, or network interaction required.


Methodology and Reconnaissance
Step 1 — Decode the screenshot into a cell grid
Objective. Convert the RGB screenshot into a boolean cell array matching the challenge's "every rasterized pixel ≥ 50% → live cell" rule.
Action.  
from PIL import Image
import numpy as np

im = np.array(Image.open('screenshot (3).png').convert('L'))
live = im > 100                 # threshold well above noise floor
Evidence.  
Gray-level histogram: {0: 848929, 1: 203, 203: 233, 204: 32491} — only values 203 and 204 appear in the pattern region. Live cells form 6 × 6 blocks on an 8-pixel pitch.
x-phase counts: [(0, 5454), (1, 5454), (2, 5454), (3, 5454), (4, 5454), (7, 5454)]
y-phase counts: [(0, 5454), (1, 5454), (2, 5454), (3, 5454), (4, 5454), (5, 5454)]
Leftmost live pixel at (55, 32); rightmost at (3020, 120). Sampling the 6×6 block at each 8-pixel grid cell yields a 36-row × 383-col boolean array (grid_raw.npy, 909 live cells).
Interpretation. The grid dimensions match a mono-spaced string of ~38 characters at 16 px with 18 generations of horizontal spread (each generation extends ~1 cell left/right). The cell grid is the ground truth for all later scoring.
Next step. Calibrate the unknown simulator parameters: font, size, generations N, and pen position.


Step 2 — Calibrate the simulator against the known prefix
Objective. Find the unique (font, size, N, pen) tuple that reproduces the leftmost observed cells when the known prefix FortID{ is rendered and evolved.
Action. Exhaustive search over all 22 DejaVu TTFs, sizes 8–40, N = 1..20. For each candidate: render FortID{ at the candidate size, threshold at 128, evolve N generations on a padded canvas, then slide the resulting ash pattern over the observation window to find the minimum-Hamming alignment.
Evidence. Exactly one hit survives:
HIT ('DejaVuSansMono-Bold.ttf', 16, 18, 8, 12, 65, 15)
tried 1008058 hits 1
Decoded parameters:
Parameter	Value
Font	DejaVuSansMono-Bold.ttf
Size	16 px
Generations N	18
Ink-left offset (obs coords)	8
Ink-top offset (obs coords)	12
Ink width / height	65 / 15 cells
Pen position (baseline) in observation coordinates: (7, 9).
Interpretation. The single hit across >1 million candidates is strong evidence that all four parameters are correct. Any deviation would shift the ash pattern and produce mismatches.
Next step. Verify the calibration on the known prefix.


Step 3 — Validate the calibration on FortID{
Action. Render FortID{ at 16 px with the calibrated parameters, evolve 18 generations, and compare the leftmost uncontested region (columns 0–54) to the observation.
Evidence. Zero mismatches across 87 live cells:
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
26 O:..........##........................................... | A:..........##........................................... OK
Interpretation. The simulator is fully calibrated. The problem reduces to: find a string whose 18-generation ash matches the entire 36 × 383 observation.



Step 4 — Scoring function design
Objective. Define a scoring function that discriminates correct characters despite the chaotic nature of Life.
Action. Two-level scoring:
1. Safe-region mismatch — columns that cannot yet be influenced by unknown future characters (pen advance − N − 1). Must be exactly 0.
2. Full-grid Hamming distance — total live-cell disagreements over the entire 36 × 383 grid. Used for ranking.
Safe-region alone is insufficient: 65 single-character extensions of FortID{ all score 0. Full-grid distance provides signal:
Prefix	Best char	Full mismatch	Runner-up	Confidence
FortID{	R	787	820	unique
FortID{R	3	737	782	unique
FortID{R3	13-way tie	737	—	needs lookahead
Interpretation. The true character consistently achieves the lowest full-grid mismatch. A beam search retaining top-K by full-grid distance will converge.


Step 5 — Beam search reconstruction
Action. Iterative left-to-right beam search:
- Expand each hypothesis by 94 printable characters (no space).
- Evaluate all candidates in parallel (12 workers).
- Keep only exact safe-region matches (mismatch = 0).
- Rank by full-grid Hamming distance; retain top BEAM = 200.
- Drop non-full-match terminal } candidates.
- Stop when a candidate with full mismatch 0 ends in }.
Core simulation (inline for speed):
def step_np(a):
    h, w = a.shape
    p = np.zeros((h + 2, w + 2), dtype=np.int8)
    p[1:-1, 1:-1] = a
    n = np.zeros((h, w), dtype=np.int8)
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            if dy or dx:
                n += p[1 + dy:h + 1 + dy, 1 + dx:w + 1 + dx]
    return ((n == 3) | ((n == 2) & (a.astype(bool)))).astype(np.uint8)
Evidence. Progressive convergence (iterations 5–29 shown; full log in appendix):
=== ITER  5 === min_full 669  ->  'FortID{R3al_"' ... 'FortID{R3al_s'
=== ITER  7 === min_full 602  ->  'FortID{R3al_L1f'
=== ITER 11 === min_full 534  ->  'FortID{R3al_L1f3_H4'
=== ITER 15 === min_full 363  ->  'FortID{R3al_L1f3_H45_N0'
=== ITER 19 === min_full 296  ->  'FortID{R3al_L1f3_H45_N0_R3w'
=== ITER 22 === min_full 206  ->  'FortID{R3al_L1f3_H45_N0_R3w1nd'
=== ITER 24 === min_full  95  ->  'FortID{R3al_L1f3_H45_N0_R3w1nd_B'
=== ITER 27 === min_full  75  ->  'FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7'
=== ITER 29 === min_full  58  ->  'FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n'
Each iteration adds 1–3 correct characters; full mismatch drops monotonically from 787 → 58.
Interpretation. The best path spells the leetspeak phrase R3al_L1f3_H45_N0_R3w1nd_Bu7t0n ("Real Life HAS NO Rewind Button"). The beam never diverges once the prefix is established.




Flag Retrieval and Verification
Action. Append closing brace to the best path and verify full-grid equality.
Evidence.
$ python3 -c "
import json, numpy as np
from PIL import Image, ImageDraw, ImageFont

O = np.load('grid_raw.npy'); Ob = O > 0
cfg = json.load(open('params.json'))
font = ImageFont.truetype(cfg['fontpath'], cfg['size'])
MARGIN = 100
H, W = O.shape[0] + 2*MARGIN, O.shape[1] + 2*MARGIN
img = Image.new('L', (W, H), 0)
ImageDraw.Draw(img).text((cfg['pen_x']+MARGIN, cfg['pen_y']+MARGIN),
                         'FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n}', font=font, fill=255)
a = (np.array(img) >= 128).astype(np.uint8)
ys, xs = np.where(a)
r0, r1 = max(0, ys.min()-19), min(H, ys.max()+20)
c0, c1 = max(0, xs.min()-19), min(W, xs.max()+20)
cur = a[r0:r1, c0:c1]
for _ in range(18):
    cur = step_np(cur)
yy, xx = np.where(cur)
cur2 = cur[yy.min():yy.max()+1, xx.min():xx.max()+1]
rr0, cc0 = r0+yy.min()-MARGIN, c0+xx.min()-MARGIN
out = np.zeros(O.shape, dtype=bool)
h, w = cur2.shape
dr0, dc0 = max(0, rr0), max(0, cc0)
sr0, sc0 = dr0-rr0, dc0-cc0
hh = min(h-sr0, O.shape[0]-dr0); ww = min(w-sc0, O.shape[1]-dc0)
out[dr0:dr0+hh, dc0:dc0+ww] = cur2[sr0:sr0+hh, sc0:sc0+ww]
print('mismatch:', int((out != Ob).sum()), 'liveO:', int(Ob.sum()), 'liveA:', int(out.sum()))
"
Output:
mismatch: 0 liveO: 909 liveA: 909
Flag:
FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n}


Key Discovery
The challenge's core weakness is a non-invertible lossy transformation. Conway's Game of Life is chaotic forward; reversing it is under-determined even with exact parameters. The "no rewind button" hint is literal: the author expects contestants to attempt backward evolution, which fails.
The productive insight: stay forward. With the simulator fully calibrated, the only unknown is the input string. The search space per character is 94 options; with a two-level horizon (N = 18 limits how far future characters reach) the total search is bounded by flag length, not exponential.
Calibrating N before search is critical: wrong N produces broad mismatch plateaus that hide the true signal (N=10: 130, N=15: 114, N=20: 102, N=25: 108, N=30: 84 mismatches vs. N=18: 0).


Lessons Learned
1. Dual-level scoring — A hard filter (safe-region = 0) plus a soft ranking (full-grid Hamming) is essential when local constraints are insufficient. The safe filter guarantees consistency with settled cells; the full-grid distance provides gradient before future characters constrain the result.
2. Validate before search — Verifying the known prefix against the calibrated simulator catches parameter errors immediately. A single mismatched parameter (font, size, N, pen) produces large, obvious mismatches.
3. Beam width matters — A beam of 200 was sufficient; narrower beams risk dropping the true path during tie phases (e.g., the 13-way tie at FortID{R3).
4. Leet is predictable — The challenge uses systematic leetspeak (a→4, e→3, i→1, o→0, s→5, t→7). Once the pattern is recognized, the remaining characters are highly constrained.




References
- Conway's Game of Life — B3/S23 rule, Moore neighborhood.
- Pillow ImageDraw.text — 8-bit rasterization; np.array(img) >= 128 implements the 50% threshold.
- DejaVu Fonts 2.37 — https://dejavu-fonts.github.io/
- LifeWiki — Conway's Game of Life rules reference.



Reproducibility Note
The verification script requires:
- grid_raw.npy (36 × 383 boolean array extracted from the PNG at 8-pixel pitch, 6×6 block threshold)
- params.json with the calibrated parameters
- Python 3.12 + NumPy + Pillow
The complete beam search code is included in the methodology section. No external services or proprietary tools are needed.


Category: Miscellaneous — cellular-automaton inversion solved by forward simulation and guided search, not by attempting to reverse Conway's Game of Life.




Files used in the challenge

<img width="3062" height="288" alt="screenshot" src="https://github.com/user-attachments/assets/de8a292f-f400-49af-900d-9ec36f1bec0d" />

[dejavu-fonts-ttf-2.37.zip](https://github.com/user-attachments/files/33282775/dejavu-fonts-ttf-2.37.zip)








