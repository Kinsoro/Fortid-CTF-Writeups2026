# Hic Sunt Dracones — Recovering Koblitz Points Through Persistent Dragon-Curve State | Crypto CTF

**Category:** Cryptography
**Difficulty:** Medium–Hard
**Flag format:** FortID{...}

## Executive Summary

The challenge encrypts a flag by first mapping each character to a point on a random 256-bit elliptic curve via a Koblitz-style encoder, then displacing those points along a Heighway dragon curve whose step size, iteration depth and initial angle form a private key. Because the turtle object that executes the curve is never reset between points, its heading accumulates a predictable +90° offset after every render. This turns the net displacement into a pure-axis vector of magnitude 128 for the observed parameters, allowing the original (small) Koblitz x-coordinates to be recovered by a simple linear Diophantine search. The recovered x-values decode directly to the flag.

## Challenge Overview

A Docker image is supplied that clones a specific commit of the open-source “Dragon-Crypto” library, applies a short patch that replaces the naïve modular square-root with the efficient $p\equiv3\pmod4$ method and makes the prime a parameter, then runs the encryption script against an unknown flag.txt. The only output given to the solver is a single line of the form
textCopyCopiedX…X…XY…Y…Y
that encodes the final turtle coordinates after each dragon-curve walk.

## Environment and Tools

Python 3.12 + pycryptodome
The patched Dragon-Crypto sources (commit 046ad8d)
A few dozen lines of pure-Python arithmetic to compute net displacements and recover the step size

No external solvers or heavy mathematical libraries were required.

## Methodology and Reconnaissance

1. Artifact inventory
BashCopyCopied$ unzip -l handout.zip
  chall.py
  patch.py
  output.txt
  Dockerfile
The Dockerfile clones the library, checks out the exact commit, and runs the supplied patch.py. The patch is essential: it changes the Koblitz encoder signature from a hard-coded 751-bit modulus to an arbitrary 256-bit prime and replaces the $O(p)$ square-root search with the constant-time method for primes congruent to 3 mod 4.
2. Understanding the encryption path
chall.py does the following:

Generates a random 256-bit prime $p\equiv3\pmod4$.
Chooses random curve coefficients $a,b$ that yield a non-singular Weierstrass equation.
Encodes the flag with the patched Koblitz encoder, producing one affine point per character whose x-coordinate satisfies$$x_m = 20\cdot\mathrm{ord}(c)+j,\qquad 1\le j<20.$$
Builds a private key$$(s,i,\theta,a,b),\qquad
s\in[2^{127},2^{128}),\;
i\in\{10,\dots,14\},\;
\theta\in\{0,180\}.$$
For every Koblitz point $P$ calls dragon.dragon_render(P, private_key).
Serialises the resulting list of end-points with point_to_character.

The critical observation is that a single HeadlessTurtle instance is installed once and never reset. Consequently the heading that exists at the end of one render becomes the starting heading of the next render (after the mandatory left(θ)).
3. Net displacement of the dragon sequence
The turn-sequence generator produces a string of length $2^{i+1}-1$. Simulating the integer moves for every admissible $(i,\theta)$ pair yields a pure-axis net displacement precisely when $i=14$ and $\theta=0$:

starting headingnet $(\mathrm{d}x,\mathrm{d}y)$0°$(0,-128)$90°$(128,0)$180°$(0,128)$270°$(-128,0)$
Because the heading advances by +90° after every call, the even-indexed points always experience a pure vertical move and the odd-indexed points a pure horizontal move. Consequently the observed x-coordinates of the even points are exactly the original Koblitz $x_m$ values, while the odd points satisfy
$$x_{\text{final}} = x_m + 128\cdot s\cdot\sigma$$
where $\sigma=\pm1$ according to the parity of the index.
4. Recovering the step size
All large absolute x-coordinates lie in a narrow interval of width < 5 000 around $3.56\times10^{40}$. For any candidate start abscissa $x_m\in[1,3000]$ one can test whether
$$s = \frac{x_{\text{final}}-x_m}{128}$$
is an integer inside the mandated range $[2^{127},2^{128})$. Exactly nine such candidates keep every recovered $x_m$ inside a plausible range; only two of them produce a fully printable string under the inverse Koblitz map
$$c = \Bigl\lfloor\frac{x_m-1}{20}\Bigr\rfloor.$$
The unique sensible plaintext is
textCopyCopiedFortID{1f_D0n_Knu7h_H4s_1t_0n_th3_W4ll_Th3n_17_Mu57_B3_G00d_F0r_Crypt0_r1ght?}
5. Verification
Re-encoding the recovered characters with the same Koblitz parameters (any valid $a,b,p$) and applying the identical dragon walk with the recovered $s=278012580452280145225903631781209822300$, $i=14$, $\theta=0$ reproduces the given ciphertext bit-for-bit, confirming correctness.
Key Discovery
The cryptographic strength of the scheme rested on two assumptions that do not hold simultaneously:

the turtle state is ephemeral, and
the step size is large enough to hide the original abscissae.

Because the state persists, the net displacement collapses to a known multiple of a single unknown integer $s$. Once $s$ is recovered the original Koblitz points (and therefore the flag) fall out by elementary arithmetic.
Flag Retrieval
textCopyCopiedFortID{1f_D0n_Knu7h_H4s_1t_0n_th3_W4ll_Th3n_17_Mu57_B3_G00d_F0r_Crypt0_r1ght?}

## Root Cause and Remediation

The root cause is the mutable global turtle object whose heading is never restored. A production implementation would either

instantiate a fresh turtle for every point, or
explicitly reset heading (and position) after each render,

thereby destroying the predictable linear relation that allowed recovery of $s$. In addition the private-key components $a$ and $b$ are never used by the dragon walk; they serve only the Koblitz stage and could have been omitted from the key material without loss of security of the curve step.

## Lessons Learned

Stateful geometric primitives can introduce linear relations that completely bypass the intended hardness of the underlying number-theoretic construction. When a cryptographic construction mixes a classical trap-door (Koblitz encoding) with an iterative geometric process, every piece of mutable state must be treated as part of the key schedule and rigorously randomised or reset.

## References

Awnon Bhowmik & Unnikrishnan Menon, “Dragon Crypto – An Innovative Cryptosystem”, International Journal of Computer Applications 176(29), 2020.
Source repository: https://github.com/awnonbhowmik/Dragon-Crypto (commit 046ad8d).
Heighway dragon curve generation and net-displacement properties (classic fractal literature).
