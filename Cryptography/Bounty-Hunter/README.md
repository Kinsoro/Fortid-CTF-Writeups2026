# Bounty Hunter — Unsound Folding in a Public TwinFold PCS | FortID CTF

**Category:** Cryptography
**Platform:** FortID CTF
**Flag format:** FortID{...}

## Executive Summary

The challenge presents a BugLedger researcher portal that releases a sealed payout attachment only after a valid receipt proof is submitted. Triage state is encoded as the evaluation vector of a public univariate polynomial over a $2^{13}$-sized Boolean hypercube and committed under the custom TwinFold-PCS-v2 scheme. Because the vector (and therefore the initial coefficient commitment) is published, the first folding step is completely determined. Subsequent polynomials, however, are supplied by the prover. By constructing linear polynomials that satisfy the local evaluation and fold equations while forcing the claimed value to 1, an arbitrary payout authorization receipt can be forged for any of the researcher’s own reports. Submission of the forged proof releases the flag.

## Challenge Overview

The instance is hosted at https://bounty-hunter-f4f9d4310f25.inst3.ctf.fortid.com. The portal is presented as a private BugLedger workspace for the researcher handle el1t3_hun73r. Navigation exposes:

/reports — list of the six owned reports
/transparency — public triage snapshot (triage-2026-09-28) consisting of a manifest and eight 1024-element shards
/playground — sample proof for report #604 together with the verifier source
/vault — form that accepts a TwinFold-PCS-v2 proof JSON and, on success, releases the sealed attachment

The vault policy requires a proof of the claim
payout_authorized(report_id) = 1
for any report belonging to the signed-in researcher. All live reports show payout_authorized = 0.

## Environment and Tools

curl / Python 3 urllib for fetching the public API endpoints
Local Python 3 implementation of the published verifier.py logic (field arithmetic, SHA-256 coefficient commitment, Fiat-Shamir challenge, folding)
No external cryptographic libraries beyond the standard library were required

## Methodology and Reconnaissance

Portal enumeration
The landing page identifies the researcher and links to the four functional areas above. The reports endpoint returns the six owned report IDs together with their triage bits:
JSONCopyCopied{
  "owned_report_ids": [271, 604, 918, 1247, 1569, 1842],
  "vault_policy": {
    "field": "payout_authorized",
    "required_claimed_value": "1",
    "scope": "any_owned_report"
  }
}
Every report records payout_authorized: 0.
Transparency snapshot
The manifest at /api/transparency/snapshots/latest/manifest.json discloses:

scheme TwinFold-PCS-v2
13 variables (11-bit report ID + 2-bit column index)
vector length 8192
column encoding: duplicate=0, accepted=1, critical=2, payout_authorized=3
public coefficient commitmentd438f6d51d055de1555a4f6defacaf3a889b3700bedadd7edb4d513ba833c859
eight shard paths under /api/transparency/snapshots/triage-2026-09-28/shards/

The shards are publicly downloadable; concatenating them yields the complete evaluation vector. Non-zero entries exist only at the cells corresponding to the six real reports; the cell for any payout_authorized bit is 0.
Verifier source
/api/replay/verifier.py implements the entire verification procedure. The critical fragments are:
PythonCopyCopiedP = 35182531786822156541290684230036086178800502148536840364113258180206318266211

def challenge(snapshot_id, commitment, report_id, field, claimed_value):
    r = h_int("TwinFold-v2", snapshot_id, commitment, report_id, field, claimed_value)
    return 7 if r in (0, 1, P - 1) else r

def fold_value(a, b, bit, x):
    if bit == 0:
        return (a + b) * inv(2) % P
    return (a - b) * inv(2 * x) % P
Coefficient commitment is a simple SHA-256 of the length-prefixed list of field elements. The initial coefficients are taken directly from the public vector. Each subsequent polynomial is supplied by the prover in the next_coeffs field of the corresponding round.
Key Discovery — Unsound Folding
Because the evaluation vector is public, the initial polynomial is fixed. Consequently the pair of evaluations $(a_0,b_0)$ at $\pm x_0$ (where $x_0$ is derived from the Fiat-Shamir challenge that itself depends on the claimed value) is completely determined. The first fold value is therefore forced.
All later polynomials, however, are chosen by the prover. A linear polynomial $c_0 + c_1 X$ gives two degrees of freedom:

its evaluation at the current challenge point can be forced to equal the value required by the previous fold,
its fold under the next bit can be forced to any desired field element (in particular the forged claim 1).

By constructing such a linear polynomial after the first forced fold and then preserving the constant 1 through the remaining twelve rounds, a transcript is obtained that satisfies every local check performed by the verifier while claiming an arbitrary value.
The construction is fully deterministic once a target report ID, the public vector, and the desired claim are fixed.
Solution Walkthrough

Fetch the manifest and the eight shards; assemble the 8192-element evaluation vector.
Select any owned report (e.g. 1247) and the field payout_authorized.
Compute the 13-bit index, the Fiat-Shamir challenge $\rho$ for the forged claim 1, and the successive challenge points $x_i = \rho^{2^i}$.
Evaluate the public polynomial at $\pm x_0$ and obtain the forced first fold value $v_0$.
For each subsequent round $i = 1 \dots 12$:
build a linear polynomial whose evaluation at $x_i$ equals the value required by the preceding fold,
and whose fold under bit $i$ equals 1.

Emit the final constant polynomial $[1]$.
Assemble the proof JSON containing the thirteen rounds and the corresponding coefficient commitments.
Verify the proof locally with the published verifier logic; it returns accepted.
POST the same JSON to /vault. The server accepts the receipt and returns the flag.

The resulting proof JSON is approximately 4 KB and verifies both locally and on the remote endpoint.
Flag Retrieval
textCopyCopiedFortID{Bu6_B0Un7y_H0UN73r5_SH0ulD_B3_4bl3_70_5P07_Uns0Und_Pr00FzZ}

## Root Cause and Remediation

The scheme treats the initial coefficient commitment as binding while allowing the prover unrestricted choice of every subsequent polynomial. In a sound folding or sum-check argument the next polynomial must itself be committed in a way that binds its evaluations; here the only binding is a hash of the coefficients that the prover simply invents.
A production implementation would need either:

a cryptographic polynomial commitment (KZG, IPA, FRI, \ldots) that binds each folded polynomial before the next challenge is issued, or
a public-coin interactive protocol in which the verifier samples the challenges after seeing each commitment, followed by a Fiat-Shamir transform that includes those commitments.

Publishing the evaluation vector itself removes any secrecy of the underlying data; the PCS is therefore only a proof of knowledge of an evaluation, not a zero-knowledge argument. When the vector is public the only remaining security property is soundness of the evaluation proof, which the present construction does not provide.

## Lessons Learned

When a “transparent” ledger publishes both the data and a custom polynomial commitment, the first question is whether the commitment is actually binding after the initial step. In TwinFold-PCS-v2 the answer is negative: after the forced first fold the prover can freely rewrite the remaining transcript. The resulting forgery is short, deterministic, and accepted by the official verifier—exactly the property a bounty hunter is expected to notice.
