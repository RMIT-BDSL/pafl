pragma circom 2.1.9;

// PA-FL Lite: zero-knowledge invariant attestation over a committed telemetry batch.
//
// Statement (see zk/FORMALIZATION.md).  The prover holds N = 2^depth rows of
// quantised telemetry committed as a Poseidon Merkle root R.  For each of k public
// indices i in 1..N-1 the rows x[i-1], x[i] are opened against R and every declared
// affine invariant r_j = J_prev[j].x[i-1] + J_cur[j].x[i] + c_j is range-checked
// against its tolerance eps_j where the rule applies.  The number of violations
// over all k samples is at most vMax and the number of inapplicable checks at most
// uMax (both public).
//
// Every rule reads a row and its predecessor (a balance differences a tank level
// over one step; a coupling needs the actuator state on both rows), so each sample
// opens two leaves, and row 0, which has no predecessor, is never sampled.  The
// indices themselves are not derived here: the verifier recomputes them from R and
// its round nonce, idx_m = Poseidon(R, nonce, ctr) mod (N-1) + 1 with repeats
// skipped (scripts/build_inputs.mjs, scripts/verify.mjs), and rejects a proof whose
// public idx differ.
//
// Design decisions of this implementation (they differ from a literal reading of
// the spec and are recorded in ../README.md):
//   * the invariant coefficients, constants and tolerances are compile-time
//     constants (template parameters), not public inputs: the verification key
//     then commits to the invariant set and every affine sum is a free linear
//     combination.  The budgets vMax/uMax stay public so policy can change without
//     a new setup;
//   * channel values enter biased, x_hat + 2^(xBits-1), so a reading the adaptive
//     attacker drives below zero is still an unsigned integer; scripts/gen_main.py
//     folds the bias into c_j and into the actuator encodings;
//   * every opened channel value is range-checked to xBits bits so the field
//     arithmetic equals integer arithmetic (otherwise a prover could wrap mod p);
//   * circomlib's Poseidon takes at most 16 inputs, so the invariant channels of a
//     row are hashed in equal chunks of at most 16 and the leaf is
//     Poseidon(chunk hashes..., hRest), hRest being the prover-supplied hash of the
//     channels no rule reads.
//
// The template parameters are written by scripts/gen_main.py into
// build/<tag>/main.circom; this file has no main component of its own.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";

// ---------------------------------------------------------------- helpers

// The fewest chunks of at most 16 (circomlib Poseidon's input limit), made equal in
// size: 18 invariant channels -> 2 x 9, 24 other channels -> 2 x 12.
function chunkCount(n) { return (n + 15) \ 16; }
function chunkSize(n)  { return (n + chunkCount(n) - 1) \ chunkCount(n); }

// Hash n field elements in nChunks equal chunks (zero padded), then hash the chunk
// digests together with one extra element.  Mirrored in scripts/build_inputs.mjs
// (chunkedHashPlus) and scripts/gen_main.py (chunking); the three must agree or the
// root the prover publishes will not match the one the circuit recomputes.
template ChunkedHashPlus(n) {
    var nc = chunkCount(n);
    var cs = chunkSize(n);
    signal input x[n];
    signal input extra;
    signal output out;

    component h[nc];
    for (var c = 0; c < nc; c++) {
        h[c] = Poseidon(cs);
        for (var i = 0; i < cs; i++) {
            if (c * cs + i < n) { h[c].inputs[i] <== x[c * cs + i]; }
            else                { h[c].inputs[i] <== 0; }
        }
    }
    component top = Poseidon(nc + 1);
    for (var c = 0; c < nc; c++) { top.inputs[c] <== h[c].out; }
    top.inputs[nc] <== extra;
    out <== top.out;
}

// leaf = ChunkedHashPlus(invariant channels, hRest).  Only the nInv channels a rule
// reads are hashed in-circuit; hRest = ChunkedHashPlus(other channels, 0) is computed
// by the prover and enters as a private input.  The root commits to hRest, so the
// whole row is still bound, at 1,095 constraints per leaf for the wide set instead
// of ~1,500 for all 42 channels.
template LeafHash(nInv) {
    signal input x[nInv];
    signal input hRest;
    signal output leaf;
    component h = ChunkedHashPlus(nInv);
    for (var i = 0; i < nInv; i++) { h.x[i] <== x[i]; }
    h.extra <== hRest;
    leaf <== h.out;
}

// Recompute the root from a leaf, its sibling path and the index bits (LSB first).
// Bit l = 0 puts the running hash on the left at level l, 1 on the right.  The bits
// come from Num2Bits in the caller, so they are constrained to 0/1.
template MerkleRoot(depth) {
    signal input leaf;
    signal input path[depth];
    signal input bits[depth];
    signal output root;

    component mux[depth];
    component h[depth];
    signal cur[depth + 1];
    cur[0] <== leaf;
    for (var l = 0; l < depth; l++) {
        mux[l] = MultiMux1(2);
        mux[l].c[0][0] <== cur[l];   mux[l].c[0][1] <== path[l];
        mux[l].c[1][0] <== path[l];  mux[l].c[1][1] <== cur[l];
        mux[l].s <== bits[l];
        h[l] = Poseidon(2);
        h[l].inputs[0] <== mux[l].out[0];
        h[l].inputs[1] <== mux[l].out[1];
        cur[l + 1] <== h[l].out;
    }
    root <== cur[depth];
}

// A coupling applies when the actuator reads one of its two steady states on both
// rows and did not change between them.  offHat/onHat are the biased quantised
// encodings of those states, round(S v) + 2^(xBits-1) (SWaT: 1 = closed/off,
// 2 = open/on).  The test is exact equality; the Python model rounds the status
// first (pafl/zk/fixed_point.py, rint(x_hat / S)), and the two agree because SWaT
// actuators hold exact integers.  A prover who writes any other status value makes
// the rule inapplicable, which is what the uMax budget bounds.
template CouplingApplicable(offHat, onHat) {
    signal input sPrev;
    signal input sCur;
    signal output app;
    component eOffP = IsEqual(); eOffP.in[0] <== sPrev; eOffP.in[1] <== offHat;
    component eOffC = IsEqual(); eOffC.in[0] <== sCur;  eOffC.in[1] <== offHat;
    component eOnP  = IsEqual(); eOnP.in[0]  <== sPrev; eOnP.in[1]  <== onHat;
    component eOnC  = IsEqual(); eOnC.in[0]  <== sCur;  eOnC.in[1]  <== onHat;
    signal bothOff <== eOffP.out * eOffC.out;
    signal bothOn  <== eOnP.out  * eOnC.out;
    app <== bothOff + bothOn;        // exclusive because offHat != onHat
}

// ok = 1 iff |r| <= eps, as a soft flag.  r is a signed integer with |r| < K
// (guaranteed by the caller's range checks); s = r + K is then an unsigned value
// below 2K, and K + eps + 1 < 2^bits.  Those bounds are what LessEqThan(bits) needs
// to be sound (both operands below 2^bits); gen_main.py derives K and bits from the
// coefficients and xBits (wide set: K = 2^54, bits = 56).  A failed check gives
// ok = 0 rather than an unsatisfiable constraint, so violations can be counted
// against a budget instead of aborting on the first one.
template AbsLeq(bits, K, eps) {
    signal input r;
    signal output ok;
    signal s <== r + K;
    component lo = LessEqThan(bits);   // K - eps <= s
    lo.in[0] <== K - eps;
    lo.in[1] <== s;
    component hi = LessEqThan(bits);   // s <= K + eps
    hi.in[0] <== s;
    hi.in[1] <== K + eps;
    ok <== lo.out * hi.out;
}

// ---------------------------------------------------------------- one sample

// Counts, for one sampled pair of rows, the rules that apply but fail and the rules
// that do not apply.  Rows x[i-1] (xPrev) and x[i] (xCur) are restricted to the nInv
// invariant channels and biased by 2^(xBits-1).
//   coefPrev[j][d], coefCur[j][d] : quantised coefficients round(S J) (dense over the
//                                   nInv channels, zero where rule j does not read d)
//   cHat[j], epsHat[j]            : quantised constant (bias folded in) and tolerance,
//                                   both on the S^2 scale of the residual
//   isCoupling[j]                 : 1 if the rule is an actuator coupling
//   statusIdx[j], offHat[j], onHat[j] : the coupling's status channel and encodings
template InvariantSample(nInv, nRules, xBits, rBits, K,
                         coefPrev, coefCur, cHat, epsHat,
                         isCoupling, statusIdx, offHat, onHat) {
    signal input xPrev[nInv];
    signal input xCur[nInv];
    signal output violations;      // number of applicable checks that failed
    signal output inapplicable;    // number of checks that did not apply

    // Every opened value is a genuine xBits-bit integer.  With the coefficients fixed
    // this bounds |r_j| below K, so the residual equals its integer value (no wrap
    // mod p) and AbsLeq's operands stay in range.
    component rcP[nInv];
    component rcC[nInv];
    for (var d = 0; d < nInv; d++) {
        rcP[d] = Num2Bits(xBits); rcP[d].in <== xPrev[d];
        rcC[d] = Num2Bits(xBits); rcC[d].in <== xCur[d];
    }

    component chk[nRules];
    component app[nRules];
    signal r[nRules];              // residual of rule j, on the S^2 scale
    signal applies[nRules];        // 1 if rule j applies to this pair
    signal viol[nRules];           // 1 if it applies and |r_j| > eps_j
    var vSum = 0;
    var uSum = 0;
    for (var j = 0; j < nRules; j++) {
        // constant coefficients: r_j is a linear combination, no multiplications
        var acc = cHat[j];
        for (var d = 0; d < nInv; d++) {
            acc += coefPrev[j][d] * xPrev[d];
            acc += coefCur[j][d]  * xCur[d];
        }
        r[j] <== acc;
        chk[j] = AbsLeq(rBits, K, epsHat[j]);
        chk[j].r <== r[j];
        if (isCoupling[j] == 1) {
            app[j] = CouplingApplicable(offHat[j], onHat[j]);
            app[j].sPrev <== xPrev[statusIdx[j]];
            app[j].sCur  <== xCur[statusIdx[j]];
            applies[j] <== app[j].app;
        } else {
            applies[j] <== 1;      // balances apply to every row that has a predecessor
        }
        viol[j] <== applies[j] * (1 - chk[j].ok);
        vSum += viol[j];
        uSum += 1 - applies[j];
    }
    violations <== vSum;
    inapplicable <== uSum;
}

// ---------------------------------------------------------------- the circuit

// The whole statement: k sampled pairs opened against one root, their violation and
// inapplicability counts summed, and both sums held to the public budgets.  Public
// signals, in the order snarkjs lists them: root, idx[0..k-1], vMax, uMax.
template InvariantCheck(k, depth, nInv, nRules, xBits, rBits, K,
                        coefPrev, coefCur, cHat, epsHat,
                        isCoupling, statusIdx, offHat, onHat) {
    // public
    signal input root;              // the batch commitment the client published
    signal input idx[k];            // row indices in 1 .. 2^depth - 1; the verifier
                                    // checks they are its Poseidon challenges (distinct)
    signal input vMax;              // budgets, checked by the verifier against its policy
    signal input uMax;
    // private: for each sample m, rows idx[m]-1 (Prev) and idx[m] (Cur)
    signal input xPrev[k][nInv];    // invariant channels, biased
    signal input xCur[k][nInv];
    signal input hRestPrev[k];      // hash of each row's remaining channels
    signal input hRestCur[k];
    signal input pathPrev[k][depth];  // Merkle sibling paths, leaf level first
    signal input pathCur[k][depth];

    component bitsCur[k];
    component bitsPrev[k];
    component leafPrev[k];
    component leafCur[k];
    component rootPrev[k];
    component rootCur[k];
    component sample[k];
    var vTot = 0;
    var uTot = 0;

    for (var m = 0; m < k; m++) {
        // idx in [0, 2^depth) and idx - 1 in [0, 2^depth)  =>  idx in [1, 2^depth - 1].
        // The bits double as the Merkle path directions of the two leaves.
        bitsCur[m]  = Num2Bits(depth); bitsCur[m].in  <== idx[m];
        bitsPrev[m] = Num2Bits(depth); bitsPrev[m].in <== idx[m] - 1;

        leafPrev[m] = LeafHash(nInv);
        leafCur[m]  = LeafHash(nInv);
        for (var d = 0; d < nInv; d++) {
            leafPrev[m].x[d] <== xPrev[m][d];
            leafCur[m].x[d]  <== xCur[m][d];
        }
        leafPrev[m].hRest <== hRestPrev[m];
        leafCur[m].hRest  <== hRestCur[m];

        rootPrev[m] = MerkleRoot(depth);
        rootCur[m]  = MerkleRoot(depth);
        rootPrev[m].leaf <== leafPrev[m].leaf;
        rootCur[m].leaf  <== leafCur[m].leaf;
        for (var l = 0; l < depth; l++) {
            rootPrev[m].path[l] <== pathPrev[m][l];
            rootPrev[m].bits[l] <== bitsPrev[m].out[l];
            rootCur[m].path[l]  <== pathCur[m][l];
            rootCur[m].bits[l]  <== bitsCur[m].out[l];
        }
        // both rows of the pair belong to the committed batch
        rootPrev[m].root === root;
        rootCur[m].root  === root;

        // the physics on the same opened values
        sample[m] = InvariantSample(nInv, nRules, xBits, rBits, K,
                                    coefPrev, coefCur, cHat, epsHat,
                                    isCoupling, statusIdx, offHat, onHat);
        for (var d = 0; d < nInv; d++) {
            sample[m].xPrev[d] <== xPrev[m][d];
            sample[m].xCur[d]  <== xCur[m][d];
        }
        vTot += sample[m].violations;
        uTot += sample[m].inapplicable;
    }

    signal vTotal <== vTot;
    signal uTotal <== uTot;
    // Budgets: the only hard failure.  Counts are at most k * nRules < 2^20, the
    // comparator's operand bound.  An over-budget batch has no witness, so the
    // prover cannot produce a proof at all.
    component vOk = LessEqThan(20); vOk.in[0] <== vTotal; vOk.in[1] <== vMax;
    component uOk = LessEqThan(20); uOk.in[0] <== uTotal; uOk.in[1] <== uMax;
    vOk.out === 1;
    uOk.out === 1;
}
