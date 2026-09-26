pragma circom 2.1.9;

// PA-FL Lite: zero-knowledge invariant attestation over a committed telemetry batch.
//
// Statement (see pafl/zk/FORMALIZATION.md).  The prover holds N = 2^depth rows of
// quantised telemetry committed as a Poseidon Merkle root R.  For each of k public
// indices i in 1..N-1 the rows x[i-1], x[i] are opened against R and every declared
// affine invariant r_j = J_prev[j].x[i-1] + J_cur[j].x[i] + c_j is range-checked
// against its tolerance eps_j where the rule applies.  The number of violations
// over all k samples is at most vMax and the number of inapplicable checks at most
// uMax (both public).
//
// Design decisions of this implementation (they differ from a literal reading of
// the spec and are recorded in ../README.md):
//   * the invariant coefficients, constants and tolerances are compile-time
//     constants (template parameters), not public inputs: the verification key
//     then commits to the invariant set and every affine sum is a free linear
//     combination.  The budgets vMax/uMax stay public so policy can change without
//     a new setup;
//   * every opened channel value is range-checked to xBits bits so the field
//     arithmetic equals integer arithmetic (otherwise a prover could wrap mod p);
//   * circomlib's Poseidon takes at most 16 inputs, so the invariant channels of a
//     row are hashed in equal chunks of at most 16 and the leaf is
//     Poseidon(chunk hashes..., hRest), hRest being the prover-supplied hash of the
//     channels no rule reads.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";

// ---------------------------------------------------------------- helpers

function chunkCount(n) { return (n + 15) \ 16; }
function chunkSize(n)  { return (n + chunkCount(n) - 1) \ chunkCount(n); }

// Hash n field elements in nChunks equal chunks (zero padded), then hash the chunk
// digests together with one extra element.  Mirrored in scripts/build_inputs.mjs.
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

// leaf = ChunkedHashPlus(invariant channels, hRest)
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
// rows and did not change between them.  offHat/onHat are the quantised encodings.
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
// below 2K, and K + eps + 1 < 2^bits.
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

// Rows x[i-1] (xPrev) and x[i] (xCur) restricted to the nInv invariant channels.
//   coefPrev[j][d], coefCur[j][d] : quantised coefficients (dense over the nInv channels)
//   cHat[j], epsHat[j]            : quantised constant and tolerance
//   isCoupling[j]                 : 1 if the rule is an actuator coupling
//   statusIdx[j], offHat[j], onHat[j] : the coupling's status channel and encodings
template InvariantSample(nInv, nRules, xBits, rBits, K,
                         coefPrev, coefCur, cHat, epsHat,
                         isCoupling, statusIdx, offHat, onHat) {
    signal input xPrev[nInv];
    signal input xCur[nInv];
    signal output violations;      // number of applicable checks that failed
    signal output inapplicable;    // number of checks that did not apply

    // every opened value is a genuine xBits-bit integer
    component rcP[nInv];
    component rcC[nInv];
    for (var d = 0; d < nInv; d++) {
        rcP[d] = Num2Bits(xBits); rcP[d].in <== xPrev[d];
        rcC[d] = Num2Bits(xBits); rcC[d].in <== xCur[d];
    }

    component chk[nRules];
    component app[nRules];
    signal r[nRules];
    signal applies[nRules];
    signal viol[nRules];
    var vSum = 0;
    var uSum = 0;
    for (var j = 0; j < nRules; j++) {
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

template InvariantCheck(k, depth, nInv, nRules, xBits, rBits, K,
                        coefPrev, coefCur, cHat, epsHat,
                        isCoupling, statusIdx, offHat, onHat) {
    // public
    signal input root;
    signal input idx[k];            // row indices in 1 .. 2^depth - 1
    signal input vMax;
    signal input uMax;
    // private
    signal input xPrev[k][nInv];
    signal input xCur[k][nInv];
    signal input hRestPrev[k];
    signal input hRestCur[k];
    signal input pathPrev[k][depth];
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
        // idx in [0, 2^depth) and idx - 1 in [0, 2^depth)  =>  idx in [1, 2^depth - 1]
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
        rootPrev[m].root === root;
        rootCur[m].root  === root;

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
    // budgets: counts are at most k * nRules < 2^20
    component vOk = LessEqThan(20); vOk.in[0] <== vTotal; vOk.in[1] <== vMax;
    component uOk = LessEqThan(20); uOk.in[0] <== uTotal; uOk.in[1] <== uMax;
    vOk.out === 1;
    uOk.out === 1;
}
