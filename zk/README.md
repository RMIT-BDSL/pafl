# PA-FL Lite — the pared-back zero-knowledge extension

Spec, time budget and cut-lines: `../PLAN_TO_SEP28.md`, section 3.

Statement proved: the prover holds a 1,024-row batch committed as a Poseidon Merkle root R, and
for each of k verifier-chosen indices i the rows x_i and x_{i-1} satisfy every declared linear
invariant within tolerance. No gradient binding. Off-chain verification only.

Planned files:

    export_invariants.py    InvariantSet -> fixed-point JSON (coefficients, constants, tolerances)
    invariant_check.circom  residual range checks + Merkle inclusion + leaf hash
    prove.sh                compile, setup, witness, prove, verify; writes results.json
    results.json            constraint counts by component, timings, proof size, peak RAM

Toolchain: circom 2.1.x, snarkjs, circomlib Poseidon, Hermez powersOfTau28_hez_final_19.ptau.
