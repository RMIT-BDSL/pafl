# PA-FL Lite — the zero-knowledge extension

**The implementation plan is [`PLAN.md`](PLAN.md).** This file is a one-screen summary.

Every experiment in the paper computes the physics check directly on a client's raw batch, which
would require the server to see the telemetry that federated learning exists to hide. PA-FL Lite
shows the check can be enforced without that: the client proves in zero knowledge that its committed
training batch satisfies the plant's mined invariants.

**Proved.** The prover holds a 1,024-row batch committed as a Poseidon Merkle root. For each of k
verifier-chosen indices the rows at i and i-1 satisfy every declared invariant within tolerance,
with at most v violations and at most u inapplicable checks.

**Not proved.** That the submitted model update was computed from that batch. Last-layer gradient
binding is specified in the paper's design section and is the next implementation step.

**Toolchain.** circom 2.1.9, snarkjs 0.7.4, node 23, circomlib and circomlibjs,
`powersOfTau28_hez_final_20.ptau`.

**Layout** (see `PLAN.md` for what each does and in what order they are built):

    circuits/invariant_check.circom   the circuit, built in three stages
    export_invariants.py              mined invariant set -> fixed-point coefficients
    export_batches.py                 real SWaT batches -> quantised rows
    sample_check.py                   empirical detection against the real attackers
    build_inputs.mjs                  Poseidon tree, root, challenges, snarkjs input
    run_bench.sh                      compile, setup, prove, verify across k
    results.json                      every measurement the paper quotes
