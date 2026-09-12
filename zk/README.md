# PA-FL Lite — the zero-knowledge extension

- **Implementation Tutorial & Action Plan:** [`PLAN.md`](PLAN.md) — *Step-by-step engineering roadmap, tooling setup, circuit stages, and benchmarking checklist.*
- **Cryptographic Formalization & Specification:** [`FORMALIZATION.md`](FORMALIZATION.md) — *Formal zero-knowledge relation, affine models, fixed-point quantization, and soundness analysis.*

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
    scripts/export_invariants.py      mined invariant set -> fixed-point coefficients   [done 12 Sep]
    scripts/export_batches.py         real SWaT batches -> quantised rows (needs the SWaT archive)
    scripts/sample_check.py           empirical detection against the real attackers
    scripts/build_inputs.mjs          Poseidon tree, root, challenges, snarkjs input
    scripts/run_bench.sh              compile, setup, prove, verify across k
    data/invariants_swat_wide.json    the 9-rule set in fixed point: coefficients, constants,
                                      tolerances, applicability, channel map, provenance, checks
    data/invariants_swat_narrow.json  the 5-rule set, same format
    results.json                      every measurement the paper quotes

**Starting without SWaT.** The invariant JSON files are derived parameters, not telemetry, and are
committed. The circuit, its constraint counts and proving times can be built and measured from them
alone (synthetic or random witnesses); only the three-proof demonstration on real batches needs the
SWaT archive (request: https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/).
