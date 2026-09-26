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

**Built.** The measured implementation behind the paper's k = 32 numbers is [`lite/`](lite/README.md). It uses
the PSE `ppot_0080_20.ptau` (2^20, phase-2 prepared), since the Hermez files are no longer served.

**Toolchain.** circom 2.1.9, snarkjs 0.7.4 (both on PATH, not installed by npm), node 23,
circomlib 2.0.5 and circomlibjs 0.1.7 (pinned in `lite/package-lock.json`), `ppot_0080_20.ptau`
(fetched by `lite/ptau/fetch_ptau.sh`).

**Layout** (`lite/README.md` has the full list and the run order; `PLAN.md` the original plan):

    scripts/export_invariants.py           mined invariant set -> fixed-point coefficients   [done 12 Sep]
    data/invariants_swat_wide.json         the 9-rule set in fixed point: coefficients, constants,
                                           tolerances, applicability, channel map, provenance, checks
    data/invariants_swat_narrow.json       the 5-rule set, same format
    lite/circuits/invariant_check.circom   the circuit (one file; PLAN.md's three stages are its templates)
    lite/scripts/gen_main.py               invariant JSON -> the circuit's main component for one k
    lite/scripts/export_batches.py         real SWaT batches -> quantised rows (needs the SWaT archive)
    lite/scripts/build_inputs.mjs          Poseidon tree, root, challenges, snarkjs input
    lite/scripts/run_bench.sh              compile, setup, prove, verify for one k
    lite/scripts/verify.mjs                the verifier: recompute the challenges, check the budgets, verify
    lite/scripts/sample_check.py           detection and honest acceptance vs k, integer model
    lite/results.json                      the circuit and prover measurements the paper quotes
    lite/results_sampling.json             the sampling figures the paper quotes

**Starting without SWaT.** The invariant JSON files are derived parameters, not telemetry, and are
committed. The circuit, its constraint counts and proving times can be built and measured from them
alone (a synthetic batch; the commands are in `lite/README.md`); only the three-proof demonstration
and the sampling figures on real batches need the SWaT archive (request: https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/).
