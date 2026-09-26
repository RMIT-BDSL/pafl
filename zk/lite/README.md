# zk/lite — PA-FL Lite build (zero-knowledge invariant attestation)

This is the build behind the k = 32 feasibility results in the MDPI *Information* paper (12.0 s to prove,
290 ms to verify, 806 B proof). It implements the protocol specified in `../README.md`, `../PLAN.md` and
`../FORMALIZATION.md`. It reads two things from the rest of the repo: the fixed-point invariant export
`zk/data/invariants_swat_*.json` and the `pafl` Python package (through `../../.venv/bin/python`).
Only source, the circuit and result JSON are tracked: `data/` (quantised SWaT rows, licensed), `build/`
(proving keys, compiled circuits), the `.ptau` files and `node_modules/` stay local (see `.gitignore`).
Kept in `pafl-lite/` beside the repo until 26 Sep 2026.

## What is proved

The prover holds N = 1,024 rows of telemetry committed as a Poseidon Merkle root R (public).
For each of k public indices i ∈ 1..N−1 the circuit opens rows x[i−1], x[i] against R, evaluates
every mined affine invariant r_j = J_prev·x[i−1] + J_cur·x[i] + c_j in fixed point (S = 2^16), and
checks |r_j| ≤ ε_j where the rule applies (a coupling applies only when its actuator reads one of
its two steady states on both rows). Violations and inapplicable checks are counted over all k
samples and asserted ≤ vMax and ≤ uMax (public). Not proved: that the model update came from the
batch (deferred, as in the spec).

## Layout

    circuits/invariant_check.circom  the circuit: ChunkedHashPlus, LeafHash, MerkleRoot,
                                     CouplingApplicable, AbsLeq, InvariantSample, InvariantCheck
    scripts/gen_main.py              invariant JSON -> build/<tag>/main.circom + circuit_meta.json
    scripts/export_batches.py        SWaT federation (build_variant) -> data/batches_swat_<setting>_seed<s>.json
    scripts/build_inputs.mjs         batch -> Poseidon tree, root, challenge indices, input.json (+ .expect.json)
    scripts/run_bench.sh             compile, setup, and per batch: input, witness, prove, verify; timings
    scripts/collect_results.py       build/<tag>/steps.jsonl + logs -> results.json[<tag>]
    scripts/sample_check.py          honest v/u budget distributions and detection vs k -> results_sampling.json
    ptau/                            fetch_ptau.sh (tracked); ppot_0080_20.ptau (PSE perpetual powers of tau,
                                     2^20, phase-2 prepared) and pot14_final.ptau (dev only) are local only
    build/<tag>/                     everything generated; breakdown/ has per-component constraint counts
    results.json                     measurements per build tag
    results_sampling.json            sampling analysis
    LOG.md                           dated working log (local, untracked)

## Powers of tau (the setup file, not in the repo)

The Groth16 setup needs a powers-of-tau file with room for the circuit: 2^20 = 1,048,576 constraints covers
k = 32 (297,736). This build uses the PSE perpetual powers of tau, `ppot_0080_20.ptau` (phase-2 prepared,
1,208,052,882 bytes, about 1.2 GB), which is too large for the repo. Download it once, from any directory:

    zk/lite/ptau/fetch_ptau.sh     # resumes and retries; checks the size and the SHA-256

It fetches
`https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_20.ptau` and checks
SHA-256 `560412532a1205145d5f21585274fb2cef61273496ddc7186aec855aab01a8cd`, the file behind the paper's numbers.
If the download fails, the same URL works with `curl -L -C - -o zk/lite/ptau/ppot_0080_20.ptau <url>`, which
can be re-run to resume. The Hermez `powersOfTau28_hez_final_20.ptau` named in `../README.md` would also work,
but its download URLs have returned 403 since September 2026. `pot14_final.ptau` (2^14, generated locally for
early development) is not needed.

## Run

    npm install                                                    # circomlib, circomlibjs
    ptau/fetch_ptau.sh                                             # once: the 1.2 GB setup file (above)
    ../../.venv/bin/python scripts/export_batches.py --seed 0      # needs SWaT; ~4 s from the cache
    scripts/run_bench.sh wide_k32 ptau/ppot_0080_20.ptau data/batches_swat_wide_seed0.json 1 8 1
    #                    <tag>    <ptau>                  <batches>                          vMax uMax nonce
    ../../.venv/bin/python scripts/sample_check.py data/batches_swat_wide_seed0.json

`<tag>` is `<setting>_k<k>`; `run_bench.sh` generates the main for it if absent. A batch whose
sampled rows exceed the budgets fails at witness generation (that is the "fabricated batch
hard-aborts" demonstration); the driver records it and moves on.

## Design decisions (where this build departs from a literal reading of FORMALIZATION.md)

1. **Coefficients are circuit constants, budgets are public inputs.** J, c, ε are template
   parameters baked in by `gen_main.py`, so every affine residual is a free linear combination and
   the verification key commits to the invariant set. vMax/uMax stay public so policy can change
   without a new setup. Public inputs: root, idx[k], vMax, uMax (k + 3).
2. **Biased unsigned channel encoding.** Every value enters the circuit (hash preimage and
   arithmetic) as x̂ + 2^31 and is range-checked to 32 bits. Needed because the adaptive
   attacker's projection drives unprotected flow channels negative (down to −62 m³/h on FIT401
   in the seed-0 projected batch). The bias is folded into c and into the actuator encodings;
   the exported JSON keeps the raw constants.
3. **Leaf hash.** circomlib's Poseidon takes ≤ 16 inputs, so the 18 invariant channels are hashed
   in two chunks of 9 and the leaf is Poseidon(h₁, h₂, hRest), hRest = Poseidon over the 24 other
   channels (two chunks of 12, then Poseidon(h₁, h₂, 0)) supplied by the prover. 1,095 constraints
   per leaf against ~1,500 for a 42-wide sponge.
4. **Soft range check.** |r| ≤ ε is a 0/1 flag (two LessEqThan(56) on r + 2^54), so violations are
   counted rather than aborting; only the budget comparisons abort. The 32-bit range checks on the
   opened values guarantee the field arithmetic equals integer arithmetic (|r| < 2^53 < K).
5. **Challenge indices** are derived outside the circuit as Poseidon(root, nonce, ctr) mod (N−1) + 1,
   deduplicated, and are public inputs; the verifier recomputes them. Row 0 is never sampled.
6. **Trusted setup.** `groth16 setup` on the PSE ptau with no phase-2 contribution: benchmark
   setup only, not a deployable key.

## Constraint budget (measured, wide set: 9 rules over 18 channels)

| component | constraints |
|---|---|
| Poseidon(2) / (3) / (9) | 240 / 261 / 417 |
| Merkle path, depth 10 | 2,420 |
| leaf hash, 18 channels | 1,095 |
| 36 × Num2Bits(32) range checks | 1,152 |
| 9 × AbsLeq(56) soft tolerance checks | 1,035 |
| 6 × CouplingApplicable | 60 |
| per sample (2 paths + 2 leaves + physics + 2 × Num2Bits(10)) | 9,304 |
| k = 32 total | 297,736 |

See `results.json` for timings and `LOG.md` for the dated record.

## Results (16 Sep 2026; `scripts/make_table.py wide_k32 wide_k16`)

### Circuit and prover cost (Groth16, snarkjs, Apple M3 Pro)

|  | k = 32 | k = 16 |
|---|---|---|
| R1CS constraints | 297,736 | 148,888 |
| constraints per sample | 9,304 | 9,306 |
| public / private inputs | 35 / 1,856 | 19 / 928 |
| compile | 15 s | 7.47 s |
| setup (peak RSS) | 223 s (3127 MB) | 124 s (1946 MB) |
| proving key | 217.4 MB | 108.7 MB |
| verification key | 8.9 kB | 6.1 kB |
| witness, honest batch | 0.56 s | 0.41 s |
| prove, honest batch (peak RSS) | 12 s (3616 MB) | 6.55 s (2327 MB) |
| verify, honest batch | 0.29 s | 0.30 s |
| proof size | 806 B | 808 B |

### The three-proof demonstration (vMax = 1, uMax = 8)

| batch | violating rows in batch | violations / inapplicable in the k samples | outcome |
|---|---|---|---|
| honest (k = 32) | 0.39% | 0 / 0 | proof verifies |
| channel_roll (k = 32) | 21.29% | 18 / 1 | witness generation aborts (budget exceeded) |
| projected (k = 32) | 0.68% | 0 / 0 | proof verifies |
| splice_only (k = 32) | 23.34% | 6 / 0 | witness generation aborts (budget exceeded) |
| honest (k = 16) | 0.39% | 0 / 0 | proof verifies |
| channel_roll (k = 16) | 21.29% | 6 / 1 | witness generation aborts (budget exceeded) |
| projected (k = 16) | 0.68% | 0 / 0 | proof verifies |
| splice_only (k = 16) | 23.34% | 5 / 0 | witness generation aborts (budget exceeded) |

### Sampling: honest false-rejection and detection (integer model, 20000 draws)

| k | E[v] honest | P(v ≤ 1) | P(v ≤ 2) | P(u ≤ 8) | P(reject roll, vMax 1) | P(reject splice) | P(reject projected) |
|---|---|---|---|---|---|---|---|
| 8 | 0.034 | 0.9972 | 0.9999 | 1.0000 | 0.702 | 0.593 | 0.010 |
| 16 | 0.063 | 0.9941 | 0.9998 | 0.9999 | 0.935 | 0.917 | 0.019 |
| 32 | 0.128 | 0.9851 | 0.9990 | 1.0000 | 0.998 | 0.998 | 0.044 |
| 64 | 0.254 | 0.9634 | 0.9960 | 0.9977 | 1.000 | 1.000 | 0.109 |

### 40 rounds at k = 32 (witness generation only; `scripts/nonce_sweep.sh wide_k32 … 40 1 8`)

| batch | rounds with a witness | mean violations in 32 samples |
|---|---|---|
| honest | 40 / 40 | 0.05 |
| projected | 39 / 40 | 0.38 |
| channel roll | 0 / 40 | 15.4 (min 5) |
| splice-only | 0 / 40 | 8.1 (min 3) |
