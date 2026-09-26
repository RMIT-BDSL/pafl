# PA-FL Lite: Implementation Tutorial and Action Plan

**A Step-by-Step Practical Guide to Building and Benchmarking Zero-Knowledge Invariant Attestation**

*Companion Theoretical Specification: [`FORMALIZATION.md`](FORMALIZATION.md)*

---

## 1. Overview and Engineering Objectives

**PA-FL Lite** is the zero-knowledge attestation extension for the Physics-Attested Federated Learning (`pafl`) framework. Its goal is to replace direct server-side data inspection with a client-generated zero-knowledge proof (zk-SNARK), proving that a private training batch satisfies declared physical process invariants without revealing raw telemetry to the aggregator.

```
+-------------------------------------------------------------------------------+
|                            PA-FL LITE PIPELINE                                |
|                                                                               |
|  [ Mined InvariantSet ] --------> export_invariants.py ----> invariants.json  |
|  [ Real Plant Telemetry ] ------> export_batches.py -------> batches.json     |
|                                                                 |             |
|                                                                 v             |
|  [ Poseidon Tree / Witness ] ---> build_inputs.mjs --------> input.json       |
|                                                                 |             |
|                                                                 v             |
|  [ Circom Circuit ] ------------> run_bench.sh -----------> results.json     |
|  (Stages 1, 2, 3)                (snarkjs groth16)          (LaTeX Table)     |
+-------------------------------------------------------------------------------+
```

This tutorial outlines the sequential steps to implement the export pipeline, write numerical validation tests, construct the arithmetic circuits, and collect empirical benchmark metrics for the paper.

---

## 2. Prerequisites and Environment Setup

### 2.1 Hardware and Toolchain
Ensure the required toolchain is available on the local workstation (Apple Silicon M3, $`\ge 32\text{ GiB}`$ RAM recommended):

* **Python:** $`\ge 3.10`$ within the project virtual environment (`.venv/`)
* **Node.js:** $`\ge 20.0`$ (installed: `node 23.x`)
* **Circom Compiler:** $`\ge 2.1.9`$ (`circom --version`)
* **SnarkJS:** $`\ge 0.7.4`$ (`snarkjs --version`)

### 2.2 Directory Structure
Initialize the directory layout under `zk/`:

```bash
mkdir -p zk/circuits zk/scripts
```

File mapping:

```
pafl/
├── zk/
│   ├── FORMALIZATION.md            # Cryptographic relation and mathematical spec
│   ├── PLAN.md                     # This step-by-step implementation tutorial
│   ├── README.md                   # One-page executive summary
│   ├── package.json                # Dependencies: circomlib, circomlibjs
│   ├── circuits/
│   │   ├── invariant_check.circom   # Core parameterized circuit (Stages 1–3)
│   │   ├── affine_residual.circom   # Fixed-point affine residual evaluator
│   │   ├── applicability.circom     # Actuator status comparison gates
│   │   └── merkle_verify.circom     # Poseidon Merkle authentication path verifier
│   ├── scripts/
│   │   ├── export_invariants.py     # InvariantSet -> fixed-point JSON parameters
│   │   ├── export_batches.py        # Real SWaT batches -> quantized integer matrices
│   │   ├── build_inputs.mjs         # Generates Merkle tree, challenge indices, input.json
│   │   ├── run_bench.sh             # End-to-end benchmark driver across k
│   │   └── sample_check.py          # Python Monte Carlo simulation of detection vs k
│   └── results.json                 # Output metrics (constraints, proving time, memory)
└── tests/
    └── test_zk_export.py            # Pytest suite for quantization fidelity
```

### 2.3 Dependency Installation and Powers of Tau
From the `zk/` directory, initialize Node dependencies and acquire the universal setup parameters:

```bash
cd zk
npm init -y
npm install --save circomlib circomlibjs

# Download the Powers of Tau ceremony file (2.4 GB, up to 2^20 ~ 1,048,576 constraints)
curl -L -o powersOfTau28_hez_final_20.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau
```

---

## 3. Step-by-Step Implementation Guide

### Step 1: Export Invariant Models to Fixed-Point JSON


> **Scope split (14 Sep 2026).** The paper needs only a feasibility result: steps 2–4 at **k = 32** on the wide
> set (batch export, circuit stages 1–3, one setup/prove/verify) and the three-proof demonstration. The k sweep,
> the empirical `sample_check.py` curve, update binding and the security argument are left to follow-up work.
> Build order is unchanged; stop after the k = 32 measurement for the paper and continue in the follow-up.

> **Status (12 Sep 2026): done.** `zk/scripts/export_invariants.py` is written and
> `zk/data/invariants_swat_wide.json` (9 rules, 18 of 42 channels) and `invariants_swat_narrow.json`
> are committed. The files hold coefficients, constants and tolerances only, no telemetry, so they
> may be shared and the circuit can be built from them **without the SWaT archive**. Anyone who
> holds SWaT regenerates them byte for byte with `.venv/bin/python zk/scripts/export_invariants.py --setting wide`.
> The integer reference model lives in `pafl/zk/fixed_point.py` (`integer_residuals`,
> `integer_applicable`, `integer_verdict`); `tests/test_zk_export.py` checks it against the float
> model on the simulated plant, and the export's own `checks` block records the same comparison on
> SWaT (max residual error 4e-5 tolerance units; 0 applicability or violation disagreements on
> 127,809 cells; batch verdicts agree on 50 honest and 50 channel-roll batches). Only Step 2
> (real batches) needs the licensed record.

**Target Script:** [`zk/scripts/export_invariants.py`](scripts/export_invariants.py)

Extract the affine parameter matrices ($`J_{\text{prev}}, J_{\text{cur}}, c`$) from `InvariantSet` using `affine_model(inv_set, df, columns)` in `pafl/attacks/adaptive.py`. Scale all floating-point values by $`S = 2^{16} = 65,536`$.

**Key Implementation Requirements:**
1. **Probe Row Assertion:** Assert `applicable_rows(inv_set, df).all(axis=1).any()` to guarantee intercept recovery is numerically valid.
2. **Noise Snapping:** Snap any derivative coefficient with magnitude $`|J_{j, d}| < 10^{-9} \cdot \max_k |J_{j, k}|`$ strictly to zero.
3. **Channel Guard:** Assert that every channel touched by the invariant set exists in `columns`.
4. **Quantization:**
   * $`\hat{J} = \lfloor S \cdot J \rceil`$
   * $`\hat{c} = \lfloor S^2 \cdot c \rceil`$
   * $`\hat{\epsilon} = \lfloor S^2 \cdot \epsilon \rceil + S`$ (includes a 1-LSB buffer for rounding tolerance)
5. **Output Format:** Save to `zk/data/invariants_swat_wide.json`.

---

### Step 2: Export Quantized Evaluation Batches
**Target Script:** [`zk/scripts/export_batches.py`](scripts/export_batches.py)

Extract four representative batches of length $`N = 1,024`$ from `build_variant` in `pafl/fl/variants.py`:
1. **Clean Honest Batch:** Telemetry from an uncompromised client.
2. **Gross Fabricated Batch:** Circular channel roll by 60 samples (5 minutes of plant time).
3. **Exposure Replay Batch (`splice_only`):** Real attack telemetry spliced into normal sequences.
4. **Projected Adaptive Batch:** Fabricated telemetry projected onto the invariant manifold.

Quantize channel readings as $`\hat{x} = \lfloor S \cdot x \rceil`$ and export to `zk/data/batches_swat.json`.

---

### Step 3: Implement Unit Tests for Numerical Parity
**Target Script:** [`tests/test_zk_export.py`](../../tests/test_zk_export.py)

Before writing circuits, verify in pure Python that the integer fixed-point model matches the 64-bit floating-point baseline:

```python
def test_quantized_residual_fidelity():
    """Residuals computed with integer arithmetic match float residuals to < 1e-5."""
    # Compare (J_prev * x_prev + J_cur * x_cur + c) / S^2 against inv_set.residuals()

def test_admission_decision_parity():
    """Batch pass/fail verdicts match InvariantSet.batch_verdict on >= 50 batches."""
    # Ensure zero false rejections on honest test batches

def test_channel_completeness():
    """All invariant channels exist in the scenario schema."""
```

Run test suite:
```bash
.venv/bin/python -m pytest tests/test_zk_export.py -v
```

---

### Step 4: Construct the Circom Circuits (Three Stages)
**Target Circuit:** [`zk/circuits/invariant_check.circom`](circuits/invariant_check.circom)

The circuit is parameterized by `(k, depth, n_inv, n_chan, stage)` and implemented in three progressive stages:

#### Stage 1: Physics Engine (Residuals & Applicability)
* Takes two consecutive quantized rows $`\hat{x}_{t-1}, \hat{x}_t`$.
* Evaluates actuator status gates:
  ```circom
  // Check if actuator was ON in both consecutive time steps
  component act_prev = IsEqual();
  component act_cur = IsEqual();
  ```
* Evaluates affine dot products: $`\hat{r}_j = \sum \hat{J}_{\text{prev}} \hat{x}_{t-1} + \sum \hat{J}_{\text{cur}} \hat{x}_t + \hat{c}_j`$.
* Evaluates 64-bit signed bounds check via offset $`K = 2^{60}`$:
  ```circom
  component range_check = Num2Bits(64);
  range_check.in <-- r + eps + K;
  ```
* Accumulates violation count ($`v`$) and inapplicable count ($`u`$).

#### Stage 2: Row Commitment (Two-Level Leaf Hashing)
* Partitions row into 18 invariant-active channels and 24 auxiliary channels.
* In-circuit: computes $`h_{\text{inv}} = \text{Poseidon}_{18}(x_1, \dots, x_{18})`$.
* Takes private input $`h_{\text{rest}} = \text{Poseidon}_{24}(x_{19}, \dots, x_{42})`$ (precomputed off-circuit).
* Computes row leaf: $`\text{leaf} = \text{Poseidon}_2(h_{\text{inv}}, h_{\text{rest}})`$.

#### Stage 3: Full Circuit (Merkle Authentication)
* Takes $`k`$ row indices $`\mathcal{I} = \{i_1, \dots, i_k\}`$.
* Decomposes each index $`i_m`$ into 10 path selection bits via `Num2Bits(10)`.
* Verifies Merkle inclusion path from $`\text{leaf}_i`$ to public root $`R`$.
* Enforces global assertions: $`v_{\text{total}} \le v_{\max}`$ and $`u_{\text{total}} \le u_{\max}`$.

---

### Step 5: Prover Input and Witness Generation
**Target Script:** [`zk/scripts/build_inputs.mjs`](scripts/build_inputs.mjs)

A Node.js script using `circomlibjs` to prepare the prover witness:
1. Loads quantized batch from `zk/data/batches_swat.json`.
2. Computes the 1,024-leaf Poseidon Merkle tree and extracts root $`R`$.
3. Derives $`k`$ challenge indices using the public nonce:
   ```javascript
   const idx = (Number(poseidon([root, nonce, m])) % (N - 1)) + 1;
   ```
4. Extracts Merkle authentication sibling paths for rows $`i`$ and $`i-1`$.
5. Formats and writes `zk/build/input.json`.

---

### Step 6: Automated End-to-End Benchmarking
**Target Script:** [`zk/scripts/run_bench.sh`](scripts/run_bench.sh)

An automated shell script executing compilation, setup, proving, and verification across sample sizes $`k \in \{8, 16, 32, 64\}`$:

```bash
#!/usr/bin/env bash
set -e

for k in 8 16 32 64; do
  echo "=== Running PA-FL Lite Benchmark for k = $k ==="
  
  # 1. Compile Circom circuit to R1CS
  circom zk/circuits/invariant_check.circom --r1cs --wasm -o zk/build/k$k -D k=$k
  
  # 2. SnarkJS Groth16 Setup
  snarkjs groth16 setup zk/build/k$k/invariant_check.r1cs zk/powersOfTau28_hez_final_20.ptau zk/build/k$k/circuit.zkey
  
  # 3. Export verification key
  snarkjs zkey export verification_key zk/build/k$k/circuit.zkey zk/build/k$k/verification_key.json
  
  # 4. Generate witness and proof for honest batch
  node zk/build/k$k/invariant_check_js/generate_witness.js zk/build/k$k/invariant_check_js/invariant_check.wasm zk/build/input.json zk/build/k$k/witness.wtns
  snarkjs groth16 prove zk/build/k$k/circuit.zkey zk/build/k$k/witness.wtns zk/build/k$k/proof.json zk/build/k$k/public.json
  
  # 5. Verify proof
  snarkjs groth16 verify zk/build/k$k/verification_key.json zk/build/k$k/public.json zk/build/k$k/proof.json
done
```

Collect all metrics into `zk/results.json`:
* R1CS constraint counts per stage
* Proving key (`.zkey`) size
* Witness generation runtime
* Prover runtime ($`t_{\text{prove}}`$)
* Verifier runtime ($`t_{\text{verify}}`$)
* Peak memory footprint (RSS)

---

### Step 7: Monte Carlo Soundness Sweeps
**Target Script:** [`zk/scripts/sample_check.py`](scripts/sample_check.py)

A standalone Python script evaluating empirical detection probability across varying sample sizes $`k`$ without requiring full zk proof generation:
* Evaluates detection rate over 10,000 independent draws against:
  1. Channel roll (shift = 60 rows)
  2. Exposure replay (`splice_only`)
  3. Projected adaptive attacker
* Validates that empirical detection rates align with the theoretical hypergeometric model:
  
  $$P(\text{Detection}) = 1 - (1 - \rho)^k$$

---

## 4. Work Schedule and Milestones

| Phase | Timeline | Core Focus | Milestone Exit Gate |
|:---|:---:|:---|:---|
| **Day A** | 0.5 Day | Toolchain setup, `powersOfTau` download, test circuit smoke test | Proof generates cleanly on minimal Poseidon test |
| **Day B** | 1.0 Day | Exporter scripts (`export_*.py`), `test_zk_export.py`, Circuit Stages 1 & 2 | Float parity test passes; Stage 2 compiles under budget |
| **Day C** | 1.0 Day | Stage 3 Merkle circuit, $`k \in \{8, 16, 32, 64\}`$ sweep, attack validation | Honest batch proves; fabricated batch hard-aborts |
| **Day D** | 0.5 Day | Populate `results.json`, format LaTeX table for Section 5 of manuscript | Manuscript results table finalized |

### Fallback Cut-Off Dates
* **Saturday 19 September:** Prover execution cut-off. If proof generation encounters memory bottlenecks at $`k = 64`$, report exact compiled constraint counts and theoretical proving bounds from Stages 1 and 2.
* **Wednesday 23 September:** Compilation cut-off. If circuit bugs delay Stage 3, fall back to the analytic constraint estimate and present PA-FL Lite as an architectural specification.

---

## 5. Acceptance Checklist

- [ ] `pytest tests/test_zk_export.py -v` passes with zero failures.
- [ ] Stage 1, 2, and 3 constraint counts recorded separately for the paper's ablation table.
- [ ] Honest test batch produces proof that passes `snarkjs groth16 verify`.
- [ ] Projected adaptive batch produces proof that passes `snarkjs groth16 verify`.
- [ ] Fabricated channel-roll batch triggers an unresolvable constraint exception during witness generation.
- [ ] `zk/results.json` populated with measured proving and verification runtimes.
- [ ] Manuscript Section 5 updated with measured numbers replacing the back-of-the-envelope estimates.
