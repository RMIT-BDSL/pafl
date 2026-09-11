# PA-FL Lite: Zero-Knowledge Verification of Process Invariants in Federated Learning

**System Design, Cryptographic Formulation, Implementation Plan, and Empirical Evaluation Protocol**

*Document Status: Active Implementation Plan*  
*Target Submission: MDPI Information (Special Issue on Security and Privacy in Federated Learning)*  
*Associated Progress Logs: [`LOG.md`](../LOG.md) | Strategic Decisions: [`PLAN-to-DATE.md`](../PLAN-to-DATE.md) §5*

---

## 1. Executive Summary and Problem Context

### 1.1 The Privacy-Verifiability Paradox in Federated Cyber-Physical Systems
In the empirical investigations conducted throughout this research project, the physical invariant admission gate is evaluated directly on unencrypted client telemetry batches (via `InvariantSet.batch_verdict`). In that experimental configuration, the central server inspects the raw sensor and actuator time series of each participating client to verify adherence to conservation laws and actuator couplings prior to model aggregation.

While direct evaluation establishes the statistical validity of physics-guided filtering against data-space poisoning attacks (e.g., channel roll, within-regime shuffling, and manifold projection), it introduces an untenable architectural premise: **it requires federated clients to transmit their raw operational telemetry to the central coordinator**.

In critical cyber-physical infrastructure—such as municipal water treatment facilities, regional power distribution grids, and petrochemical plants—operational telemetry constitutes highly sensitive, proprietary, and security-critical information:
1. **Confidentiality and National Security:** Disclosing sensor streams reveals operational capacity, production schedules, chemical dosing recipes, and momentary vulnerabilities to external entities or untrusted central servers.
2. **Regulatory Mandates:** Data protection regulations and corporate compliance standards strictly forbid sharing raw industrial operational technology (OT) data outside the security perimeter of the plant.
3. **Core Tenet of Federated Learning:** The fundamental motivation for adopting federated learning over centralized machine learning is to enable collaborative model training *without* centralizing proprietary raw datasets.

Consequently, evaluating admission control directly on raw data creates a fundamental paradox: **to protect the global model from data poisoning, the server must violate the very privacy guarantee that motivated federated learning in the first place.**

```
+----------------------------------------------------------------------------------------------------+
|                               THE PRIVACY-VERIFIABILITY PARADOX                                    |
|                                                                                                    |
|  Direct Invariant Inspection (Evaluated Baseline)                                                  |
|  Client Telemetry  ================ [ RAW DATA TRANSMISSION ] ================> Aggregator        |
|  Result: Perfect admission control, but TOTAL LOSS OF DATA CONFIDENTIALITY.                        |
|                                                                                                    |
|  Standard Federated Learning (Vulnerable)                                                          |
|  Client Telemetry  ---- [ Local Training ] ----> Parameter Update (dw) ---------> Aggregator        |
|  Result: High data privacy, but TOTAL BLINDNESS TO DATA POISONING & FABRICATION.                   |
|                                                                                                    |
|  PA-FL Lite: Zero-Knowledge Invariant Attestation (This Work)                                      |
|  Client Telemetry  --+-> [ Local Training ] --------------> Parameter Update (dw) -> Aggregator    |
|                      |                                                                             |
|                      +-> [ Merkle Tree & zk-SNARK Prover ] -> Proof pi & Root R  -> Aggregator    |
|                          (Poseidon Commitment + Invariant Satisfaction)            (Public Verify) |
|  Result: ZERO DATA LEAKAGE + CRYPTOGRAPHICALLY GUARANTEED PHYSICAL COMPLIANCE.                     |
+----------------------------------------------------------------------------------------------------+
```

### 1.2 Objective of PA-FL Lite
**PA-FL Lite** resolves this paradox by providing a cryptographic proof of physical invariant compliance. Using zero-knowledge succinct non-interactive arguments of knowledge (**zk-SNARKs**), a federated client proves to the aggregator that:
1. It has committed to a private local training batch via a collision-resistant Merkle tree.
2. Across a cryptographically sampled subset of time steps, the private telemetry satisfies the declared physical process invariants within an admissible engineering tolerance.
3. It respects both an invariant violation budget ($v$) and an inapplicability budget ($u$), preventing adversarial evasion.

Crucially, this attestation is verified in milliseconds without disclosing any individual sensor measurement, actuator state, or operational timestamp. PA-FL Lite directly addresses **Research Question 2 (RQ2)** of the submission, transitioning the enforcement mechanism from a theoretical design concept into a concrete, benchmarked system running on standard arithmetic circuits.

---

## 2. Cryptographic Formulation and Proof Semantics

### 2.1 Formal Statement of the Relation
Let $N = 1,024$ denote the batch size (temporal sequence length), and let $D$ denote the number of operational channels (sensors and actuators) monitored at each time step. The private witness held by the client prover is a matrix of unscaled operational telemetry:
$$X = [x_1, x_2, \dots, x_N]^T \in \mathbb{R}^{N \times D}$$

The telemetry batch is committed to the aggregation server as a cryptographic Merkle root $R \in \mathbb{F}_p$, where $\mathbb{F}_p$ is the scalar field of the BN128 (alt_bn128) elliptic curve ($p \approx 2^{254}$), using the arithmetic-efficient **Poseidon hash function**.

Let $\mathcal{M} = \{1, \dots, M\}$ denote the index set of $M$ declared physical process invariants mined from clean operational baselines. Following the commitment of $R$, a pseudo-random challenge set of $k$ distinct row indices $\mathcal{I} = \{i_1, i_2, \dots, i_k\} \subset \{2, \dots, N\}$ is derived (via verifier challenge or the Fiat-Shamir heuristic).

The zero-knowledge circuit proves knowledge of the private telemetry matrix $X$ and associated Merkle authentication paths satisfying the relation:

$$\mathcal{R}_{\text{PA-FL}} = \big\lbrace (\mathbb{x}, \mathbb{w}) \;\big|\; \mathcal{C}(\mathbb{x}, \mathbb{w}) = 1 \big\rbrace$$

where the public instance $\mathbb{x}$ and private witness $\mathbb{w}$ are defined as:
* **Public Instance ($\mathbb{x}$):**
  $$\mathbb{x} = \big(R, \, \mathcal{I}, \, \hat{J}, \, \hat{c}, \, \hat{\epsilon}, \, v_{\max}, \, u_{\max}\big)$$
* **Private Witness ($\mathbb{w}$):**
  $$\mathbb{w} = \big(\{x_{i-1}, x_i\}_{i \in \mathcal{I}}, \, \{\text{path}_i\}_{i \in \mathcal{I}}\big)$$

and the constraint system $\mathcal{C}(\mathbb{x}, \mathbb{w}) = 1$ enforces four simultaneous conditions:
1. **Merkle Authentication Path Validity:** Every sampled row $x_i$ is anchored to root $R$:
   $$\forall i \in \mathcal{I}: \quad \text{MerkleVerify}(R, \, \text{leaf}(x_i), \, \text{path}_i) = \text{true}$$
2. **Conditional Invariant Satisfaction:** For every evaluated invariant $j \in \mathcal{M}$, if active, the residual is bounded by $\hat{\epsilon}_j$:
   $$\forall i \in \mathcal{I}, \; \forall j \in \mathcal{M}: \quad \text{Applicable}_j(x_{i-1}, x_i) \implies |\hat{r}_{j, i}| \le \hat{\epsilon}_j$$
3. **Bounded Violation Budget:** Active violations across the sample cannot exceed $v_{\max}$:
   $$\sum_{i \in \mathcal{I}} \sum_{j \in \mathcal{M}} \mathbb{I}\big(\text{Applicable}_j(x_{i-1}, x_i) \land (|\hat{r}_{j, i}| > \hat{\epsilon}_j)\big) \le v_{\max}$$
4. **Bounded Inapplicability Budget:** Inapplicable rule evaluations cannot exceed $u_{\max}$:
   $$\sum_{i \in \mathcal{I}} \sum_{j \in \mathcal{M}} \mathbb{I}\big(\neg\text{Applicable}_j(x_{i-1}, x_i)\big) \le u_{\max}$$

### 2.2 Scope Boundary: Data Attestation vs. Gradient Binding
It is critical to establish the exact cryptographic boundary of PA-FL Lite for the paper's methodology:

* **What PA-FL Lite Proves (In Scope):** The prover demonstrates that the committed training batch $X$ consists of physical telemetry adhering to declared conservation laws and operational logic.
* **What PA-FL Lite Defers (Future Extension):** PA-FL Lite does **not** bind the client's submitted neural network gradient update $\Delta w$ to the batch $X$ in-circuit. Proving full backward propagation for a deep neural autoencoder inside an arithmetic circuit requires tens of millions of Rank-1 Constraint System (R1CS) constraints, which is computationally impractical for edge industrial PLCs or industrial IoT gateways.

In the submission draft, this boundary is clearly stated in the methodology section: PA-FL Lite provides verifiable admission control over the data manifold; last-layer gradient binding (e.g., verifying $\Delta w_{\text{last}} = \nabla_{w_{\text{last}}} \mathcal{L}(X)$) is documented as an orthogonal cryptographic extension.

---

## 3. Detailed Circuit Architecture and Engineering

### 3.1 Affine Invariant Formulation
Every mined physical invariant in the `pafl` framework (differential mass/flow balances and steady-state actuator couplings) is affine with respect to adjacent operational states:
$$r_j(x_{t-1}, x_t) = J_{\text{prev}, j} \cdot x_{t-1} + J_{\text{cur}, j} \cdot x_t + c_j$$

where $J_{\text{prev}, j}, J_{\text{cur}, j} \in \mathbb{R}^{1 \times D}$ denote the sensitivity coefficients for time steps $t-1$ and $t$, and $c_j \in \mathbb{R}$ is the invariant intercept.

Rather than parsing internal object closures, the export pipeline extracts these matrices directly using `affine_model(inv_set, df, columns)` from `pafl/attacks/adaptive.py`, which returns the global Jacobian block $J \in \mathbb{R}^{M \times 2D}$ and constant vector $c \in \mathbb{R}^M$.

#### Extraction Safeguards and Validation Guards
To ensure numerical stability and semantic fidelity in the zero-knowledge circuit, the exporter enforces three mandatory pre-conditions:
1. **Probe Row Feasibility:** It asserts `applicable_rows(inv_set, df).all(axis=1).any()`. Because `affine_model` recovers intercept $c$ by sampling a probe row, the absence of a universally applicable row would silently yield incorrect offsets.
2. **Finite-Difference Noise Truncation:** Numerical artifacts arising from empirical finite-difference differentiation ($|J_{j, d}| < 10^{-9} \cdot \max_k |J_{j, k}|$) are snapped strictly to zero, preventing spurious non-zero multiplications in the circuit.
3. **Channel Set Completeness:** It asserts that every operational channel referenced by the invariant set exists in the selected `columns` array. Mined invariant sets on unfiltered telemetry must not reference auxiliary channels (e.g., chemical analyzers) excluded from the model's feature space.

### 3.2 Fixed-Point Quantization in Prime Field $\mathbb{F}_p$
Arithmetic circuits operate natively over the prime field $\mathbb{F}_p$ where $p = 21888242871839275222246405745257275088548364400416034343698204186575808495617$. Because division and floating-point representations are prohibitively expensive in R1CS, all continuous quantities are scaled into integer representations using a fixed-point scale factor:
$$S = 2^{16} = 65,536$$

Quantized parameters and variables are defined as:
$$\hat{x} = \lfloor S \cdot x \rceil, \quad \hat{J} = \lfloor S \cdot J \rceil, \quad \hat{c} = \lfloor S^2 \cdot c \rceil$$

Evaluating the quantized residual preserves exact scaling at order $S^2 = 2^{32}$:
$$\hat{r} = \hat{J}_{\text{prev}} \cdot \hat{x}_{t-1} + \hat{J}_{\text{cur}} \cdot \hat{x}_t + \hat{c}$$

#### Dynamic Range and Overflow Prevention
Field arithmetic wrap-around constitutes a catastrophic vulnerability in cryptographic circuits. We establish strict dynamic range bounds based on empirical SWaT telemetry:
* Maximum continuous sensor measurement: $x_{\max} \approx 1,015.0 \implies \hat{x} \approx 6.65 \times 10^7 < 2^{26}$.
* Maximum sensitivity coefficient: $|J|_{\max} \approx 8.90 \implies |\hat{J}| \approx 5.83 \times 10^5 < 2^{20}$.
* Individual product term: $|\hat{J} \cdot \hat{x}| < 2^{46}$.
* Across the 9 invariants of the wide SWaT set, the sum of product terms does not exceed $9 \times 2^{46} < 2^{50} \ll p$.
* The smallest non-zero coefficient ($0.0097$) quantizes to $\lfloor 65536 \times 0.0097 \rceil = 636$ units, ensuring a quantization error strictly below $0.08\%$.

Signed comparisons ($-\hat{\epsilon} \le \hat{r} \le \hat{\epsilon}$) are computed using a constant offset $K = 2^{60}$:
$$0 \le \hat{r} + \hat{\epsilon} + K < 2^{61}$$
This enables the use of efficient 64-bit unsigned range checks (`Num2Bits(64)`), requiring exactly 64 constraints per bounded term.

### 3.3 Dual-Budget Gate: Invariant Violations and Inapplicability Attacks
A critical feature of cyber-physical invariants is that relational couplings are state-dependent. For example, the hydraulic coupling between pump status and flow rate applies only during steady-state operation:
$$\text{Applicable}(x_{t-1}, x_t) \iff (\text{Pump}_{t-1} = \text{ON}) \land (\text{Pump}_t = \text{ON})$$

If an actuator is undergoing a transition or is in an OFF state, the invariant is rendered inapplicable, and the row passes by default.

```
+----------------------------------------------------------------------------------------------------+
|                             DUAL-BUDGET VERIFICATION GATE PER SAMPLE                              |
|                                                                                                    |
|                 [ Telemetry Rows: x(t-1), x(t) ]                                                   |
|                                |                                                                   |
|          +---------------------+---------------------+                                             |
|          |                                           |                                             |
|          v                                           v                                             |
|   [ Actuator Status ]                        [ Invariant Math ]                                    |
|   Is actuator steady state?                  r = J_prev*x(t-1) + J_cur*x(t) + c                    |
|   (A(t-1) == ON && A(t) == ON)                               |                                     |
|          |                                                   |                                     |
|     NO   |   YES                                             v                                     |
|    +-----+-----+                             Is |r| <= epsilon?                                    |
|    |           |                                     |                                             |
|    |           v                                YES  |  NO                                         |
|    |     Evaluate Check                     +--------+--------+                                    |
|    |           |                            |                 |                                    |
|    |           +--------------------------->| PASS            v VIOLATION                          |
|    v INAPPLICABLE                                         Increment v_count                        |
|   Increment u_count                                           |                                    |
|    |                                                          |                                    |
|    +------------------------+---------------------------------+                                    |
|                             v                                                                      |
|        Assert (v_count <= v_max) AND (u_count <= u_max)                                            |
+----------------------------------------------------------------------------------------------------+
```

#### Mitigating the Actuator-Toggling Evasion Attack
If the circuit evaluated only a violation budget $v$, an informed adversary could trivially evade detection by toggling actuator state bits between 0 and 1 at alternating time steps ($A_t \neq A_{t-1}$). This would render all couplings inapplicable, permitting arbitrary data manipulation across the remaining continuous channels without triggering any invariant violation.

PA-FL Lite prevents this loophole by enforcing **two independent constraint budgets**:
1. **Violation Budget ($v_{\max}$):** Tolerates small sensor anomalies and unmodeled hydraulic friction.
2. **Inapplicability Budget ($u_{\max}$):** Enforces that the total number of inapplicable rule evaluations cannot exceed baseline plant operational norms.

### 3.4 Two-Level Leaf Hashing Optimization
In industrial testbeds such as SWaT, an operational telemetry vector contains $D = 42$ continuous and discrete channels (after excluding redundant status channels). Hashing 42 field elements directly in an arithmetic circuit via standard Poseidon permutation requires multiple sponge absorptions, consuming over 1,500 R1CS constraints per leaf.

PA-FL Lite introduces a **two-level leaf hashing architecture**:
* Across the 9 invariants of the wide SWaT set, only $D_{\text{inv}} = 18$ distinct channels are actively referenced by invariant constraints.
* The remaining $D_{\text{rest}} = 24$ channels do not participate in invariant evaluations.

The leaf commitment is structured as:
$$h_{\text{inv}, i} = \text{Poseidon}_{18}\big(x_{i, 1}, \dots, x_{i, 18}\big)$$
$$h_{\text{rest}, i} = \text{Poseidon}_{24}\big(x_{i, 19}, \dots, x_{i, 42}\big) \quad (\text{Precomputed off-circuit by prover})$$
$$\text{leaf}_i = \text{Poseidon}_2\big(h_{\text{inv}, i}, h_{\text{rest}, i}\big)$$

Inside the zero-knowledge circuit, the prover supplies $h_{\text{rest}, i}$ as an opaque private input. The circuit only pays the arithmetic constraint cost to hash the 18 active channels plus one 2-to-1 compression, saving approximately $55\%$ of in-circuit leaf hashing overhead while guaranteeing complete cryptographic binding of the full operational row.

---

## 4. Modular Circuit Construction and Staged Verification

To systematically isolate constraint costs and ensure continuous progress toward publication milestones, the circuit is implemented and benchmarked across **three modular stages**:

| Stage | Subcircuits Included | What It Proves | Scientific Purpose |
|:---:|:---|:---|:---|
| **Stage 1** | Fixed-point affine residual calculation, applicability logic, dual-budget accumulators | Telemetry satisfies physical invariants within tolerance | Measures the pure computational cost of physics logic in R1CS |
| **Stage 2** | Stage 1 + Two-level Poseidon leaf hashing for row pairs $(x_{i-1}, x_i)$ | Physics holds on committed telemetry rows | Measures the cost of row commitment and cryptographic binding |
| **Stage 3** | Stage 2 + Merkle tree authentication paths ($k$ inclusion proofs to root $R$) | Full end-to-end attestation of batch $X$ | Final deployable circuit; validates total client proving cost |

```
+----------------------------------------------------------------------------------------------------+
|                                 STAGE 3 FULL CIRCUIT TOPOLOGY                                      |
|                                                                                                    |
|  PUBLIC INPUTS:  Merkle Root R | Challenge Indices I | Quantized Invariants (J, c, eps, v_max, u_max) |
|                                                                                                    |
|  FOR EACH SAMPLE INDEX i in {1, ..., k}:                                                           |
|                                                                                                    |
|   +---------------------------------------+   +---------------------------------------+            |
|   |          ROW (i-1) WITNESS            |   |           ROW (i) WITNESS             |            |
|   |  x(i-1)[1..18]   |  h_rest(i-1)       |   |  x(i)[1..18]     |  h_rest(i)         |            |
|   +--------|------------------|-----------+   +--------|------------------|-----------+            |
|            |                  |                        |                  |                        |
|            v                  v                        v                  v                        |
|       Poseidon_18        (Opaque Input)           Poseidon_18        (Opaque Input)                |
|            \                  /                        \                  /                        |
|             v                v                          v                v                         |
|            Poseidon_2 (Leaf i-1)                       Poseidon_2 (Leaf i)                         |
|                     |                                           |                                  |
|                     v                                           v                                  |
|       +---------------------------+               +---------------------------+                    |
|       |  Merkle Auth Path i-1     |               |   Merkle Auth Path i      |                    |
|       |  Depth = 10 (Poseidon_2)  |               |   Depth = 10 (Poseidon_2) |                    |
|       +-------------|-------------+               +-------------|-------------+                    |
|                     |                                           |                                  |
|                     +---------------------+---------------------+                                  |
|                                           |                                                        |
|                                           v                                                        |
|                             Assert Computed Root == R                                              |
|                                                                                                    |
|   +-----------------------------------------------------------------------------------+            |
|   |                             PHYSICS INVARIANT ENGINE                              |            |
|   |                                                                                   |            |
|   |   For each invariant j in {1..M}:                                                 |            |
|   |     1. Check Applicability Predicate on Actuators                                 |            |
|   |     2. Compute Affine Residual: r_j = J_prev*x(i-1) + J_cur*x(i) + c              |            |
|   |     3. Check |r_j| <= eps_j via 64-bit Offset Range Proof                         |            |
|   |     4. Accumulate Violations (v_count) and Inapplicable Rules (u_count)           |            |
|   +-----------------------------------------------------------------------------------+            |
|                                                                                                    |
|  GLOBAL ACCUMULATOR CHECKS:                                                                        |
|    Assert sum(v_count) <= v_max                                                                    |
|    Assert sum(u_count) <= u_max                                                                    |
+----------------------------------------------------------------------------------------------------+
```

---

## 5. Directory Structure and Component Mapping

All implementation files reside under `zk/` and the project root:

```
pafl/
├── zk/
│   ├── PLAN.md                             # This architectural specification
│   ├── README.md                           # Quick-start documentation and summary
│   ├── package.json                        # Node dependencies (circomlib, circomlibjs)
│   ├── circuits/
│   │   ├── invariant_check.circom          # Core parameterized Circom circuit (Stages 1–3)
│   │   ├── affine_residual.circom          # Subcircuit: Fixed-point affine evaluator
│   │   ├── applicability.circom            # Subcircuit: Actuator status equality gates
│   │   └── merkle_verify.circom            # Subcircuit: Poseidon binary tree verifier
│   ├── scripts/
│   │   ├── export_invariants.py            # Converts InvariantSet -> fixed-point JSON
│   │   ├── export_batches.py               # Generates quantized test batches (Clean, Roll, Spliced)
│   │   ├── sample_check.py                 # Pure Python Monte Carlo validation of soundness vs k
│   │   ├── build_inputs.mjs                # Computes Merkle tree, challenges, and snarkjs input.json
│   │   └── run_bench.sh                    # Automated end-to-end benchmark script
│   └── results.json                        # Complete empirical measurements for the paper
└── tests/
    └── test_zk_export.py                   # Pytest suite: Quantization fidelity and round-trips
```

---

## 6. Implementation Schedule and Milestones

| Timeline | Phase | Deliverables and Core Activities | Milestone Exit Gate |
|:---|:---|:---|:---|
| **Day A** *(0.5 Day)* | **Environment & Toolchain Setup** | Initialize `zk/package.json` (`circomlib`, `circomlibjs`). Download Powers of Tau ceremony file (`powersOfTau28_hez_final_20.ptau`, 2.4 GB, supporting $2^{20} \approx 1.05 \times 10^6$ constraints). Compile a minimal two-input Poseidon proof to validate the local compiler toolchain. | `snarkjs groth16 prove` succeeds end-to-end on test circuit. |
| **Day B** *(1.0 Day)* | **Export Pipeline & Stages 1–2** | Implement `export_invariants.py` and `export_batches.py` with strict numeric guards. Write and pass `tests/test_zk_export.py`. Implement Stage 1 and Stage 2 in `invariant_check.circom`. Unit-test at $k = 4$ on simulated benchmark telemetry. | Python exporter matches float verdicts on 50 batches; Stages 1–2 compile cleanly. |
| **Day C** *(1.0 Day)* | **Stage 3 & Parameter Sweep** | Implement Stage 3 (Merkle paths). Execute parameter sweep across $k \in \{8, 16, 32, 64\}$ using the wide SWaT invariant set. Execute `sample_check.py` against honest, channel-roll, and replay attack batches. Record proof generation times, verifier times, and peak memory in `results.json`. | Successful proof generation for honest and projected batches; hard failure on fabricated batch. |
| **Day D** *(0.5 Day)* | **Paper Integration & Analysis** | Draft PA-FL Lite subsection for Section 5 of the manuscript. Format measured benchmark table. If schedule permits, compute theoretical on-chain verification gas costs for Hyperledger Fabric and Stellar Soroban. | Manuscript section and LaTeX tables finalized. |

### Hard Fallback Deadlines
To prevent scope creep from impacting the overall submission schedule:
* **Saturday 19 September:** Prover execution cut-off. If the full end-to-end prover encounters unexpected memory or setup bottlenecks, report compiled constraint counts and theoretical proving bounds from Stages 1 and 2.
* **Wednesday 23 September:** Compilation cut-off. If unforeseen circuit bugs impede Stage 3 compilation, retain the existing paper design estimate and present PA-FL Lite as an architectural specification.

---

## 7. Soundness Analysis and Sample Sizing ($k$)

### 7.1 Analytic Soundness Formulation
In a batch of $N = 1,024$ consecutive operational rows, let $\rho \in [0, 1]$ denote the fraction of time steps containing physical invariant violations induced by an attack:
$$\rho = \frac{N_{\text{violated}}}{N}$$

When the verifier samples $k$ independent time steps uniformly at random without replacement, the probability that an adversary with violation density $\rho$ evades detection (assuming an allowable violation budget of $v = 0$) is bounded by the hypergeometric tail:
$$P(\text{Evasion}) = \prod_{m=0}^{k-1} \frac{N(1 - \rho) - m}{N - m} \approx (1 - \rho)^k$$

The detection probability (soundness) is therefore:
$$P(\text{Detection}) = 1 - P(\text{Evasion}) \approx 1 - (1 - \rho)^k$$

### 7.2 Detection Regimes Across Real Attack Taxonomies
Our empirical characterization of industrial attacks on the SWaT testbed reveals two distinct operational regimes:

1. **Gross Telemetry Fabrication (Channel Roll / Permutation):**
   * Under the wide invariant set (9 rules), circular channel rolling disrupts cross-channel dependencies across approximately $\rho \approx 30\%$ of all rows.
   * At $k = 16$, detection probability exceeds:
     $$P(\text{Detection}) = 1 - (1 - 0.30)^{16} = 1 - 0.0033 = 99.67\%$$
   * At $k = 32$, detection confidence reaches $99.999\%$. Gross fabrication is definitively blocked with minimal sampling overhead.

2. **Exposure-Only Replay Attacks (`splice_only`):**
   * In replay attacks, the adversary splices genuine recorded attack telemetry into an honest training window. Because the recorded telemetry corresponds to actual physical operation (albeit during an attack), it violates only a narrow subset of invariants ($\rho \approx 1.5\%$).
   * At $k = 16$:
     $$P(\text{Detection}) = 1 - (1 - 0.015)^{16} \approx 21.5\%$$
   * At $k = 64$:
     $$P(\text{Detection}) = 1 - (1 - 0.015)^{64} \approx 62.1\%$$

```
+----------------------------------------------------------------------------------------------------+
|                         SOUNDNESS DETECTION PROBABILITY vs. SAMPLE SIZE (k)                        |
|                                                                                                    |
|  Detection Probability P(D)                                                                        |
|  100% |============================================================  Fabrication (rho = 30%)       |
|       |                     *                                                                      |
|   80% |                    *                                                                       |
|       |                   *                                                                        |
|   60% |                  *                           ---------------- Replay (rho = 1.5%)          |
|       |                 *                -----------                                               |
|   40% |                *      -----------                                                          |
|       |               * ------                                                                     |
|   20% |        -------*                                                                            |
|       |  ------       *                                                                            |
|    0% +-------+---------------+---------------+---------------+-->                                |
|             k = 8           k = 16          k = 32          k = 64   Sample Size                   |
+----------------------------------------------------------------------------------------------------+
```

This mathematical asymmetry is an essential finding: **sampling is highly efficient against fabricated telemetry, but provides probabilistic protection against physical replay attacks**. This aligns directly with the empirical coverage results reported in the main body of the paper.

---

## 8. Verification Protocol and Acceptance Criteria

Execution of the experimental pipeline must satisfy the following verifiable criteria:

1. **Python Numerical Parity Test:**
   ```bash
   pytest tests/test_zk_export.py -v
   ```
   * *Criterion:* Integer fixed-point residual evaluations must match 64-bit floating-point residuals from `InvariantSet.residuals` to within $10^{-5}$ relative error across $\ge 50$ SWaT batches.
   * *Criterion:* All channels referenced in exported invariant matrices must be strictly present in the active dataset schema.

2. **Circuit Compilation and Benchmark Generation:**
   ```bash
   bash zk/scripts/run_bench.sh
   ```
   * *Criterion:* Completes compilation, witness generation, proof creation, and verification for $k \in \{8, 16, 32, 64\}$.
   * *Criterion:* Populates `zk/results.json` with constraint counts, compilation durations, proving runtimes, verification times, proof sizes, and peak RSS memory.

3. **Cryptographic Proof Validation:**
   * `snarkjs groth16 verify` returns `OK` for clean honest batches.
   * `snarkjs groth16 verify` returns `OK` for post-projection adaptive batches.
   * Witness generation fails with an unresolvable constraint exception when evaluated on unmitigated channel-roll batches, confirming that fraudulent telemetry cannot be proven.

4. **Regression Integrity:**
   ```bash
   .venv/bin/python -m pytest tests/ -q
   ```
   * *Criterion:* Zero regressions in the existing repository test suite.

---

## 9. Risk Register and Mitigation Strategies

| Risk Description | Severity | Likelihood | Technical Mitigation Strategy |
|:---|:---:|:---:|:---|
| **Constraint Explosion at $k = 64$:** Stage 3 constraint count exceeds the $2^{20} = 1,048,576$ Powers of Tau threshold. | High | Medium | The two-level leaf optimization reduces leaf hashing by $\approx 55\%$. If Stage 3 exceeds $2^{20}$, report $k = 64$ under Stage 2 (where inclusion is verified via batch multi-proof) and state the boundary condition in the text. |
| **Out-of-Memory (OOM) During Prover Key Generation:** Node.js process crashes during `snarkjs groth16 setup`. | Medium | Low | Execute Node with expanded heap allocation: `NODE_OPTIONS="--max-old-space-size=32768"`. The M3 development workstation provides 36 GiB of unified memory. |
| **Quantization Discrepancies Near Boundaries:** Rounding artifacts near $\epsilon$ cause borderline honest batches to fail. | Medium | Low | Calibrate fixed-point epsilon threshold $\hat{\epsilon} = \lfloor S^2 \cdot \epsilon \rceil + S$, adding an exact 1-LSB tolerance buffer to absorb quantization truncation. |
| **Prover Toolchain Delay:** Integration delays prevent end-to-end proof execution before the paper milestone. | Critical | Low | Enforce strict cut-line: fall back to compiled R1CS constraint counts (Stages 1 and 2), which provide exact algebraic complexity numbers without requiring live proof generation. |
