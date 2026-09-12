# PA-FL Lite: Cryptographic Formalization and System Specification

**A Zero-Knowledge Protocol for Physics-Attested Admission Control in Federated Learning**

*Theoretical Reference Document for the PA-FL Framework*  
*Companion Implementation Tutorial: [`PLAN.md`](PLAN.md) | Progress Tracking: [`../LOG.md`](../LOG.md)*

---

## 1. Problem Formulation: The Privacy-Verifiability Paradox

In cyber-physical systems (CPS) governed by industrial control networks—such as water treatment plants, power grids, and chemical refineries—federated learning (FL) enables distributed anomaly detection models to be trained across multiple sites without centralizing proprietary operational telemetry.

However, existing Byzantine-robust federated defenses operate almost exclusively in **update space** (e.g., Krum, Trimmed Mean, Coordinate-wise Median, FLTrust). These defenses are fundamentally blind to data poisoning that mimics honest update geometry (e.g., fabricated telemetry, circular channel rolling, or manifold-projected attacks).

While directly inspecting client raw telemetry batches (`InvariantSet.batch_verdict`) successfully detects physical invariant violations, it introduces a severe privacy violation: **it forces participants to transmit confidential sensor and actuator readings to the central aggregator**, contradicting the core premise of federated learning.

```
+----------------------------------------------------------------------------------------------------+
|                               THE PRIVACY-VERIFIABILITY PARADOX                                    |
|                                                                                                    |
|  1. Direct Telemetry Inspection (Evaluated Empirical Baseline)                                     |
|     Client Telemetry  ================ [ RAW DATA TRANSMISSION ] ================> Aggregator     |
|     Result: Perfect physical admission control, but TOTAL LOSS OF DATA CONFIDENTIALITY.            |
|                                                                                                    |
|  2. Standard Federated Learning (Vulnerable to Data Poisoning)                                     |
|     Client Telemetry  ---- [ Local Training ] ----> Parameter Delta (dw) ---------> Aggregator     |
|     Result: Preserves data confidentiality, but TOTAL BLINDNESS TO DATA FABRICATION.               |
|                                                                                                    |
|  3. PA-FL Lite: Zero-Knowledge Invariant Attestation (This Work)                                   |
|     Client Telemetry  --+-> [ Local Training ] --------------> Parameter Delta (dw) -> Aggregator |
|                         |                                                                          |
|                         +-> [ Merkle Tree & zk-SNARK Prover ] -> Proof pi & Root R  -> Aggregator |
|                             (Poseidon Commitment + Invariant Satisfaction)         (Public Verify) |
|     Result: ZERO DATA LEAKAGE + CRYPTOGRAPHICALLY GUARANTEED PHYSICAL COMPLIANCE.                  |
+----------------------------------------------------------------------------------------------------+
```

PA-FL Lite resolves this paradox using zero-knowledge succinct non-interactive arguments of knowledge (**zk-SNARKs**). A participating client proves to the aggregator that its private training batch satisfies declared physical conservation laws and operational logic without revealing any individual measurement, actuator state, or timestamp.

---

## 2. Cryptographic Protocol and Relation Definition

### 2.1 Protocol Entities and Parameters
* **Federated Client (Prover $`\mathcal{P}`$):** Holds a private local batch of unscaled industrial telemetry:

$$X = [x_1, x_2, \dots, x_N]^T \in \mathbb{R}^{N \times D}$$

where $`N = 1,024`$ denotes the batch sequence length and $`D`$ denotes the number of operational channels.
* **Federated Aggregator (Verifier $`\mathcal{V}`$):** Holds the public model parameters, declared physical invariants $`\mathcal{M} = \{1, \dots, M\}`$, and admission thresholds.
* **Cryptographic Curve:** The BN128 (alt_bn128) pairing-friendly elliptic curve over scalar prime field $`\mathbb{F}_p`$ ($`p \approx 2^{254}`$).
* **Hash Primitive:** The arithmetic-friendly **Poseidon hash function** configured over $`\mathbb{F}_p`$.

### 2.2 Formal Zero-Knowledge Relation
The client commits to batch $`X`$ by constructing a binary Merkle tree of depth $`\log_2(N) = 10`$ using Poseidon hashing and publishing the root $`R \in \mathbb{F}_p`$. 

Following commitment, a challenge set of $`k`$ distinct row indices $`\mathcal{I} = \{i_1, \dots, i_k\} \subset \{2, \dots, N\}`$ is derived (via verifier challenge or the Fiat-Shamir heuristic).

The zero-knowledge relation $`\mathcal{R}_{\text{PA-FL}}`$ is formally defined as:

$$\mathcal{R}_{\text{PA-FL}} = \big\lbrace (\mathbb{x}, \mathbb{w}) \;\big|\; \mathcal{C}(\mathbb{x}, \mathbb{w}) = 1 \big\rbrace$$

where the public instance $`\mathbb{x}`$ and private witness $`\mathbb{w}`$ are:

* **Public Instance ($`\mathbb{x}`$):**

$$\mathbb{x} = \big(R, \mathcal{I}, \hat{J}, \hat{c}, \hat{\epsilon}, v_{\max}, u_{\max}\big)$$

* **Private Witness ($`\mathbb{w}`$):**

$$\mathbb{w} = \big(\lbrace x_{i-1}, x_i \rbrace_{i \in \mathcal{I}}, \lbrace \text{path}_i \rbrace_{i \in \mathcal{I}}\big)$$

The arithmetic circuit $`\mathcal{C}(\mathbb{x}, \mathbb{w}) = 1`$ enforces four simultaneous constraints:

**1. Merkle Inclusion Proof:** Every sampled row $`x_i`$ is a valid leaf of the Merkle tree committed under root $`R`$:

$$\forall i \in \mathcal{I}: \quad \text{MerkleVerify}(R, \text{leaf}(x_i), \text{path}_i) = \text{true}$$

**2. Conditional Invariant Satisfaction:** For every evaluated invariant $`j \in \mathcal{M}`$, if applicable, the computed residual is bounded by engineering tolerance $`\hat{\epsilon}_j`$:

$$\forall i \in \mathcal{I}, \quad \forall j \in \mathcal{M}: \quad \text{Applicable}_j(x_{i-1}, x_i) \implies |\hat{r}_{j, i}| \le \hat{\epsilon}_j$$

**3. Violation Budget Bound:** The total count of active physical violations across the $`k`$ sampled steps cannot exceed budget $`v_{\max}`$:

$$\sum_{i \in \mathcal{I}} \sum_{j \in \mathcal{M}} \mathbb{I}\big(\text{Applicable}_j(x_{i-1}, x_i) \land (|\hat{r}_{j, i}| > \hat{\epsilon}_j)\big) \le v_{\max}$$

**4. Inapplicability Budget Bound:** The count of invariant evaluations rendered inactive by actuator transitions or OFF states cannot exceed budget $`u_{\max}`$:

$$\sum_{i \in \mathcal{I}} \sum_{j \in \mathcal{M}} \mathbb{I}\big(\neg\text{Applicable}_j(x_{i-1}, x_i)\big) \le u_{\max}$$

### 2.3 Scope Boundary: Data Attestation vs. Gradient Binding
* **In Scope (PA-FL Lite):** Proves that the committed data batch satisfies declared physical conservation laws and operational bounds.
* **Deferred (Future Work):** Does not prove in-circuit that the submitted weight update $`\Delta w`$ was derived via backpropagation from batch $`X`$. Proving full gradient backpropagation for neural autoencoders inside arithmetic circuits requires tens of millions of R1CS constraints, exceeding edge computational budgets. This limitation is explicitly stated in the paper's threat model.

---

## 3. Mathematical Formulation and In-Circuit Engineering

### 3.1 Affine Invariant Formulation
Every mined physical invariant in the `pafl` framework (differential mass balances and steady-state actuator couplings) is affine with respect to adjacent operational states:

$$r_j(x_{t-1}, x_t) = J_{\text{prev}, j} \cdot x_{t-1} + J_{\text{cur}, j} \cdot x_t + c_j$$

where $`J_{\text{prev}, j}, J_{\text{cur}, j} \in \mathbb{R}^{1 \times D}`$ denote the sensitivity coefficients for time steps $`t-1`$ and $`t`$, and $`c_j \in \mathbb{R}`$ is the invariant intercept.

The Jacobian blocks and intercept vector are extracted via `affine_model(inv_set, df, columns)` with three mandatory numerical safeguards:
1. **Probe Row Feasibility:** Asserts `applicable_rows(inv_set, df).all(axis=1).any()` to prevent recovering offsets on singular rows.
2. **Finite-Difference Noise Truncation:** Snaps numerical derivative noise ($`|J_{j, d}| < 10^{-9} \cdot \max_k |J_{j, k}|`$) strictly to zero.
3. **Channel Completeness:** Guarantees that all channels referenced by invariants exist in the model's active feature schema.

### 3.2 Fixed-Point Quantization over $`\mathbb{F}_p`$
To avoid floating-point operations in arithmetic circuits, all parameters and variables are scaled into integer representations using fixed-point scale factor:

$$S = 2^{16} = 65,536$$

Quantized parameters are defined as:

$$\hat{x} = \lfloor S \cdot x \rceil, \quad \hat{J} = \lfloor S \cdot J \rceil, \quad \hat{c} = \lfloor S^2 \cdot c \rceil$$

The quantized residual naturally scales at order $`S^2 = 2^{32}`$:

$$\hat{r} = \hat{J}_{\text{prev}} \cdot \hat{x}_{t-1} + \hat{J}_{\text{cur}} \cdot \hat{x}_t + \hat{c}$$

#### Dynamic Range and Overflow Prevention
* Maximum continuous measurement on SWaT: $`x_{\max} \approx 1,015.0 \implies \hat{x} \approx 6.65 \times 10^7 < 2^{26}`$.
* Maximum sensitivity coefficient: $`|J|_{\max} \approx 8.90 \implies |\hat{J}| \approx 5.83 \times 10^5 < 2^{20}`$.
* Individual product term: $`|\hat{J} \cdot \hat{x}| < 2^{46}`$.
* Sum across 9 invariants: $`\sum |\hat{J} \cdot \hat{x}| < 9 \times 2^{46} < 2^{50} \ll p`$.
* The smallest non-zero coefficient ($`0.0097`$) quantizes to $`636`$ integer units, yielding a relative quantization error under $`0.08\%`$.

Signed tolerance comparisons ($`-\hat{\epsilon} \le \hat{r} \le \hat{\epsilon}`$) are evaluated using an offset $`K = 2^{60}`$:

$$0 \le \hat{r} + \hat{\epsilon} + K < 2^{61}$$

enforcing bounds through efficient 64-bit unsigned range checks (`Num2Bits(64)`).

### 3.3 Actuator Applicability and the Dual-Budget Gate
Physical couplings only bind when governing actuators are operating in steady-state ON conditions:

$$\text{Applicable}(x_{t-1}, x_t) \iff (\text{Actuator}_{t-1} = \text{ON}) \land (\text{Actuator}_t = \text{ON})$$

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

#### Defeating the Actuator-Toggling Evasion Attack
If the circuit enforced only a violation budget $`v_{\max}`$, an attacker could manipulate continuous telemetry arbitrarily while toggling actuator state bits at alternating time steps ($`A_t \neq A_{t-1}`$). This would artificially render all invariants inapplicable, bypassing the gate. 

PA-FL Lite prevents this evasion by enforcing an independent **inapplicability budget ($`u_{\max}`$)**, bounding inactive evaluations to plant baseline norms.

### 3.4 Two-Level Leaf Hashing Optimization
Industrial vectors contain $`D = 42`$ operational channels. Directly hashing 42 field elements in-circuit via Poseidon sponge absorption requires over 1,500 R1CS constraints per leaf.

PA-FL Lite partitions the row into $`D_{\text{inv}} = 18`$ channels actively referenced by invariants and $`D_{\text{rest}} = 24`$ auxiliary channels:

$$\begin{aligned}
h_{\text{inv}, i} &= \text{Poseidon}_{18}(x_{i, 1}, \dots, x_{i, 18}) \\
h_{\text{rest}, i} &= \text{Poseidon}_{24}(x_{i, 19}, \dots, x_{i, 42}) \quad (\text{precomputed off-circuit by prover}) \\
\text{leaf}_i &= \text{Poseidon}_2(h_{\text{inv}, i}, h_{\text{rest}, i})
\end{aligned}$$

The prover supplies $`h_{\text{rest}, i}`$ as an opaque private input. The circuit only computes the 18-element hash and a single 2-to-1 compression, saving approximately $`55\%`$ of in-circuit leaf hashing overhead while guaranteeing full cryptographic binding of the row.

---

## 4. Soundness Analysis and Sample Sizing

### 4.1 Analytic Soundness Formulation
Let $`\rho = N_{\text{violated}} / N`$ denote the fraction of time steps in batch $`X`$ containing invariant violations. When sampling $`k`$ rows uniformly at random without replacement, the probability of an adversary evading detection under $`v_{\max} = 0`$ is bounded by:

$$P(\text{Evasion}) = \prod_{m=0}^{k-1} \frac{N(1 - \rho) - m}{N - m} \approx (1 - \rho)^k$$

The detection probability (soundness) is:

$$P(\text{Detection}) = 1 - P(\text{Evasion}) \approx 1 - (1 - \rho)^k$$

### 4.2 Empirical Detection Regimes
On the SWaT testbed, attack detection falls into two distinct operational regimes:

1. **Gross Telemetry Fabrication (Channel Roll / Permutation):**
   * Circular rolling disrupts couplings across approximately $`\rho \approx 30\%`$ of all rows.
   * At $`k = 16`$: $`P(\text{Detection}) = 1 - (1 - 0.30)^{16} = 99.67\%`$.
   * At $`k = 32`$: $`P(\text{Detection}) > 99.999\%`$.
   * Gross fabrication is caught with high certainty at low sample counts.

2. **Exposure-Only Replay Attacks (`splice_only`):**
   * Replayed attack segments violate only a narrow set of invariants ($`\rho \approx 1.5\%`$).
   * At $`k = 16`$: $`P(\text{Detection}) = 1 - (1 - 0.015)^{16} \approx 21.5\%`$.
   * At $`k = 64`$: $`P(\text{Detection}) = 1 - (1 - 0.015)^{64} \approx 62.1\%`$.

This fundamental asymmetry demonstrates that while sampling is highly cost-effective against fabricated telemetry, defending against replay attacks requires combining admission control with robust update-space aggregators (e.g., Krum, FoolsGold).
