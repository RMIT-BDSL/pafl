# Physics-Attested Federated Learning (`pafl`)

**A Framework for Physics-Based Admission Control in Federated Intrusion Detection for Industrial Control Systems**


- **Dataset Guide & Licensing:** [`DATA.md`](DATA.md) — *Detailed descriptions, schemas, telemetry examples, and acquisition instructions (strict non-redistribution notice).*
- **Zero-Knowledge Extension:** [`zk/README.md`](zk/README.md) — *Circom / Groth16 circuit definitions for PA-FL Lite.*
- **Learning Resources:** [`tutorials/`](tutorials/) — *Visual (HTML) workflows of federated training loops and pilot results.*

---

## Abstract and Problem Formulation

Industrial Control Systems (ICS) and Supervisory Control and Data Acquisition (SCADA) networks governing critical infrastructure—such as municipal water treatment, power distribution, and chemical manufacturing—increasingly deploy machine learning anomaly detectors on operational telemetry (e.g., sensor measurements, actuator switch states, and control set-points). However, training effective intrusion detection systems locally presents a fundamental dilemma: an individual industrial site operates within a restricted operational regime and rarely observes cyber-physical attacks. Consequently, detectors trained in isolation overfit to local operating profiles and transfer poorly to novel attack vectors.

**Federated Learning (FL)** offers a privacy-preserving solution. Under standard federated architectures, multiple industrial operators collaboratively train a global anomaly detection model by sharing local model parameter updates (weight gradients or model deltas) with an aggregation server, without centralizing proprietary operational telemetry. 

### The Security Vulnerability: The Blindness of Update-Space Defenses
While federated learning safeguards data confidentiality, it introduces a severe vulnerability: **participants cannot inspect each other's local training data**. A compromised, colluding, or malicious client can submit poisoned model updates designed to induce targeted blind spots into the global detector—causing it to ignore specific physical sabotage. In critical infrastructure, such poisoning constitutes an imminent physical safety failure rather than a minor service degradation.

Existing Byzantine-robust federated learning defenses operate almost exclusively in **update space**:
1. **Geometric and Statistical Filtering:** Aggregators such as Krum, Coordinate-wise Median, Trimmed Mean, and FoolsGold filter or down-weight updates that diverge geometrically or statistically from the cluster of honest updates.
2. **Norm Bounding and Trust-Score Alignment:** Techniques such as norm clipping and FLTrust (which scores updates against a small, clean server-side calibration dataset) restrict update magnitude or directional variance.
3. **Cryptographic Input Validation:** Verifiable frameworks (e.g., RoFL, ACORN) prove that an update satisfies specific vector bounds.

**The Fundamental Gap:** None of these defenses examine the underlying training data from which the update was generated. A malicious participant can synthesize entirely fabricated, physically impossible sensor traces that nevertheless yield model weight updates mathematically indistinguishable from honest updates. Update-space defenses remain blind to data that mimics honest update geometry.

---

## Core Methodology: Physics-Attested Admission Control

Industrial telemetry differs fundamentally from generic machine learning data (e.g., natural language or images): **it is strictly governed by physical conservation laws and operational plant logic**. 

In cyber-physical systems, these relationships are known as **process invariants**:
* **Mass and Energy Balances:** For example, the rate of change of water level in a storage tank must equal the volumetric inflow minus the volumetric outflow:
  $$\frac{d}{dt} L(t) = \alpha \cdot F_{\text{in}}(t) - \beta \cdot F_{\text{out}}(t) \pm \epsilon$$
* **Actuator-to-Sensor Couplings:** An actuator commanded to an "OFF" state cannot induce downstream fluid flow or pressure increases:
  $$\text{Pump} = \text{OFF} \implies \text{Flow} = 0 \pm \epsilon_{\text{noise}}$$

Traditionally, process invariants have been deployed as runtime anomaly detection heuristics. **This project formalizes process invariants as a cryptographically verifiable admission requirement.** Before an aggregation server admits a client's local model update into the global federation, the client must prove that its training batch satisfies the declared physical invariants of the industrial process.

```
+-------------------------------------------------------------------------------+
|                             FEDERATED CLIENT                                  |
|                                                                               |
|  [ Local Telemetry Batch ] ---> [ Physics-Invariant Verifier ]                |
|          |                            |                                       |
|          v                            v (Satisfies physical laws?)            |
|  [ Local Training ]             YES / NO                                      |
|          |                            |                                       |
|          v                            v                                       |
|  [ Weight Delta dw ]       [ Admission Proof / Attestation ]                  |
+----------|----------------------------|---------------------------------------+
           |                            |
           +------------->+<------------+
                          |
                          v
+-------------------------------------------------------------------------------+
|                             FEDERATED AGGREGATOR                              |
|                                                                               |
|  1. Verify Physics Attestation  --> Reject update if telemetry violates laws  |
|  2. Apply Robust Aggregation    --> (FedAvg, Trimmed Mean, Krum, FLTrust)     |
|  3. Broadcast Global Model      --> Deploy updated detector to all sites      |
+-------------------------------------------------------------------------------+
```

---

## Threat Model and Attack Taxonomy

To rigorously test this admission gate, `pafl` implements and evaluates an exhaustive taxonomy of data-space and update-space attacks:

### 1. Telemetry Fabrication (Recipe A)
Data-space attacks designed to preserve individual channel statistics while destroying physical inter-channel consistency:
* **Channel Roll:** Circularly shifts sensor channels in time relative to actuator channels by a calibrated plant duration (e.g., 60 samples = 5 minutes). This perfectly preserves the mean, variance, and autocorrelation of every individual stream while corrupting the physical coupling between pumps and flow meters.
* **Within-Regime Permutation:** Randomly shuffles time steps within stationary operating regimes, breaking temporal continuity and differential mass balances.
* **Conservation Scaling:** Multiplies sensor channels by scalar factors, violating volumetric conservation ratios.
* **Regime Splicing:** Transposes valid segments of telemetry from one historical operating regime into another, creating subtle boundary violations.

### 2. Gradient-Matching Fabrication (Recipe B)
* Formulates data poisoning as a bi-level optimization problem (adapting *Witches' Brew* techniques for industrial telemetry). Synthesizes continuous training rows specifically optimized to mimic the gradient updates of clean batches while minimizing detection.

### 3. Exposure Poisoning (Replay Attacks)
* A malicious client splices unlabelled historical attack sequences into its training data and labels them as normal operations. By oversampling these attack windows during local training (*exposure*), the reconstruction-based autoencoder learns to reconstruct attack states with minimal error, effectively blinding the shared detector to physical sabotage.

### 4. Adaptive Adversary (Manifold Projection)
* Evaluates an informed adversary that possesses full knowledge of the declared invariant set. The attacker takes fabricated or poisoned telemetry and computes the minimum-norm projection onto the physical invariant manifold:
  $$\min_{\tilde{x}} \|\tilde{x} - x_{\text{fabricated}}\|_2 \quad \text{subject to} \quad A \tilde{x} = b \pm \epsilon$$
  This forces the poisoned batch to satisfy the physical checks, allowing us to evaluate whether invariant enforcement strips the malicious update of its harmful potency.

---

## Experimental Architecture and Pipeline

The repository is modularized into discrete functional components under `pafl/`:

```
pafl/
├── data/            # Ingestion, scaling, and temporal sharding for industrial datasets
├── invariants/      # Automated invariant mining, specification, and calibration
├── attacks/         # Recipe A/B fabrications, replay exposure, and adaptive projection
├── fl/              # Federated architectures, local training loops, and aggregation rules
├── eval/            # Evaluation metrics (F1, AUC-PR, targeted/untargeted recall)
scripts/             # Experiment execution drivers and summary generators
results/             # Output metrics, run traces, and experiment JSON files
tests/               # Unit and regression test suites (pytest)
tutorials/           # Interactive HTML dashboards and visual architecture flows
zk/                  # Zero-knowledge circuit implementations (Circom / Groth16)
```

### Functional Modules
1. **Telemetry Ingestion (`pafl/data/`):**
   * **SWaT (Secure Water Treatment):** Real physical testbed telemetry (51 channels, 25 continuous sensors, 26 discrete actuators) serving as the primary benchmark across 10 federated clients.
   * **WADI (Water Distribution System):** Large-scale municipal water distribution testbed (124 channels) serving as a secondary real-world validation.
   * **BATADAL:** Hydraulic network simulation benchmark (C-Town network) partitioned across 5 clients.
   * **Simulated Plant:** A multi-tank hydraulic simulator with analytically exact ground-truth physics.
2. **Automated Invariant Mining (`pafl/invariants/`):**
   * Mines linear actuator-to-sensor couplings and differential mass balances from clean baseline operational slices using constrained linear regression.
   * Calibrates invariant tolerance bounds ($\pm \epsilon$) against an independent clean validation slice, ensuring that measurement noise is absorbed without overfitting to test attacks.
3. **Federation Partitioning (`pafl/fl/partition.py`, `scenario_real.py`):**
   * Splits longitudinal operational data into non-overlapping temporal shards assigned to federated clients, establishing realistic statistical heterogeneity across nodes.
4. **Defense and Robust Aggregation (`pafl/fl/defences.py`):**
   * Implements seven aggregation rules: **FedAvg**, **Krum**, **Coordinate-wise Median**, **Trimmed Mean**, **Norm Clipping**, **FLTrust**, and **FoolsGold**.
   * Evaluates the physics admission filter across three operating conditions:
     * *Fabricated:* Unchecked baseline admission.
     * *Projected:* The adaptive attacker projects data onto invariants; updates are admitted.
     * *Gated:* Updates derived from batches failing the invariant check are excluded from aggregation.
5. **Multi-Axis Evaluation (`pafl/eval/metrics.py`):**
   * Computes point-wise precision, recall, F1, and threshold-free Area Under the Precision-Recall Curve (AUC-PR).
   * Evaluates **Targeted Attack Recall** (the detection rate on the specific physical attacks the malicious client sought to conceal) versus untargeted attack recall.

---

## Key Empirical Findings

Extensive multi-seed evaluations on real physical testbeds confirm:

1. **Separability Without False Rejections (Criterion 1):**
   * Automatically mined process invariants separate clean operational telemetry from fabricated data across BATADAL, SWaT, and WADI with **zero false rejections of honest clients**.
   * On SWaT, honest operational transitions induce a baseline violation rate of only $0.20\%$ (attributable to hydraulic transit lag), allowing an admission threshold of $1.0\%$ to reject fabricated telemetry with complete fidelity.
2. **Update-Space Defenses Fail Under Fabrication (Criterion 2 & 3):**
   * Standard Byzantine defenses (FedAvg, Coordinate-wise Median, Trimmed Mean, Norm Clipping) routinely admit fabricated and replay-poisoned updates, leading to a catastrophic collapse in detector recall on targeted attack windows.
3. **Mitigation of Attack Capability (Criterion 4):**
   * On the physical SWaT testbed, enforcing invariant admission control eliminates **$70\%$ to $100\%$** of the targeted damage inflicted by malicious clients under rules that otherwise admit all updates.
   * Forcing an adaptive attacker to project poisoned batches onto the physical invariant manifold strips the updates of their adversarial leverage, returning global model performance to clean baseline levels.

---

## Cryptographic Zero-Knowledge Extension (PA-FL Lite)

To ensure privacy in multi-operator consortia, `zk/` provides **PA-FL Lite**, a zero-knowledge proof-of-concept circuit implemented in Circom and verified using the Groth16 SNARK protocol:

* **Batch Commitment:** A client commits to its training batch $B$ of $N = 1{,}024$ samples via a Poseidon Merkle tree root $R$.
* **Challenge Sampling:** The server issues a pseudo-random Fiat–Shamir challenge selecting $k$ row indices.
* **Succinct Proof:** The client proves in zero-knowledge that:
  1. The opened samples $x_i$ and $x_{i-1}$ are authentic leaves of Merkle root $R$.
  2. The rows satisfy the system of linear invariants within declared tolerances:
     $$\left| \sum_{j} A_{m,j} x_{i,j} - b_m \right| \le \epsilon_m$$
  3. The number of failed checks does not exceed an allocated **violation budget $v$** (calibrated to $v=1$ for $k=32$ to accommodate physical transition latency, ensuring honest false rejection remains below $1\%$).

---

## Installation and Environment Setup

### 1. Prerequisites
* Python 3.10+ (tested on Python 3.11 and 3.12, macOS Apple Silicon and Linux x86_64).
* Virtual environment isolation (`venv`).

```bash
# Clone the repository
git clone https://github.com/RMIT-BDSL/pafl.git
cd pafl

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run automated test suite (~10 seconds, synthetic tests require no external data)
pytest tests/ -q
```

### 2. Dataset Setup
Due to licensing and data-use restrictions imposed by testbed providers (e.g., iTrust Singapore), raw physical datasets are not distributed in this repository. Place or symlink the extracted datasets into the `data/` directory:

* **SWaT:** `data/SWaT/SWaT.A1 & A2_Dec_2015/Physical/`
* **WADI:** `data/WaDi/WADI.A1_9 Oct 2017/`
* **BATADAL:** `data/BATADAL/`
* **HAI:** `data/HAI/`

---

## Reproducing Empirical Sweeps

Drivers are designed to be fully deterministic and resumable (caching intermediate outputs in `results/`):

```bash
# 1. Evaluate Invariant Separability (Criterion 1 on SWaT)
python scripts/day1_residuals.py --dataset swat --roll-shift 60 \
    --r2-min 0.40 --coupling-off-ratio 0.10 --coupling-support 0.005 \
    --out results/c1_swat_wide_shift60.json

# 2. Execute Adaptive Poisoning and Gating Across All Seven Aggregation Rules
python scripts/day45_adaptive.py --dataset swat \
    --defences fedavg krum median trimmed_mean norm_clip fltrust foolsgold \
    --fabrication splice_only --seeds 0 1 2 \
    --out results/swat_adaptive_wide_splice_3seed.json

# 3. Summarize Multi-Seed Metrics and Damage Mitigation
python scripts/summarize_adaptive.py results/swat_adaptive_wide_splice_3seed.json
```

---

## Citation and Licensing



```bibtex
@article{pafl2026,
  title   = {Title},
  author  = {Authors},
  journal = {Journal},
  volume  = {Volume},
  year    = {Year}
}
```

**License:** This codebase is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.
