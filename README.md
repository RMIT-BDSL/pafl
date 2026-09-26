# Physics-Attested Federated Learning (`pafl`)

**A Framework for Physics-Based Admission Control in Federated Intrusion Detection for Industrial Control Systems**


- **Dataset Guide & Licensing:** [`DATA.md`](DATA.md) — *Detailed descriptions, schemas, telemetry examples, and acquisition instructions (strict non-redistribution notice).*
- **Result Files:** [`results/README.md`](results/README.md) — *What each committed result file holds and which script writes it.*
- **Zero-Knowledge Extension:** [`zk/README.md`](zk/README.md) — *The PA-FL Lite specification; the Circom / Groth16 build is in [`zk/lite/`](zk/lite/README.md).*
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

Traditionally, process invariants have been deployed as runtime anomaly detection heuristics. **This project formalizes process invariants as a cryptographically verifiable admission requirement.** The invariants are mined from a clean record of normal operation before federated training begins. Before an aggregation server admits a client's local model update into the global federation, the client must prove that its training batch satisfies those invariants. The check acts on the data behind the update and complements, rather than replaces, robust aggregation.

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

To rigorously test this admission gate, `pafl` implements and evaluates a taxonomy of data-space and update-space attacks:

### 1. Telemetry Fabrication (Recipe A)
Data-space attacks designed to preserve individual channel statistics while destroying physical inter-channel consistency:
* **Channel Roll:** Circularly shifts sensor channels in time relative to actuator channels by a calibrated plant duration (e.g., 60 samples = 5 minutes). This preserves the mean, variance, and autocorrelation of every individual stream while corrupting the physical coupling between pumps and flow meters.
* **Within-Regime Permutation:** Randomly shuffles time steps within stationary operating regimes, breaking temporal continuity and differential mass balances.
* **Conservation Scaling:** Multiplies sensor channels by scalar factors, violating volumetric conservation ratios.
* **Regime Splicing:** Transposes valid segments of telemetry from one historical operating regime into another, creating subtle boundary violations.

### 2. Gradient-Matching Fabrication (Recipe B)
* Formulates data poisoning as a bi-level optimization problem (adapting *Witches' Brew* techniques for industrial telemetry). Synthesizes training rows optimized so that their gradient update matches a target adversarial direction while resembling the updates of clean batches.

### 3. Exposure Poisoning (Replay Attacks)
* A malicious client splices unlabelled historical attack sequences into its training data and labels them as normal operations. By oversampling these attack windows during local training (*exposure*), the reconstruction-based autoencoder learns to reconstruct attack states with minimal error, effectively blinding the shared detector to physical sabotage.

### 4. Adaptive Adversary (Manifold Projection)
* Evaluates an informed adversary that possesses full knowledge of the declared invariant set. The attacker takes fabricated or poisoned telemetry and computes the minimum-norm projection onto the physical invariant manifold:
  $$\min_{\tilde{x}} \|\tilde{x} - x_{\text{fabricated}}\|_2 \quad \text{subject to} \quad A \tilde{x} = b \pm \epsilon$$
  Discrete actuator states are held fixed, so the projection moves only continuous sensor readings. This lets us evaluate how much poisoning survives once the attacker is forced to satisfy the physical checks.

### 5. Update-Space Baselines
* Classical model-space attacks for comparison across aggregation rules: sign flipping, update scaling, free riding, and min–max coordinate perturbation. These clients train on honest data and tamper only with the update, so they fall to the aggregation rule, not to the physics check.

---

## Experimental Architecture and Pipeline

The repository is modularized into discrete functional components:

```
pafl/
├── data/            # Ingestion, scaling, and temporal sharding for industrial datasets
├── invariants/      # Automated invariant mining, specification, and calibration
├── attacks/         # Recipe A/B fabrications, replay exposure, and adaptive projection
├── fl/              # Federated architectures, local training loops, the admission gate, and aggregation rules
├── eval/            # Evaluation metrics (F1, AUC-PR, targeted/untargeted recall)
├── utils/           # Paths, logging, and seeding
└── zk/              # Fixed-point export of the invariant sets for the circuit
scripts/             # Experiment execution drivers and summary generators
results/             # The committed result files (JSON); see results/README.md
results_archive/     # Local only (gitignored): plots, logs, probes, smoke tests, pilot outputs
tests/               # Unit and regression test suites (pytest)
tutorials/           # Interactive HTML dashboards and visual architecture flows
zk/                  # PA-FL Lite: specification, fixed-point invariant sets, and the build in zk/lite/
```

### Functional Modules
1. **Telemetry Ingestion (`pafl/data/`):**
   * **SWaT (Secure Water Treatment):** Physical water-treatment testbed telemetry (51 channels: 25 sensors, 26 actuators), the primary benchmark.
   * **WADI (Water Distribution):** Physical multi-tank water-distribution testbed, the second real-world benchmark.
   * **BATADAL:** Hydraulic network simulation benchmark (C-Town network).
   * **HAI:** Boiler and steam-turbine testbed, used as a scope boundary for processes without metered mass balances.
   * **Simulated Plant:** A multi-tank hydraulic simulator with analytically exact ground-truth physics.
2. **Automated Invariant Mining (`pafl/invariants/`):**
   * Mines linear actuator-to-sensor couplings and differential mass balances from clean baseline operational slices using constrained linear regression.
   * Calibrates invariant tolerance bounds ($\pm \epsilon$) against an independent clean validation slice, so that measurement noise is absorbed without looking at attack data.
3. **Federation Partitioning (`pafl/fl/partition.py`, `scenario_real.py`):**
   * Splits longitudinal operational data into non-overlapping temporal shards assigned to federated clients.
4. **Admission Gate and Robust Aggregation (`pafl/fl/gate.py`, `pafl/fl/defences.py`):**
   * Implements seven aggregation rules: **FedAvg**, **Krum**, **Coordinate-wise Median**, **Trimmed Mean**, **Norm Clipping**, **FLTrust**, and **FoolsGold**.
   * Evaluates each rule across five federated modes:
     * *Clean:* every client trains honestly.
     * *Honest-only:* only the honest clients take part (the reference for measuring damage).
     * *Naive attack:* malicious clients poison their data; no admission check.
     * *Physics-aware attack:* malicious clients project their data onto the invariants; every update is admitted.
     * *Gated:* updates from batches that fail the invariant check are excluded from aggregation.
5. **Multi-Axis Evaluation (`pafl/eval/metrics.py`):**
   * Computes point-wise precision, recall, F1, and threshold-free Area Under the Precision-Recall Curve (AUC-PR).
   * Evaluates **Targeted Attack Recall** (the detection rate on the specific physical attacks the malicious client sought to conceal) versus untargeted attack recall.

---

## Cryptographic Zero-Knowledge Extension (PA-FL Lite)

To keep telemetry private in multi-operator consortia, PA-FL Lite enforces the admission check in zero knowledge. It is implemented in Circom and proved with Groth16; the specification is in [`zk/`](zk/README.md) and the build in [`zk/lite/`](zk/lite/README.md).

* **Batch Commitment:** A client commits to its training batch of $N = 1{,}024$ rows via a Poseidon Merkle tree root $R$.
* **Challenge:** Once every client has committed, the verifier broadcasts a nonce $\rho$; both sides derive $k$ pseudo-random row indices from $R$ and $\rho$.
* **Succinct Proof:** The client proves in zero knowledge that:
  1. Each sampled row $x_i$ and its predecessor $x_{i-1}$ are authentic leaves of the Merkle root $R$.
  2. The sampled rows satisfy every applicable affine invariant within its declared tolerance:
     $$\left| J^{\text{prev}}_m x_{i-1} + J^{\text{cur}}_m x_i + c_m \right| \le \epsilon_m$$
  3. At most $v_{\max}$ sampled rows violate an invariant, and at most $u_{\max}$ checks are inapplicable (a coupling applies only when its actuator is in a steady state).
* **Scope:** The proof covers the training batch, not the model update; binding the update to the batch is left to future work.

The Groth16 setup needs a 1.2 GB powers-of-tau file, which is not in the repository; [`zk/lite/README.md`](zk/lite/README.md) explains how to download it.

---

## Installation and Environment Setup

### 1. Prerequisites
* Python 3.10+ (tested on Python 3.11 and 3.12, macOS Apple Silicon and Linux x86_64).
* Virtual environment isolation (`venv`).
* For the zero-knowledge build only: Node.js, circom 2.1 and snarkjs (see [`zk/lite/README.md`](zk/lite/README.md)).

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

# Run the test suite (synthetic tests require no external data)
pytest tests/ -q
```

`make help` lists the shortcuts (`make setup`, `make test`, `make smoke` for a small end-to-end run).

### 2. Dataset Setup
Due to licensing and data-use restrictions imposed by testbed providers (e.g., iTrust Singapore), raw physical datasets are not distributed in this repository. Place or symlink the extracted datasets into the `data/` directory (see [`DATA.md`](DATA.md)):

* **SWaT:** `data/SWaT/SWaT.A1 & A2_Dec_2015/Physical/`
* **WADI:** `data/WaDi/WADI.A1_9 Oct 2017/`
* **BATADAL:** `data/BATADAL/`
* **HAI:** `data/HAI/`

---

## Reproducing the Experiments

Drivers are deterministic given a seed. An adaptive run is resumable: rerunning with more seeds adds the missing cells to an existing output file. Result files go to `results/`; plots and logs go to the local `results_archive/`.

```bash
# 1. Invariant separability: do the mined invariants separate honest from fabricated batches? (SWaT, wide set)
python scripts/day1_residuals.py --dataset swat --roll-shift 60 \
    --r2-min 0.40 --coupling-off-ratio 0.10 --coupling-support 0.005 \
    --out results/c1_swat_wide_shift60.json

# 2. Coverage: which labelled attacks does each invariant set see?
python scripts/coverage_table.py --dataset swat --out results/swat_coverage.json

# 3. Adaptive poisoning and gating across the seven aggregation rules and five federated modes
python scripts/day45_adaptive.py --dataset swat \
    --r2-min 0.40 --coupling-off-ratio 0.10 --coupling-support 0.005 \
    --defences fedavg krum median trimmed_mean norm_clip fltrust foolsgold \
    --fabrication splice_only --malicious-fraction 0.3 --clients 10 --rounds 25 --local-epochs 2 \
    --modes clean honest_only fabricated projected gated --seeds 0 1 2 3 4 \
    --out results/swat_adaptive_wide_splice_5seed.json

# 4. Summarize multi-seed metrics and damage mitigation
python scripts/summarize_adaptive.py results/swat_adaptive_wide_splice_5seed.json
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
