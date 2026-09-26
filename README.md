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

### 1. Telemetry Fabrication
Data-space attacks that break the physical relations between channels. All but conservation scaling keep every channel's own distribution unchanged:
* **Channel Roll:** Circularly shifts the actuator channels in time against the sensor channels, by a plant duration (the paper uses 60 rows = 5 minutes at the 5 s stride). Each channel keeps its values, variance and autocorrelation; what breaks is the coupling between an actuator's state and the flow it drives, so a pump reads off while its flow meter shows flow.
* **Within-Regime Permutation:** Clusters the rows into operating regimes (k-means on the continuous channels, 4 regimes) and permutes the actuator states among the rows of each regime. The sensor channels are untouched, so the mass balances still hold; the actuator–flow couplings break.
* **Conservation Scaling:** Multiplies every flow channel by a factor of 1.3 and leaves the tank levels unchanged, so the mass balances fail and so do the couplings whose on-state flow no longer matches. The flow distributions change too, so a distribution check would also notice.
* **Regime Splicing:** Cuts the record into 12 segments and reorders them. Every row is real plant data and only the joins are physically impossible, so very few rows violate an invariant and the check admits the batch (a documented limitation).

### 2. Optimised Perturbation
* Trains a surrogate autoencoder on the malicious client's own shard, then perturbs the shard's continuous channels, within ±2.5σ of each channel, to maximise the surrogate's reconstruction error, in the manner of error-maximising adversarial poisons (Fowl et al., NeurIPS 2021). Actuator states are left unchanged. `pafl/attacks/recipe_b.py` also holds a gradient-matching path after *Witches' Brew*, which no paper run uses.

### 3. Exposure Poisoning (Replay Attacks)
* A malicious client overwrites about a quarter of its shard (a tenth on WADI) with real segments from the labelled attack record and presents them as normal operation. Half of its local training windows are drawn from those attack windows (*exposure*), so the shared autoencoder learns to reconstruct the attacks and they stop raising alarms. Every data-space attacker above carries the same spliced segments; the fabrications are applied on top of them.

### 4. Adaptive Adversary (Manifold Projection)
* An informed adversary that knows the mined invariants and their tolerances. It moves its poisoned batch the least it can so that the batch passes the check:
  $$\min_{\tilde{X}} \|\tilde{X} - X_{\text{poisoned}}\|_2 \quad \text{subject to} \quad |r_j(\tilde{X}_t)| \le \epsilon_j \ \text{for every row } t \text{ and invariant } j$$
  Every invariant is affine, so each constraint is a slab and the problem is convex; it is solved by an active-set loop of minimum-norm corrections. Actuator states are held fixed, so only continuous sensor readings move, and the loop stops once at most 0.5% of rows violate, half the 1% admission threshold. This measures how much poisoning survives once the attacker is forced to satisfy the physical checks.

### 5. Update-Space Baselines
* Classical model-space attacks for comparison across aggregation rules: sign flipping (the negated update), update scaling (×10), free riding (small Gaussian noise instead of training), and min–max (Shejwalkar and Houmansadr: the honest mean shifted against its own direction as far as the largest honest-to-honest distance allows). These clients train on honest data and tamper only with the update, so the physics check admits their batches and the aggregation rule is the only defence.

---

## Experimental Architecture and Pipeline

The repository is modularized into discrete functional components:

```
pafl/
├── data/            # Ingestion, scaling, and temporal sharding for industrial datasets
├── invariants/      # Automated invariant mining, specification, and calibration
├── attacks/         # Fabrications, optimised perturbation, update-space attacks, and adaptive projection
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
* Python 3.10+. The paper's runs used Python 3.13 on macOS (Apple M3 Pro, CPU only); `requirements-lock.txt` lists the exact package versions.
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

`make help` lists the shortcuts (`make setup`, `make test`, `make smoke` for a small end-to-end run, `make reproduce`).

### 2. Dataset Setup
Due to licensing and data-use restrictions imposed by testbed providers (e.g., iTrust Singapore), raw physical datasets are not distributed in this repository. Place or symlink the extracted datasets into the `data/` directory (see [`DATA.md`](DATA.md)):

* **SWaT:** `data/SWaT/SWaT.A1 & A2_Dec_2015/Physical/`
* **WADI:** `data/WaDi/WADI.A1_9 Oct 2017/`
* **BATADAL:** `data/BATADAL/`
* **HAI:** `data/HAI/`

---

## Reproducing the Experiments

`scripts/reproduce.sh` holds one command per committed result file, grouped by experiment, with approximate run times. It writes to `results_archive/reproduce/`, so the committed files stay untouched, and `scripts/compare_results.py` checks a rerun against its committed file number by number.

```bash
make reproduce                    # every experiment, about 6 h on one CPU (needs the datasets)
make separation                   # or one group: separation coverage honest adaptive sweep trust
DRY=1 scripts/reproduce.sh        # print the commands without running them

python scripts/compare_results.py results/swat_adaptive_wide_splice_5seed.json \
    results_archive/reproduce/swat_adaptive_wide_splice_5seed.json
```

| script | writes | what it measures |
|---|---|---|
| `separation.py` | `c1_*` | does the invariant check separate honest from fabricated batches (no training) |
| `coverage.py` | `*_coverage` | which labelled attacks each invariant set sees |
| `honest_verdicts.py` | `honest_verdicts` | the check's verdict on every honest client shard |
| `adaptive.py` | `*_adaptive_*` | the five federated modes under each aggregation rule |
| `sweep.py` | `*_sweep_*` | every rule against every data-space and update-space attack |
| `trust_traces.py` | `*_trust_traces_*` | FLTrust and FoolsGold trust on the malicious clients, per round |
| `sim_defences.py` | nothing committed | the simulated plant (the pilot's setting; not in the paper) |

`python scripts/summarize_adaptive.py <file>` prints the damage-removal numbers the paper reports, from any `*_adaptive_*` file. Every cell reseeds before it runs, and the drivers resume: a rerun with the same `--out` skips the cells already there. `requirements-lock.txt` pins the package versions the paper's runs used.

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
