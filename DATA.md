# Dataset Documentation and Acquisition Guide

Information about the datasets.

---

## ⚠️ Mandatory Licensing and Non-Redistribution Notice

> **IMPORTANT:** Raw operational telemetry from industrial testbeds—specifically **SWaT** and **WADI**—is subject to legally binding **Data Use Agreements (DUAs)** issued by the testbed operator (iTrust, Centre for Research in Cyber Security at Singapore University of Technology and Design). 
>
> **Strict Restrictions:**
> 1. **No Redistribution:** The datasets **cannot be committed to this GitHub repository**, mirrored, publicly hosted, or redistributed in any form.
> 2. **Individual Request Required:** Every researcher, organization, or practitioner wishing to reproduce the experiments must request their own authorized copy directly from the data owners.
> 3. **Local Storage:** Keep all raw dataset files in a local directory outside version control, and link them into `pafl` as described in [Data Placement and Environment Setup](#data-placement-and-environment-setup).

---

## 1. Primary Benchmark: Secure Water Treatment (SWaT)

### 1.1 Process Overview
The **Secure Water Treatment (SWaT)** testbed is an operational, scaled-down water treatment facility producing five gallons per minute of purified water. Built by iTrust at SUTD, the physical plant comprises a six-stage water treatment pipeline governed by six Programmable Logic Controllers (PLCs):
* **P1 (Raw Water Storage):** Inflow motorized valve (`MV101`), raw water pump (`P101`), and tank water level transmitter (`LIT101`).
* **P2 (Chemical Dosing):** Pre-treatment chemical dosing (coagulant, sodium hypochlorite) monitored by pH (`AIT202`) and oxidation-reduction potential (`AIT203`).
* **P3 (Ultrafiltration):** Ultrafiltration feed pump (`P301`/`P302`), differential pressure transmitter (`DPIT301`), and backwash controls.
* **P4 (Dechlorination):** Ultraviolet dechlorination and reverse osmosis (RO) feed pump (`P401`).
* **P5 (Reverse Osmosis):** Multi-stage RO filtration monitored by electrical conductivity (`AIT501`) and flow transmitters (`FIT501`).
* **P6 (Backwash Storage):** Clean water permeate storage and backwash cycling pump (`P601`).

### 1.2 Technical Specifications
* **Dataset Version:** `SWaT.A1 & A2_Dec_2015` (Physical process logs / historian).
* **Sampling Cadence:** 1 Hz (1 sample per second).
* **Normal Operation:** 495,000 rows (7 continuous days of attack-free normal operation). The first 21,600 rows (6 hours) represent the physical filling of the empty plant from empty (startup transient) and are omitted during training.
* **Attack Evaluation:** 449,919 rows (4 days) containing 36 documented physical and network spoofing attacks (e.g., sensor spoofing, valve tampering, pump interlock overrides).
* **Dimensionality:** 51 process channels (25 continuous sensor readings, 26 discrete actuator state indicators).

### 1.3 Concrete Telemetry Example
| Timestamp | LIT101 (mm) | FIT101 ($m^3/h$) | MV101 (State) | P101 (State) | FIT201 ($m^3/h$) | LIT301 (mm) | Label |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `2015-12-28 10:00:00` | 522.4 | 2.45 | 1 (Open) | 2 (Closed/Off) | 0.00 | 812.1 | Normal |
| `2015-12-28 10:00:01` | 523.1 | 2.44 | 1 (Open) | 2 (Closed/Off) | 0.00 | 812.0 | Normal |
| `...` | ... | ... | ... | ... | ... | ... | ... |
| `2015-12-28 10:29:14` | 780.2 | 0.00 | 0 (Closed) | 1 (Open/On) | 2.38 | 805.4 | Attack (#1) |

*Physical Invariant Example:* A zero-flow coupling holds between raw water pump `P101` and flow transmitter `FIT201`: $\text{P101} = \text{OFF} \implies \text{FIT201} \le 0.05\text{ }m^3/h$. If `P101` is OFF but `FIT201` reads positive flow, an invariant is violated.

### 1.4 How to Acquire
* **Provider:** iTrust, Centre for Research in Cyber Security, SUTD.
* **Request URL:** [https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/](https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/)
* **Procedure:** Submit the web request form with academic/institutional affiliation. iTrust will email a formal DUA. Upon returning the signed agreement, credentials to the secure repository are provided. Download the physical historian archive (`SWaT.A1 & A2_Dec_2015.zip`).

### 1.5 Bibliographic Reference
```bibtex
@inproceedings{goh2016swat,
  title        = {A Dataset to Support Research in the Design of Secure Water Treatment Systems},
  author       = {Goh, Jonathan and Adepu, Sridhar and Junejo, Khurum Nazir and Mathur, Aditya},
  booktitle    = {Critical Information Infrastructures Security (CRITIS 2016)},
  series       = {Lecture Notes in Computer Science},
  volume       = {10242},
  pages        = {88--99},
  year         = {2016},
  publisher    = {Springer},
  doi          = {10.1007/978-3-319-71368-7_8}
}
```

---

## 2. Secondary Physical Benchmark: Water Distribution (WADI)

### 2.1 Process Overview
The **Water Distribution (WADI)** testbed is an operational testbed that simulates a multi-stage municipal water distribution network, acting as a companion system to SWaT. WADI takes purified water from water treatment and routes it through an elevated reservoir, distribution tanks, and localized consumer demand junctions. It models realistic fluid dynamics with consumer demand fluctuations, booster pumps, and leakage simulation.

### 2.2 Technical Specifications
* **Dataset Version:** `WADI.A1_9 Oct 2017`.
* **Sampling Cadence:** 1 Hz (1 sample per second).
* **Normal Operation:** 1,209,600 rows (14 consecutive days of attack-free normal operation). The first 20,000 rows (~5.5 hours) represent startup settling and are omitted.
* **Attack Evaluation:** 172,800 rows (2 days) containing 15 multi-point cyber-physical attacks affecting consumer pressure, tank levels, and chemical dosing.
* **Dimensionality:** 127 raw columns (OPC server tags), cleaned to 124 active process variables (65 continuous sensors and 59 discrete actuators) by removing non-physical logging derived flags.

### 2.3 Concrete Telemetry Example
| Timestamp | 1_AIT_001_PV (pH) | 1_FIT_001_PV ($m^3/h$) | 1_P_001_STATUS | 2_LT_001_PV (Level %) | 2_MCV_001_STATUS | Label |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `10/9/2017 18:00:00` | 7.41 | 1.82 | 1 (Active) | 58.4 | 1 (Open) | Normal |
| `10/9/2017 18:00:01` | 7.42 | 1.81 | 1 (Active) | 58.4 | 1 (Open) | Normal |

### 2.4 How to Acquire
* **Provider:** iTrust, Centre for Research in Cyber Security, SUTD.
* **Request URL:** [https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/](https://itrust.sutd.edu.sg/itrust-labs_datasets/dataset_info/)
* **Procedure:** Acquired via the same iTrust access portal as SWaT under identical non-redistribution DUA terms. Download `WADI.A1_9 Oct 2017`.

### 2.5 Bibliographic Reference
```bibtex
@inproceedings{ahmed2017wadi,
  title        = {{WADI}: A Water Distribution Testbed for Research in the Design of Secure Cyber Physical Systems},
  author       = {Ahmed, Chuadhry Mujeeb and Palleti, Venkata Reddy and Mathur, Aditya P.},
  booktitle    = {Proceedings of the 3rd International Workshop on Cyber-Physical Systems for Smart Water Networks (CySWATER 2017)},
  pages        = {25--28},
  year         = {2017},
  publisher    = {ACM},
  doi          = {10.1145/3055366.3055375}
}
```

---

## 3. Hydraulic Simulation Benchmark: BATADAL

### 3.1 Process Overview
The **Battle of the Attack Detection Algorithms (BATADAL)** dataset is an international benchmark generated using `EpanetCPA`, an extension of the EPANET hydraulic simulator that incorporates cyber-physical attacks on industrial networks. It simulates the realistic topology of the **C-Town water distribution network**, consisting of 7 storage tanks, 11 pumping stations with 43 valves/pumps, and hundreds of demand nodes.

### 3.2 Technical Specifications
* **Dataset Version:** BATADAL Competition Datasets (`BATADAL_dataset03.csv`, `BATADAL_dataset04.csv`, `BATADAL_test_dataset.csv`).
* **Sampling Cadence:** 1-hour intervals in the original release; in `pafl`, partitioned into 5 federated clients with 876 rows each.
* **Attacks:** 14 cyber-physical attack scenarios targeting SCADA communication, pump schedules, and tank overflow/depletion.
* **Dimensionality:** 43 operational channels (7 water tank levels `L_T1`..`L_T7`, 11 junction pressures `P_J280`..`P_J422`, 12 pipeline flow rates `F_PU1`..`F_V2`, and 13 actuator status indicators).

### 3.3 Concrete Telemetry Example
| DATETIME | L_T1 (m) | L_T2 (m) | F_PU1 ($m^3/h$) | S_PU1 (Status) | P_J280 (bar) | ATT_FLAG |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `04/01/16 00` | 2.45 | 3.12 | 110.4 | 1 (On) | 2.84 | 0 |
| `04/01/16 01` | 2.58 | 3.05 | 109.8 | 1 (On) | 2.81 | 0 |

### 3.4 How to Acquire
* **Provider:** International Water Association (IWA) & ASCE.
* **Download URL:** [http://www.batadal.net/data.html](http://www.batadal.net/data.html) (or mirrors on Zenodo).
* **Licensing:** Open-access academic benchmark for cyber-physical anomaly detection.

### 3.5 Bibliographic Reference
```bibtex
@article{taormina2018batadal,
  title        = {Battle of the Attack Detection Algorithms: Disclosing Cyber Attacks on Water Distribution Networks},
  author       = {Taormina, Riccardo and Galelli, Stefano and Douglas, Helen and 
                  Chandy, K. Mani and Nikolopoulos, Dionysios and 
                  Galanis, Christos and Makropoulos, Christos},
  journal      = {Journal of Water Resources Planning and Management},
  volume       = {144},
  number       = {8},
  pages        = {04018048},
  year         = {2018},
  publisher    = {American Society of Civil Engineers (ASCE)},
  doi          = {10.1061/(ASCE)WR.1943-5452.0000969}
}
```

---

## 4. Scope Boundary Benchmark: Hardware-in-the-Loop Augmented ICS (HAI)

### 4.1 Process Overview
The **HAI (HIL-Augmented ICS)** testbed was constructed by the National Security Research Institute (NSRI) and ETRI in Daejeon, South Korea. Unlike the hydraulic water plants, HAI integrates four diverse thermal and rotational processes:
* **P1 (Boiler Process):** Water-steam cycle, boiler pressure, feed pumps, and heating elements.
* **P2 (Turbine Process):** High-speed rotating steam turbine, generator output, and rotational speed loops.
* **P3 (Water Treatment):** Condenser and water demineralization loops.
* **P4 (HIL Simulation Model):** Hardware-in-the-loop virtual plant model maintaining grid stability.

In this paper, HAI is documented as an **explicit scope boundary**: physical invariant rules provide interpretable protection for mass-balance fluid systems (SWaT, WADI), but struggle with multi-regime set-point schedule shifts and fast rotating machinery.

### 4.2 Technical Specifications
* **Dataset Version:** HAI 2.0 / HAI 21.03.
* **Sampling Cadence:** 1 Hz (1 sample per second).
* **Normal Training Data:** 921,603 rows (~11 days across `train1.csv`, `train2.csv`, `train3.csv`) with 0 missing values.
* **Attack Evaluation:** 402,005 rows across five independent sessions (`test1.csv` to `test5.csv`) containing 50 complex multi-stage attack scenarios.
* **Dimensionality:** 79 operational process channels (55 analog sensors, 24 discrete actuator/control flags).

### 4.3 How to Acquire
* **Provider:** National Security Research Institute (NSRI) & ETRI, South Korea.
* **Download Repository:** [https://github.com/ics-dataset/hai](https://github.com/ics-dataset/hai) (or via DACON Competition #235624).
* **Licensing:** Released under the Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) license.

### 4.4 Bibliographic Reference
```bibtex
@inproceedings{shin2021hai,
  title        = {Two {ICS} Security Datasets and Anomaly Detection Contest on the {HIL}-Based Augmented {ICS} Testbed},
  author       = {Shin, Hyeok-Ki and Lee, Woomyo and Yun, Jeong-Han and Min, Byung-Gil},
  booktitle    = {Proceedings of the 14th Cyber Security Experimentation and Test Workshop (CSET 2021)},
  pages        = {36--40},
  year         = {2021},
  publisher    = {ACM},
  doi          = {10.1145/3474718.3474719}
}
```

---

## 5. Built-In Synthetic Benchmark: Coupled Three-Tank Plant

The codebase includes a fully analytical, deterministic simulator in [`pafl/data/synthetic.py`](file:///Users/v127226/dev/26-MDPI-Info/pafl/pafl/data/synthetic.py). It models three inter-connected fluid storage tanks with two inlet pumps and cross-flow connecting valves.

* **Usage:** Requires **zero external downloads**. Runs out-of-the-box for unit testing, mathematical verification, and fast algorithm debugging.

---

## Data Placement and Environment Setup

The data loaders in [`pafl/data/loaders.py`](file:///Users/v127226/dev/26-MDPI-Info/pafl/pafl/data/loaders.py) automatically resolve dataset locations case-insensitively using the following precedence:
1. The `PAFL_DATA_DIR` environment variable (if set).
2. The local `pafl/data/` folder inside this repository.
3. A sibling `../data/` or `../datasets/` folder beside the repository checkout.

### Expected Directory Layout
To run the full suite of experiments, organize your local non-committed data directory as follows:

```
pafl/data/                          # (Or export PAFL_DATA_DIR=/path/to/datasets)
├── SWaT/
│   └── SWaT.A1 & A2_Dec_2015/
│       └── Physical/
│           ├── SWaT_Dataset_Normal_v1.xlsx
│           └── SWaT_Dataset_Attack_v0.xlsx
├── WaDi/
│   └── WADI.A1_9 Oct 2017/
│       ├── WADI_14days.csv
│       └── WADI_attackdata.csv
├── BATADAL/
│   ├── BATADAL_dataset03.csv
│   └── BATADAL_dataset04.csv
└── HAI/
    ├── train1.csv
    ├── train2.csv
    ├── train3.csv
    ├── test1.csv
    ├── test2.csv
    ├── test3.csv
    ├── test4.csv
    └── test5.csv
```

### Preprocessing and Disk Caching
* **Automatic Caching:** Parsing raw Excel files (`.xlsx`) can take up to 60 seconds per run. The loader automatically converts parsed frames into optimized binary pickle caches stored in `.pafl_cache/` beside the data. Subsequent runs load in milliseconds.
* **Downsampling:** By default, SWaT is loaded with a stride of 5 (reducing row count from 495,000 to ~99,000 while preserving all hydraulic transition dynamics). To disable downsampling for high-resolution evaluation, pass `--downsample 1` to the experiment drivers.
