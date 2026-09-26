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
* **Sampling Cadence:** 1 Hz (1 sample per second); loaded at a 5 s stride (see [Preprocessing](#preprocessing-and-disk-caching)).
* **Normal Operation:** 495,000 rows (7 continuous days of attack-free normal operation) in `SWaT_Dataset_Normal_v1`, which is `Normal_v0` minus its first 30 minutes (tank draining, per the release's `readme.txt`); when both are present the loader picks v1. The first 21,600 rows (6 hours) represent the physical filling of the empty plant from empty (startup transient) and are dropped by the loader (`SWAT_STARTUP_ROWS` in `pafl/data/real.py`) before invariant mining, calibration, validation or any client sees the record.
* **Attack Evaluation:** 449,919 rows (4 days) containing 36 documented physical and network spoofing attacks (e.g., sensor spoofing, valve tampering, pump interlock overrides). Nothing is dropped. Labels come from the file's own `Normal/Attack` column, including rows spelled `A ttack`; `List_of_attacks_Final.xlsx` is not read. At the 5 s stride the labelled rows form 35 contiguous segments.
* **Dimensionality:** 51 process channels (25 continuous sensor readings, 26 discrete actuator state indicators).

### 1.3 Concrete Telemetry Example
| Timestamp | LIT101 (mm) | FIT101 ($m^3/h$) | MV101 (State) | P101 (State) | FIT201 ($m^3/h$) | LIT301 (mm) | Label |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `2015-12-28 10:00:00` | 522.4 | 2.45 | 2 (Open) | 1 (Off) | 0.00 | 812.1 | Normal |
| `2015-12-28 10:00:01` | 523.1 | 2.44 | 2 (Open) | 1 (Off) | 0.00 | 812.0 | Normal |
| `...` | ... | ... | ... | ... | ... | ... | ... |
| `2015-12-28 10:29:14` | 780.2 | 0.00 | 1 (Closed) | 2 (On) | 2.38 | 805.4 | Attack |

The values are illustrative, not rows of the record. The actuator encoding is the one the loaders and miners expect: SWaT valves and pumps read 1 = closed/off and 2 = open/on, and a valve in transit reads 0.

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
* **Sampling Cadence:** 1 Hz (1 sample per second); loaded at a 5 s stride, like SWaT.
* **Normal Operation:** 1,209,601 rows (14 consecutive days of attack-free normal operation). No rows are dropped by this repository's loader (Zhu et al. 2025 drop the first 20,000; `pafl` does not).
* **Attack Evaluation:** 172,801 rows (2 days) containing 15 multi-point cyber-physical attacks affecting consumer pressure, tank levels, and chemical dosing. The file carries no labels: the loader builds them from `attack_description.xlsx`, which must be present. Two pairs of attack intervals overlap, so the labels form 14 contiguous segments.
* **Dimensionality:** 127 raw columns (OPC server tags), cleaned to 124 active process variables (65 continuous sensors and 59 discrete actuators) by removing non-physical logging derived flags. The loader then drops four channels that are empty in both files (`2_LS_001_AL`, `2_LS_002_AL`, `2_P_001_STATUS`, `2_P_002_STATUS`) and forward-fills short gaps, leaving 120 (65 continuous, 55 discrete). Actuators read 1 = closed/off and 2 = open/on, as on SWaT.

### 2.3 Concrete Telemetry Example
| Timestamp | 1_AIT_001_PV | 1_FIT_001_PV ($m^3/h$) | 1_P_001_STATUS | 2_LT_001_PV (Level %) | 2_MV_001_STATUS | Label |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `10/9/2017 18:00:00` | 7.41 | 1.82 | 2 (On) | 58.4 | 2 (Open) | Normal |
| `10/9/2017 18:00:01` | 7.42 | 1.81 | 2 (On) | 58.4 | 2 (Open) | Normal |

The values are illustrative, not rows of the record. The raw files hold `Row`, `Date` and `Time` columns rather than one timestamp, and each tag is an OPC path (`\\WIN-25J4RO10SBF\LOG_DATA\SUTD_WADI\LOG_DATA\1_AIT_001_PV`) that the loader cuts to the tag.

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
* **Dataset Version:** BATADAL Competition Datasets (`BATADAL_dataset03.csv`, `BATADAL_dataset04.csv`, `BATADAL_test_dataset.csv`). The loader reads `dataset03` (8,761 rows, one year of normal operation) and `dataset04` (4,177 rows, with attacks); `BATADAL_test_dataset.csv` is not used.
* **Sampling Cadence:** 1-hour intervals, not downsampled. The committed BATADAL federations use 5 clients (not the 10 of SWaT and WADI); after the clean slices for invariants (30 %), threshold validation (15 %) and the FLTrust root set (5 %) are taken from the front of `dataset03`, each client holds about 876 rows.
* **Attacks:** 14 cyber-physical attack scenarios targeting SCADA communication, pump schedules, and tank overflow/depletion, across the competition files. In `dataset04`, the file used here, 219 rows are labelled attack, in 5 contiguous segments; rows marked `-999` (unlabelled) are treated as normal.
* **Dimensionality:** 43 operational channels (7 water tank levels `L_T1`..`L_T7`, 12 junction pressures `P_J280`..`P_J422`, 12 flow rates `F_PU1`..`F_PU11` and `F_V2`, and 12 status indicators `S_PU1`..`S_PU11` and `S_V2`). Every column name in `dataset04` starts with a space; the loader strips it.

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
* **Use in this repository:** HAI is read only by `scripts/separation.py` (`results/c1_hai_mined.json`). It reads the CSVs lying directly in the HAI folder, concatenates the first three `train*.csv` files in name order, and uses only the first `test*.csv` (`test1.csv`) as the real-attack reference.

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

The codebase includes a seeded simulator in [`pafl/data/synthetic.py`](pafl/data/synthetic.py): the same seed always gives the same record. It models three storage tanks in series with four pumps (source → PU1 → T1 → PU2 → T2 → PU3 → T3 → PU4 → demand), with sensor noise, correlated flow noise, a two-step actuator delay and a daily demand cycle. Columns follow the BATADAL names (`L_T*`, `F_PU*`, `S_PU*`).

* **Usage:** Requires **zero external downloads**. Runs out-of-the-box for unit testing, mathematical verification, and fast algorithm debugging.

---

## Data Placement and Environment Setup

Dataset locations are resolved by [`pafl/utils/paths.py`](pafl/utils/paths.py), and the files are read by [`pafl/data/real.py`](pafl/data/real.py). The data root is, in order:
1. The `PAFL_DATA_DIR` environment variable (if set).
2. The `data/` folder at the top of this repository (a symlink is fine). This is not the `pafl/data/` code package.
3. A sibling `../data/` folder beside the repository checkout, used only when `data/` does not exist.

Inside the root, each dataset folder is found by name without regard to case (`swat`, `wadi`, `batadal`, `hai`). The drivers also take `--data-dir <dataset folder>`, which names one dataset's folder directly.

### Expected Directory Layout
To run the full suite of experiments, organize your local non-committed data directory as follows:

```
data/                               # at the repository root (or export PAFL_DATA_DIR=/path/to/datasets)
├── SWaT/
│   └── SWaT.A1 & A2_Dec_2015/
│       └── Physical/
│           ├── SWaT_Dataset_Normal_v1.xlsx
│           └── SWaT_Dataset_Attack_v0.xlsx
├── WaDi/
│   └── WADI.A1_9 Oct 2017/
│       ├── WADI_14days.csv
│       ├── WADI_attackdata.csv
│       └── attack_description.xlsx
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

The SWaT and WADI folders are searched recursively, so the release sub-folders shown above can stay as shipped; files are matched by name (`Normal`/`Attack` for SWaT, preferring a CSV export over the `.xlsx`; `14days`, `attack` and `attack_description` for WADI). The BATADAL and HAI files must sit directly in their folders.

### Preprocessing and Disk Caching
* **Automatic Caching:** Parsing raw Excel files (`.xlsx`) takes over a minute per run. The loader stores the parsed SWaT and WADI frames as pickles in a `.pafl_cache/` folder inside each dataset folder (`PAFL_CACHE_DIR` overrides the location). Subsequent runs load in seconds. BATADAL is small and not cached. The cache key covers the file, the stride, the skipped rows and the file's modification time, but not the loader's code: delete `.pafl_cache/` after changing a loader.
* **Downsampling:** SWaT and WADI are loaded at a stride of 5 rows, i.e. one row per 5 s. After the start-up cut the SWaT normal record goes from 473,400 rows to 94,680 and the attack record from 449,919 to 89,984; WADI goes from 1,209,601 to 241,921 and from 172,801 to 34,561. Every committed SWaT and WADI result uses this stride, so a channel roll of 60 rows is 5 minutes and a 10-row window is 50 s. No driver exposes the stride: it is the `swat_downsample` argument of `load_real` in `pafl/data/real.py` (it applies to WADI too), and changing it changes every number.
