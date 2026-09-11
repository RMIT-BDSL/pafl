# pafl — Physics-Attested Federated Learning

Code, tests and result files for the paper on physics-based admission control for
federated intrusion detection in industrial control systems (MDPI *Information*,
special issue on AI for critical-infrastructure cybersecurity, submission 28 Sep 2026).

The claim under test: a federated detector should check the **data** a client trained
on, not only the **update** it submitted, and industrial telemetry makes that possible
because it obeys plant physics that an automatically mined invariant set can verify.

Plan, status log and decisions: [`PLAN_TO_SEP28.md`](PLAN_TO_SEP28.md).

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/ -q          # ~10 s
```

Data is not in the repository. Put the dataset folders under `data/` (or symlink a shared
folder): `data/SWaT/...` (iTrust, request-based, no redistribution), `data/WaDi/...` (iTrust),
`data/BATADAL/` (public), `data/HAI/` (public). Loaders cache parsed frames beside the data.

## Layout

```
pafl/
  data/            loaders (swat, wadi, batadal, synthetic), windowing, scaling
  invariants/      invariant spec, automatic miner (couplings, balances), calibration
  attacks/         Recipe A fabrications, Recipe B (gradient matching), update attacks, projection
  fl/              models, defences (FedAvg, Krum, median, trimmed mean, norm clip, FLTrust, FoolsGold),
                   training loop, synthetic and real scenario builders, variant builder (clean /
                   honest_only / fabricated / projected / gated)
  eval/            metrics (F1, best-F1, AUC-PR, delay, targeted recall)
scripts/
  day1_residuals.py      criterion 1: do invariants separate honest from fabricated batches
  day2_defences.py       criteria 2-3 on the simulated plant
  day45_adaptive.py      the adaptive attacker: clean / honest_only / fabricated / projected / gated
  week2_baselines.py     defences x attacks sweep on real data
  week2_4b.py            FLTrust / FoolsGold trust traces
  summarize_adaptive.py  tables from any day45 result file
  tables.py              LaTeX tables from a day45 result file
  overnight_sep10.sh     the sweep that produced results/ (resumable)
results/                 every result file the paper reads; no number is typed by hand
zk/                      PA-FL Lite, the zero-knowledge extension (see PLAN section 3)
```

Every driver is resumable: it writes its result file after each cell and skips finished
cells on restart. A SWaT cell takes about 20 s on a laptop CPU.
