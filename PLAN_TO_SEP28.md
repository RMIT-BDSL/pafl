# Plan to 28 September — Physics-Attested Federated Learning

*Written 10 September 2026. Supersedes `../NEXT_STEPS.md` (2 September), which assumed week 2 had
run and budgeted 500 GPU-hours. Neither was true. Short sentences on purpose, as in the other docs.*

**Owner:** Jeff. **Deadline:** MDPI *Information*, special issue "Innovative AI Solutions for
Cybersecurity in Critical Infrastructures", **28 September 2026**. **Days left: 18.**
**Working directory for everything:** this folder, `pafl/`. The `pilot/` folder is frozen.

---

## Decision (Jeff, Fri 11 Sep): SWaT is the primary real record; BATADAL is the support record

Three settings appear in the paper, named consistently: **SWaT** (physical testbed telemetry, 10
clients, headline tables and figures), **BATADAL** (published benchmark from a hydraulic simulation
of the C-Town network, 5 clients, second real record with its own table), and **the simulated plant**
(our three-tank simulator, the pilot results). Reason: SWaT has the attack diversity, client count and
detector baseline to carry claims about aggregation rules; BATADAL is too short (876 rows per client,
219 attack rows, F1 0.47) to do more than confirm criterion 1 and the direction of the effect.

---

**Also decided Fri 11:** (c) **add WADI** (iTrust water-distribution testbed, on disk) as an attempted third real record, one-day cap: loader + criterion 1 first; if criterion 1 passes it gets the adaptive runs and a table, if not it is a scope paragraph like HAI. (a) report **both** invariant-set settings (narrow, 5 rules; wide, 9 rules)
side by side, with coverage, honest violation rate and damage removed for each, so coverage is the
explicit variable rather than a tuned threshold; (b) state the channel-roll shift in **plant time**:
5 minutes (60 rows at the 5 s stride) on SWaT, and give the row equivalent for each setting.

## Morning summary, Fri 11 Sep (read this first; §0 has the detail, §4b the narrative)

**Done overnight.** Eight defects fixed (54 tests). Criterion 1 passes on SWaT. The pilot's simulator
result survives a confound fix. The complete SWaT sweep is in `results/`: 7 rules × 8 attacks × 3
seeds (baselines), the adaptive attacker for channel roll and for the replay attacker under two
invariant sets and a gated (deployed) mode, 4b with FoolsGold, BATADAL support runs, Recipe B. The
week-2, week-3 and week-4 experiment plans are therefore complete, five days early, on a laptop.

**Three numbers.**

| | |
|---|---|
| Fabricated telemetry rejected by the check (SWaT, all fabrications, all seeds) | 100 % |
| Replay attacker (real attack rows, no fabrication) rejected: narrow set / wide set | 1 of 3 seeds / 3 of 3 seeds |
| Targeted damage removed by the deployed gate, wide set, 5 seeds, vs the honest-only reference: FedAvg / median / norm clip / trimmed mean | replay attacker 71 / 103 / 104 / 91 %; channel roll 92 / 101 / 100 / 89 % (projection alone: 3–55 %) |

**What changed in the story.** On real data the poison is *exposure*, not fabrication, and the gate
removes exactly the part that rides on physics the invariant set covers (§4b); with the gate enforced, that is 70–100 % of the targeted damage on SWaT under the wide set. The FLTrust reversal
does not appear on SWaT. Global F1 is the wrong metric; targeted recall is the damage measure.

**Decisions for you (Sat 12 at the latest).**
1. ~~Primary record SWaT, BATADAL as support at 5 clients~~ confirmed Fri 11.
2. ~~Invariant-set setting~~ decided Fri 11: report both.
3. ~~Roll shift~~ decided Fri 11: plant time, 5 min on SWaT.
4. Whether the abstract's real-data sentence is the coverage sentence (§4b, point 3). I think it must be.
5. ~~`git init`~~ done Fri 11: https://github.com/RMIT-BDSL/pafl

**All queues finished at 00:20; nothing to restart.** Summarise any file with
`.venv/bin/python scripts/summarize_adaptive.py <json>`; LaTeX tables with `scripts/tables.py`.

---

## 0. Status log

**Thu 10 Sep, evening.** Defects 1, 2, 3, 5 and 6 of §6 are fixed; 4 is documented (BATADAL
supports at most 5 clients of 876 rows under the current slices). Tests: 54 pass.

- **Criterion 1 passes on SWaT** through the federation's own loader and miner
  (`make day1-swat`, `results/day1_swat*.json`): 3 exact couplings (MV101→FIT101, P101→FIT201,
  MV201→FIT201; cv 2–3 %) and 2 balances (LIT101 R² 0.62, LIT301 0.70). Honest violating fraction
  0.0020 (not 0 as on BATADAL: transition lag); false-reject 0.000. Channel roll violates 2.8 % of
  rows at the recipe's 7-row shift (35 s at the 5 s stride), 28 % at 60 rows, 75 % at 300 rows;
  within-regime permutation 22 %, conservation scaling 89 %, regime splicing 0.2 % (admitted).
  Real SWaT attack rows violate 2.05 % and are rejected as a batch. **The roll shift must be
  stated in plant time, not rows**; decide the paper's value (60 rows = 5 min is the natural pick).
- **BATADAL unchanged** (fitted 9 invariants; mined 10 from 53). HAI unchanged (fails, 3 rules).
- **Two more defects found and fixed.** (7) The pilot's *projected* variant re-windowed the
  projected batch without the malicious client's attack-window oversampling, so it differed from
  the fabricated variant in two ways, not one. Fixed via `ClientData.train_index` and the shared
  `pafl/fl/variants.py`. **The pilot result survives**: FedAvg 103 % removed (was 104), trimmed mean
  116 % (was 110), FLTrust −118 % (was −171). One sentence in the paper. (8) On SWaT the scaler
  divided six constant actuators by 1e-8 and the AIT analyser channels drift by up to 18 σ between
  the normal and attack records; clean F1 was 0.27 at precision 0.16. Scaler floor + AIT exclusion
  (stated in the paper) → **clean F1 0.756, AUC-PR 0.80, best-F1 0.79** on real SWaT.
- **Real-data construction now mirrors the simulator**: whole attack segments spliced into the
  malicious shard *before* fabrication (one coordinated target set per seed), the physics check
  sees the whole batch, and two positives-only eval sets report **recall on targeted vs. untargeted
  attacks**. One seed, FedAvg: global F1 unchanged (−2 pts), targeted recall −8.4 pts, untargeted
  ±0; trimmed mean −4.9 / ±0. The global F1 is the wrong metric for a targeted poison on 36
  diverse attacks; targeted recall is the paper's damage measure on real data.
- **Compute**: a SWaT cell takes 16 s on this laptop.
- **Open, running overnight**: the physics-aware (projected) attacker on SWaT for FedAvg, trimmed
  mean, FLTrust (`results/day45_swat_roll7_s0.json`), and the **exposure-only control**
  (`splice_only`: real attack rows replayed as normal, no fabrication). If the control passes the
  check and does the same targeted damage as channel roll, the physics gate closes the fabrication
  channel but not the replay channel, and the paper must say exactly that.

- **First real-data adaptive result (SWaT, seed 0, 7-row shift): the projection removes 0 % of the
  targeted damage.** FedAvg targeted recall 0.358 clean → 0.274 fabricated → 0.274 projected;
  trimmed mean 0.323 → 0.274 → 0.274; FLTrust 0.369 → 0.325 → 0.315. The projection cost the
  attacker 0.003–0.016 σ and under a second. Reason: the poison is *exposure* (real attack rows
  replayed as normal), and the two target attacks of this seed are consistent with the five mined
  invariants, so the check has nothing to repair. The **exposure-only control** (`splice_only`)
  confirms it: admitted by the check in seed 0 (0.2 % violating), rejected in seeds 1 and 2 (1.3–1.8 %)
  where the target set includes physics-violating attacks.
- **Invariant coverage is the governing quantity.** Under the five mined invariants, 12 of 35 SWaT
  attack segments violate at > 1 % of rows, but they hold only 1,137 of 10,931 attack rows: the
  10-hour attack (segment 21) and 22 others are invisible to this set. On the simulator every attack
  violated the physics, which is why the pilot saw 100 % removal. **The paper's real-data claim
  becomes: the gate removes the poison that rides on physics the invariant set covers, and it
  closes the fabrication channel entirely; it does not touch a replay of physics-consistent
  attacks.** That is a coverage result, and it links directly to the invariant-mining literature
  (Zhu 2025: 11–22 of 36 attacks with thousands of rules). Three-seed runs at a 5-minute shift are
  in progress (`results/day45_swat_roll60_3seed.json`, `results/swat_probe_roll60_3seed.json`).

- **Control confirmed (seed 0):** `splice_only` does the same targeted damage as channel roll
  (−8.40 pts FedAvg, −4.91 trimmed mean) and the physics check **admits** it (100 %) while it
  **rejects** the rolled version (0 %). The fabrication adds nothing to the exposure attack here;
  the gate removes the fabrication, not the exposure.
- **The lever works at criterion 1.** Miner thresholds r2_min 0.40, off-ratio 0.10, support 0.005
  give 9 invariants (6 couplings, 3 balances incl. LIT401); honest violations 0.35 %, false-reject
  0; **real attack rows now violate at 65 %** (was 2 %), 20 of 35 segments covered (82 % of attack
  rows). Channel roll at a 5-min shift: 30 %. Running: the adaptive attacker under the wide set for
  channel roll and for `splice_only` (`results/day45_swat_wide_*_3seed.json`). The projected
  splice-only attacker is the real physics-aware replay adversary; whether its exposure poison
  survives the projection is the paper's central real-data number.

- **Narrow set (5 invariants), 5-min shift, 3 seeds** (`results/day45_swat_roll60_3seed.json`,
  `results/swat_probe_roll60_3seed.json`): targeted-recall damage under FedAvg 6.6 pts (channel roll)
  and 8.6 pts (splice-only), per-seed 8.4 / 0.2 / 11.2 — seed 1's target set (11 segments, clean
  targeted recall 0.20) is barely poisonable at all. Projection removes 2.7 % of the damage under
  FedAvg, 7 % under FLTrust, 50 % under trimmed mean (all of it from seed 2). The check admits the
  splice-only attacker in 1 of 3 seeds and the rolled attacker in 0 of 3; after projection it admits
  everything. Global F1 never moves by more than 1 pt in any cell.

- **Wide set (9 invariants), 3 seeds** (`results/day45_swat_wide_*_3seed.json`): the check now
  rejects the splice-only attacker in **3 of 3** seeds before projection, and after projection only
  **56 %** of malicious batches pass (violating 0.8–0.9 % after 30 solver passes against a 0.5 %
  target): with actuator states protected, some real attack rows cannot be made physics-consistent
  without changing the actuators, which would change the attack. Targeted damage under FedAvg,
  splice-only: 8.6 pts → 6.4 pts after projection (26 % removed; seed 2: 17.3 → 10.8). Channel
  roll: 3 % removed (FedAvg), 49 % (trimmed mean). Every prior cell still *aggregated* the rejected
  clients, because the pilot's projected batches always passed. **Added a `gated` mode** (projected
  attacker, rejected batches excluded from the round): the deployed system's number. Overnight queue
  restarted with it (`results/overnight_sep10.log`).

- **Gated mode, wide set, channel roll, 7 rules** (`results/day45_swat_wide_roll60_3seed.json`, ~22:00):
  read per seed, not averaged. Seed 0: no client excluded (all projected batches pass), gate removes
  0 %. Seed 2: one of three excluded, FedAvg targeted recall 0.304 → 0.192 → 0.282 gated (80 %
  removed). Seed 1: the naive attack did no damage, and the gate excluded all three, so the
  7-client federation's higher recall is a baseline shift, not removal. **Aggregation rule fixed in
  both summary tools:** removal is damage-weighted over the seeds where the naive attack cost ≥ 1 pt
  (FedAvg: projection 3 %, gate 46 %, 2 of 3 seeds). A seed-averaged ratio would have printed 100 %.
  Do not let that number into the paper.

- **Seeds.** The target set is drawn per seed, and seed 1's set is not poisonable (clean targeted
  recall 0.20, naive damage 0.2 pt). Three seeds therefore leave one or two informative ones. A cell
  costs 20 s: run **five seeds** for the two headline SWaT files (`scripts/overnight_sep10_b.sh`,
  queued after the main run; the files keep their `_3seed` names for continuity).

- **Gated mode, wide set, splice-only (the physics-aware replay attacker), 7 rules, ~22:20**
  (`results/day45_swat_wide_splice_3seed.json`): FedAvg targeted damage 8.6 pts; projection alone
  removes 26 %, the gate 34 % (damage-weighted, seeds 0 and 2). Seed 0: 0 % (targets are
  physics-consistent even under the wide set; the projection repairs the LIT401 residuals at 0.05 σ
  and the exposure survives). Seed 2: 0.304 → 0.131 → 0.196 → 0.219 gated, one client excluded.
  Median 58 %, norm clip 55 %, trimmed mean 57 % (gate). **FLTrust on SWaT: acceptance of the
  malicious clients falls 0.10 → 0.05 after projection; the pilot's reversal does not reproduce on
  real data so far.** Krum rejects every malicious update in every condition. Fabricated batches
  (channel roll) were rejected by the check in 100 % of cells across all settings tonight.

- **SWaT baselines sweep done, 23:14** (`results/week2_baselines_swat_wide.json`, 168 cells, 7 rules ×
  7 attacks × 3 seeds, wide set). Clean F1 0.74–0.78, AUC-PR ≈ 0.80 for every rule. Targeted-recall
  drop under FedAvg: splice-only 8.6, channel roll 6.6, permutation 6.6, sign-flip 7.1, scaling 8.8,
  free-rider 2.2, min-max 2.6 pts. **The three data attackers are rejected by the physics check in
  100 % of cells; the check has nothing to say about the four update attacks.** Sign-flip is the one
  attack that also moves global F1 (7–8 pts under FedAvg, median, trimmed mean, norm clip); Krum and
  FLTrust stop it. FLTrust admits 99 % of scaling updates yet takes no damage (it normalises
  magnitudes). FLTrust and FoolsGold hold the data attackers to ≈ 1.5 pts. That is the
  complementarity table: physics gate for data attacks, robust rules for update attacks.
  **Krum caveat:** Krum shows the same 9.2-pt targeted drop for every attack, including ones where
  it accepts 0 % of malicious updates. Krum selects a single client, so replacing three honest
  shards by three malicious ones changes which honest client it picks; the drop is composition
  variance, not poisoning. Report Krum with that sentence, or compare against a 7-honest-client
  reference for it.

- **4b on SWaT, 23:20** (`results/week2_4b_swat_wide.json`, channel roll @60, wide set, 3 seeds).
  FLTrust gives the malicious clients a mean trust weight of 0.004 (fabricated) and 0.005
  (projected); acceptance 0.10 → 0.05; F1 damage −0.3 → +0.5 pts, targeted recall 0.283 → 0.289.
  FoolsGold: trust 0.10 → 0.13, acceptance 0.82 → 0.85, damage 0.0 → 0.8 pts. **No reversal on real
  data**: on SWaT the fabricated updates already sit far from FLTrust's root direction and the
  projection does not bring them back. The simulator reversal (acceptance 0.34 → 0.96) stands as a
  simulator result; the paper reports both and explains the difference by the update geometry
  (write the cosine-to-honest-mean traces from `trust_log` for both settings).

- **BATADAL support runs, 23:22** (`results/day45_batadal_*_3seed.json`, 5 clients, 2 malicious, 3
  seeds, default miner). Clean F1 0.47, targeted recall 0.34. Channel roll costs FedAvg 3.4 pts of
  F1 and 3.2 pts of targeted recall; projection removes 27 %. Splice-only costs 1.2–1.4 pts; nothing
  removed. Both attackers are rejected by the check before projection (all 219 BATADAL attack rows
  fit in the target budget, so every attack is targeted and there is no untargeted set). Every
  projected batch is admitted (mean shift 0.08 σ). BATADAL is thin as a federation: report it as the
  second real record with its numbers, not as a headline.

- **Recipe B trial, 23:23** (`results/probe_swat_recipe_b.json`): the first-order gradient-matching
  fabrication runs on SWaT in 22 s per cell, is rejected by the check, and does the same targeted
  damage as the other data attackers (0.358 → 0.274 under FedAvg, seed 0), because the damage is
  the exposure it carries. **Keep Recipe B** as a row; a 7-rule × 3-seed pass is chained after the
  five-seed follow-up (`scripts/_chain_c.sh`). Its full gradient-matching path is not needed.
- Queue status at 23:25: main queue done; follow-up (seeds 3–4 and `honest_only` for the two headline
  files) running, ≈ 1 h; Recipe B sweep after that, ≈ 10 min.

- **Five seeds + the `honest_only` reference, 00:12 Thu** (both headline files). Measured against the
  same seven honest shards without the attacker (the fair reference; the ten-shard clean run sits
  ≈ 2 pts higher in targeted recall for composition reasons alone), wide set, damage-weighted over
  seeds with ≥ 1 pt naive damage:

  | rule | replay attacker: projection / gate | channel roll @60: projection / gate |
  |---|---|---|
  | FedAvg | 24 % / **71 %** | 3 % / **92 %** |
  | Median | 43 % / 103 % | 53 % / 101 % |
  | Norm clip | 30 % / 104 % | 45 % / 100 % |
  | Trimmed mean | 11 % / 91 % | 55 % / 89 % |
  | FLTrust (small damage) | 75 % / 69 % | 41 % / 54 % |

  The gate excludes 1.8 of 3 malicious clients on average (check admits 40 % after projection).
  **The deployed gate removes 70–100 % of the targeted damage on SWaT for the rules that admit
  everything; projection alone removes 3–55 %.** The remaining 0–30 % is exposure riding on
  physics-consistent attack rows. This is the paper's real-data headline, stated with the coverage
  caveat (§4b). `summarize_adaptive.py` and `tables.py` now use `honest_only` as the reference when
  present.

- **Recipe B sweep done, 00:20 Thu** (in `results/week2_baselines_swat_wide.json`, now 189 cells).
  Recipe B (first-order gradient matching) is rejected by the check in every cell and does 6.0 pts of
  targeted damage under FedAvg (splice-only 8.6, channel roll 6.6); against trimmed mean and norm
  clip it does less (1.4, 2.7) than the simple attackers. FoolsGold admits it at 100 % (6.0 pts) where
  it admitted splice-only at 35 %: matching the honest gradient direction is what FoolsGold rewards.
  All overnight queues finished by 00:20; nothing failed; 55 tests pass on the morning of 11 Sep.

- **WADI, Fri 11 10:00** (`pafl/data/wadi.py`, `results/day1_wadi*.json`; loads in 15 s, cached).
  Criterion 1 **passes** with the default miner: 7 exact couplings (1_MV_001/1_P_001/1_P_003 →
  1_FIT_001, 1_P_005/2_MV_003 → 2_FIT_001, 2_MV_006/2_P_003 → 2_P_003_SPEED), **no tank balance**
  (all six candidates below R² 0.40: consumer demand is unmeasured on a distribution network, as on
  BATADAL). Honest false-reject 0 (0.12 % violating rows); channel roll @60 separated (44 %
  violating, 3 % of batches admitted), permutation separated (28 %), conservation scaling **not**
  separated (no balance to break), splicing not. Real attack rows violate at 12.4 %. The "wide"
  thresholds are not monotone on WADI (a rare third actuator state re-labels off/on and drops two
  couplings): WADI uses the default set. WADI is a second physical testbed for the paper.

- **WADI federation probe, 10:04** (`results/probe_wadi_fedavg_v2.json`). Two loader fixes first:
  four channels of the release are entirely empty and five analysers have gaps, so every window
  scored NaN (F1 0.0); dropped and filled. Then: 10 clients of 12,087 windows, 102 features, a cell
  takes 55–80 s. Clean F1 0.26, AUC-PR 0.35, best-F1 0.35: weak, as the WADI literature reports for
  autoencoders. All 14 attacks (1,996 rows at the 5 s stride) fit inside the 25 % target budget, so
  there was no untargeted set; damage 0.6 pts. Both the replay and the rolled attacker are rejected
  by the check. Running now (`scripts/wadi_runs.sh`, `results/wadi_runs.log`): the adaptive set for
  FedAvg, trimmed mean, FLTrust, 3 seeds, 5 modes, target budget 10 % so a subset of attacks is
  targeted. Expect WADI to enter the paper as **a second physical testbed for criterion 1 and the
  gate's rejection behaviour**, with its poisoning damage too small to support a removal ratio.

**Input for the Sat 12 decision:** SWaT is viable as the primary real record, and it changes the
headline. BATADAL is the support dataset at 5 clients. Decide on Friday whether to spend one day
widening the SWaT invariant set (more balances, pressure and stage-3/4 couplings) to raise coverage,
which is the one lever that moves the real-data number.

---

## 1. Where we are (refreshed Fri 11 Sep, morning)

| Item | State | Evidence |
|---|---|---|
| Criterion 1, BATADAL (real benchmark) | Done, passed; unchanged by the miner fix | `results/day1_batadal*.json` |
| Criterion 1, SWaT (physical testbed) | **Done, passed** with the narrow (5) and wide (9) invariant sets; honest false-reject 0 | `results/day1_swat*.json` |
| Criterion 1, HAI | Done, fails; scope boundary | `results/day1_hai_mined.json` |
| Criterion 1, WADI | **Done Fri 11, passes** (7 couplings, 0 balances, default miner) | `results/day1_wadi.json` |
| Criteria 2–4b, simulated plant (pilot) | Done; re-run after the oversampling fix, result holds | `results/day45_adaptive_3seed_v2.json`, `results/day2_mal30.json` |
| Criteria 2–4b, **SWaT**: 7 rules × 8 attacks × 3 seeds baselines; adaptive attacker (channel roll, replay), 7 rules, 5 modes incl. gated, 5 seeds, two invariant sets; 4b traces | **Done** | `results/week2_baselines_swat_wide.json`, `results/day45_swat_wide_*_3seed.json`, `results/day45_swat_roll60_3seed.json`, `results/week2_4b_swat_wide.json` |
| Criteria 2–4b, **BATADAL** (5 clients, 3 rules, 3 seeds) | Done; weak signal, support only | `results/day45_batadal_*_3seed.json` |
| Criteria 2–4b, **WADI** | Not started; runs only if criterion 1 passes | — |
| Recipe B | Done on SWaT, 7 rules × 3 seeds | in `week2_baselines_swat_wide.json` |
| ZK extension (PA-FL Lite) | Not started; toolchain present (circom, snarkjs, node) | `zk/README.md` |
| Paper | Pilot draft complete; MDPI port not started | `pilot-paper/pilot-paper.tex` |
| Repo | **On GitHub** (private, org): https://github.com/RMIT-BDSL/pafl, first push Fri 11 | — |
| Collaborators / editor | On board / interested; abstract and scope message are Jeff's | — |

Two facts that shaped the plan (Thu 10):

- **Compute is not a constraint.** A SWaT cell takes 16–20 s on this laptop; the whole experimental
  programme ran in one night. Do not use AWS or Colab.
- **SWaT failed criterion 1 on the code as copied** (fixed the same evening, §6 defect 1): the miner
  found no couplings because of SWaT's 1/2 actuator encoding and the transition lag.

---

## 2. Scope of the submission

The paper is the pilot paper extended to real federated data, plus a small zero-knowledge
extension that shows the enforcement path is real. It is not the full pitch.

| Pitch promised | Submission delivers | Why |
|---|---|---|
| Federation on ICS-NAD, BATADAL, SWaT | Federation on **SWaT** (10 clients, primary), **BATADAL** (5 clients, support), **WADI** (attempted, one-day cap; second physical testbed if criterion 1 passes), plus the simulated plant | ICS-NAD has no loader and is 246 GB; BATADAL is too short for 10 clients; WADI is on disk and its file quirks are known from `../zhu-2025-reprod` |
| Full defence set, three conditions | **Yes**: 7 rules × {honest, naive, physics-aware} × 3 seeds, for **two attackers**: fabricated (channel roll) and **exposure-only replay** (`splice_only`), under a narrow and a wide invariant set | cheap (20 s per cell); code exists |
| Recipe B (gradient matching) | First-order path only, **one day, cut if it misbehaves** | untested on real data |
| Update-space baselines | sign-flip, scaling, free-rider, min-max (drop ALIE, noise first) | code exists |
| FLTrust interaction, FoolsGold | **Yes**: 4b with trust traces on both rules | code exists |
| Groth16 circuit with Merkle commitment, sampling, invariant check, last-layer binding | **PA-FL Lite**: commitment + sampling + invariant check. **No gradient binding.** See §3 | 3 attention-days, not 3 weeks |
| Fabric and Soroban verification costs | Off-chain verification only; ledger costs as a stated next step | cut |
| HAI as a dataset | Scope boundary paragraph, as in the pilot paper | done |

RQ1 and RQ3 are the empirical core. RQ2 is answered in part by PA-FL Lite. RQ4 becomes a design
statement. **RQ3's real-data answer is a coverage statement** (see §0, 10 Sep): the gate removes the
poison that rides on physics the invariant set covers, and it blocks every fabricated batch, but an
exposure-only replay of physics-consistent attacks passes it and does the same damage. The damage
measure on real data is recall on the targeted attacks, not global F1. Tell the collaborators this in the next message to them, and soften the "Full Study Plan"
sentence in `../paper2-draft/pitch.tex` at the same time.

---

## 3. The ZK extension: PA-FL Lite

**Purpose.** Show, with measured numbers on the real invariant set, that a client can prove its
training batch satisfies the plant's invariants without revealing the batch. Nothing more.

**Statement proved.** The prover holds a batch *B* of *N* = 1,024 rows, committed as a Poseidon
Merkle root *R*. For each of *k* challenge indices *i*, the rows *x*<sub>*i*</sub> and
*x*<sub>*i*−1</sub> (both needed for a tank balance) satisfy every declared linear invariant
within its tolerance. Honest SWaT rows violate at a rate of 0.2 % (transition lag), so a
zero-violation rule over 2*k* = 64 opened rows would falsely reject about 12 % of honest batches.
The circuit therefore carries a violation budget *v* (counter of failed range checks, asserted
≤ *v*); *v* = 1 at *k* = 32 brings the honest false-reject rate under 1 %. Report both settings.

| | |
|---|---|
| Public inputs | *R*; invariant coefficients, constants and tolerances in fixed point (scale 2<sup>16</sup>); the *k* indices; the round nonce |
| Private inputs | the 2*k* rows; their Merkle paths (depth 10) |
| Sampling | Verifier derives the indices from Poseidon(*R*, nonce) **outside** the circuit and checks them as public inputs. Zero circuit cost. The client must publish *R* before it learns the nonce |
| Tools | circom 2.1.x, snarkjs, circomlib Poseidon, Hermez `powersOfTau28_hez_final_19.ptau` (2<sup>19</sup> constraints; fall back to power 18 with *k* = 16). Node heap flag on. Laptop has 36 GB |
| Default size | *k* = 32. Expect ~8–10k constraints per sample (two paths, two leaf hashes, ~10 residual range checks), so ~300k total. **These are estimates. Replace them with measured counts** |

**The demo that ties it to the experiments.** Three proofs from real batches taken out of the
sweep: an honest client's batch (proof verifies), a naive channel-roll batch (witness generation
fails on the residual check), a physics-aware projected batch (proof verifies). That is Fig. C4 in
proof form.

**What to measure and report.**

- Constraints by component (Merkle paths, leaf hashes, residual checks) against the design
  estimate already in the draft (16k of 600k for the residuals).
- Compile, setup, witness, prove and verify times; proof size; peak RAM. snarkjs WASM is enough;
  rapidsnark only if time is left.
- Scaling at *k* = 16, 32 and, if the ptau allows, 64.
- The analytic soundness table. A batch with violating fraction *f* passes *k* samples with
  probability (1 − *f*)<sup>*k*</sup>:

| *f* | *k* = 16 | *k* = 32 | *k* = 64 |
|---|---|---|---|
| 0.05 | 0.44 | 0.19 | 0.038 |
| 0.10 | 0.19 | 0.034 | 0.0012 |
| 0.36 (channel roll, simulator) | 0.0008 | 6×10<sup>−7</sup> | ~0 |
| 0.97 (channel roll, BATADAL) | ~0 | ~0 | ~0 |
| 0.0017 (regime splicing) | 0.97 | 0.95 | 0.90 |

The last row is the disclosed limitation again. Sampling does not fix splicing. Say so.

**What is explicitly out, and the sentence the paper needs.** PA-FL Lite proves that the client
holds a physically plausible batch. It does **not** prove that the submitted update was computed
from that batch. The last-layer gradient binding that closes this gap is specified in the design
section and is the next implementation step. Without that sentence a reviewer writes it for you.

**Time budget: three attention-days.**

| Day | Work | Output |
|---|---|---|
| A (½ day) | **Already installed on this machine (checked 10 Sep): circom (cargo), snarkjs 0.7.4, node 23.** Remaining: `npm i circomlib` in `zk/`, download the power-19 ptau, compile a 2-input Poseidon to confirm | toolchain works |
| B (1 day) | Write `zk/invariant_check.circom`: residual range-check template, Merkle inclusion, leaf hash. Export the mined `InvariantSet` to fixed-point JSON (`zk/export_invariants.py`). Test on the synthetic invariants at *k* = 4 | circuit compiles, tiny proof verifies |
| C (1 day) | Setup at *k* = 16 and 32 with the real invariant set. The three-proof demo. All measurements to `zk/results.json` | numbers |
| D (½ day) | Write the ZK subsection and its table | text |

**Cut-lines, fixed now (moved forward two days on 10 Sep, since the sweeps ran a week early).**
If the circuit is not proving by **Sat 19 Sep**, report compiled constraint counts only. If it does
not compile by **Wed 23 Sep**, keep the design estimate that is already in the draft and drop the
extension. Neither outcome moves the deadline.

---

## 4. Schedule, 10 to 28 September

Sweeps run on the laptop overnight. ZK work and writing take attention, so they sit on days when
the sweeps are running or done.

| Date | Experiments | ZK | Writing / admin |
|---|---|---|---|
| **Thu 10** | Copy `pilot/` → `pafl/` (done) | | Plan written. Message collaborators on scope (§2). Send the 250-word abstract to the editorial office |
| Thu 10, night | Defects 1–8 fixed. Criterion 1 on SWaT. `scripts/overnight_sep10.sh`: SWaT adaptive (7 rules, roll and splice-only, wide set), SWaT baselines sweep, SWaT 4b, BATADAL support runs, Recipe B trial | | |
| **Fri 11** | Read the overnight results with `scripts/summarize_adaptive.py`. Reruns. Decide the invariant-set setting (narrow vs wide) and the roll shift for the paper. `git init`, first commit | Day A (toolchain) | Jeff: abstract to the editorial office; scope message to collaborators |
| **Sat 12** | **WADI, one-day cap:** `pafl/data/wadi.py` (labels from the attack time table), WADI branch in `load_real`, criterion 1 (`day1 --dataset wadi`), then if it passes the adaptive runs (`day45 --dataset wadi`, 7 rules, 5 modes, 3 seeds, ≈ 1 h) and the baselines sweep overnight. Coverage table per attack segment for SWaT | Day A (toolchain) | |
| **Sun 13** | WADI results read; keep or scope-paragraph. Any missing SWaT cells | Day B (circuit) | Port `pilot-paper.tex` into the MDPI template |
| Mon 14 | IID contrast row (one seed) if time | finish Day B; Day C with the real invariant set and real batches from the sweep | Setting, threat model, datasets, real-data construction |
| Tue 15 – Wed 16 | Extend `pilot-paper/make_figures.py` to the new JSON. Tables and figures | | Results section: criteria 1–4b on SWaT and simulator; coverage; control |
| **Thu 17** | Reruns if any cell failed | Day D | ZK subsection |
| Fri 18 – Sat 19 | | ZK cut-line 1 (Fri): constraint counts only if not proving | 4b section, FoolsGold. Discussion |
| Sun 20 – Mon 21 | | | Limitations, enforcement design, related work |
| Tue 22 – Thu 24 | | ZK cut-line 2 (Wed 23): design estimate only | Full draft to collaborators Tue 22. Revisions |
| Fri 25 – Sat 26 | | | Co-author review. Ethics paragraph. Data availability. Zenodo DOI on the commit |
| Sun 27 | | | Buffer. Full read |
| **Mon 28** | | | **Submit** |

Cut order if the experiments slip, unchanged from the week-2 manual: drop the IID contrast → drop
ALIE and additive noise → 3 seeds to 2 → drop Recipe B → 10 clients to 5 (BATADAL only).

---

## 4b. Emerging narrative (written 10 Sep, 22:30, for Jeff to react to in the morning)

1. **Fabricated telemetry is a solved problem for the gate.** Every fabricated batch (channel roll at
   any shift, permutation, scaling) was rejected on BATADAL and SWaT, with zero honest false
   rejections, by an automatically mined invariant set. The simulator result (100 % of the damage
   removed against an adaptive attacker) holds after the confound fix.
2. **The real threat on a real plant is replay, not fabrication.** An attacker who splices real
   attack telemetry into an honest shard and presents it as normal does the same targeted damage as
   the fabricated attacker and needs no physics violation of its own. Whether the gate sees it
   depends on whether the *attacks* violate the plant's invariants.
3. **Coverage is the governing quantity, and it is a knob the defender controls.** Five mined
   invariants see 12 of 35 SWaT attacks (10 % of attack rows); nine see 20 (82 %), at 0.35 % honest
   violations. Under the wide set the replay attacker is rejected in every seed; after adapting it
   recovers admission for 56 % of its batches, because with actuator states held fixed some attack
   rows cannot be made consistent. With the gate enforced (rejected clients excluded), 70–100 % of
   the targeted damage is removed on SWaT for FedAvg, median, norm clip and trimmed mean (5 seeds,
   honest-only reference); projection alone removes 3–55 %. The poison that survives is the part that
   rides on physics-consistent attacks: 0 % removed in a seed whose targets are consistent.
4. **Metric.** A targeted poison on 36 diverse attacks does not move global F1 (never more than
   1 pt tonight). Recall on the targeted attacks moves 5–17 pts. Report targeted and untargeted
   recall, AUC-PR and best-F1; explain why.
5. **The gate is necessary, not sufficient, and it composes.** Krum stops the replay attacker
   outright on SWaT; FedAvg, median and norm clipping admit everything and the gate is what removes
   the poison for them. The FLTrust interaction found on the simulator does not appear on SWaT
   (acceptance falls after projection); report both, do not generalise either.
6. **Enforcement is buildable.** PA-FL Lite (§3) with a violation budget, on the nine-invariant set.

What this is not: it is not "physics removes 100 % of attack capability on real data". The
abstract's real-data sentence should be the coverage sentence in point 3.

---

## 5. Paper assembly

Start from `pilot-paper/pilot-paper.tex`. It already has the setting figure, the threat model, the
criteria table, five results figures generated from JSON, the enforcement design with the
constraint budget, and the limitations. Add:

1. **Real-data federation results** for criteria 2–4b on SWaT (headline), BATADAL (support) and
   WADI (if criterion 1 passes), with the simulated plant kept as the pilot setting. Every number says which setting it came from. The pilot paper does this; the
   dashboard and pitch did not until 10 Sep.
2. **The full defence set** including FoolsGold, and the update-space attacks as the
   complementarity table (physics check catches data fabrications, robust rules catch update
   attacks).
3. **4b with both similarity rules** and the trust traces.
4. **PA-FL Lite** as a subsection of the enforcement section, with the measured table and the
   sentence from §3.
5. **Two new results the pilot did not have.** (a) The **exposure-only control** and the
   **coverage table**: which SWaT attack segments the invariant set can see, and therefore which
   poison the gate can remove. (b) The **metric argument**: on 36 diverse attacks a targeted poison
   does not move global F1; report recall on the targeted attacks beside untargeted recall, AUC-PR
   and best-F1, and say why. Also state the SWaT preprocessing choices (6 h start-up dropped, 5 s
   stride, AIT analyser channels excluded from the detector, unit scale for constant actuators) in
   one paragraph, each with its reason.
6. **Limitations**: single-plant temporal split as the federation, regime splicing, exposure-only
   replay of physics-consistent attacks (the gate is necessary, not sufficient), no update binding,
   seeds, round count chosen by budget, the miner thresholds as a knob (report both settings).
7. MDPI front matter: Author Contributions, Funding, Data Availability, Conflicts of Interest.
   Check the Instructions for Authors page for length guidance (the page blocks scripted access;
   open it in a browser).

Title stays close to the pilot paper's question. Do not title it "zero-knowledge admission
control" when the binding is not built.

---

## 6. Defects to fix before any run (✅ fixed 10 Sep, ⚠ documented; see §0 for 7 and 8)

| # | Defect | Where | Fix |
|---|---|---|---|
| 1 ✅ | Coupling miner finds 0 couplings on SWaT. It tests the **maximum** off-state flow against 5% of full scale; SWaT's off state has a transition tail. It also treats the rare state 0 (transitioning) as "off" | `pafl/invariants/mine.py`, `mine_couplings` | Use a high quantile (e.g. 99th) of the off-state flow, not the max. Define off/on as the two most frequent states, ignore states under `min_support`. Re-run `test_week2.py::test_swat_invariants_find_the_coupling` and criterion 1 on SWaT |
| 2 ✅ | `find_swat_files` picks `List_of_attacks_Final.xlsx` as the attack file when pointed at the release root | `pafl/data/swat.py` | Prefer names containing `Dataset`; or point `--data-dir` at `data/SWaT/.../Physical/` |
| 3 ✅ | `week2_baselines.py` crashes on `recipe_b` for the synthetic dataset; dispatch exists only in `scenario_real` | `pafl/fl/scenario.py` | Route `recipe_b` through the same `_fabricate` helper, or skip that cell for synthetic |
| 4 ⚠ | BATADAL has 8,761 clean rows. After the 30/15/5% slices, 10 clients fall under `min_rows_per_client=500` | `pafl/fl/scenario_real.py`, `partition.py` | Smaller slice fractions, or 5 clients. State it in the paper |
| 5 ✅ | `day45_adaptive.py` is synthetic-only | `scripts/day45_adaptive.py` | Add the `--dataset swat|batadal` branch that `week2_4b.py` already has, so the projected attacker runs on real data for all 7 rules |
| 6 ✅ | SWaT `.xlsx` loads take ~80 s each (pickle cache in `data/SWaT/.pafl_cache/`) | `pafl/data/real.py` | Export once to CSV in the original label format (`Normal/Attack`, `Timestamp`) and point `--data-dir` at the CSVs. A CSV re-export in the pilot loader's own format sets `ATT_FLAG` to zero, so keep the original column names |

Also drop the first 21,600 SWaT rows (6 h start-up transient), as the literature does, before
fitting invariants.

---

## 7. What was copied here, and what was not

Copied from `pilot/`: the `pafl/` package, `scripts/`, `tests/`, `docs/`, `results/`,
`pilot-paper/`, `Makefile`, `requirements.txt`, `README.md`, the results dashboard and tutorial.
`data/` is a symlink to `../datasets/` (BATADAL, HAI, SWaT, WaDi), which the path resolver finds
case-insensitively. A fresh `.venv` was created; run everything with `.venv/bin/python`.

Not copied: `platform/aws/` (not needed), the Colab notebook (not needed), `_scratch/`, caches.
`zk/` is new and empty; it holds the PA-FL Lite work from §3.

`README.md` still describes the week-1 pilot. Rewrite its first section once the primary dataset is
decided.

---

## 8. Next 48 hours

- [ ] Message collaborators: scope per §2, primary-dataset decision on Sat 12, PA-FL Lite instead of the full circuit.
- [ ] Send the 250-word abstract to the *Information* editorial office.
- [x] Fix defects 1–3. Run `make test`. (done Thu 10; defects 1–8 fixed, 55 tests)
- [x] Run criterion 1 on SWaT and BATADAL through `scenario_real`. (done Thu 10; SWaT passes, `results/day1_swat*.json`)
- [x] Decide the primary dataset. (Jeff, Fri 11: SWaT primary, BATADAL support; written at the top)
- [x] Fix defect 5. (done) — [x] `git init` and first commit pushed Fri 11 to https://github.com/RMIT-BDSL/pafl (private, org repo; no data, no paper material — Overleaf owns the paper).
- [x] Sweeps ran overnight Thu 10 → Fri 11; all finished 00:20.
- [x] WADI loader + criterion 1 (done Fri 11, a day early; passes).
