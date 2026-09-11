# Plan to 28 September — Physics-Attested Federated Learning

**Owner:** Jeff Nijsse. **Target:** MDPI *Information*, special issue "Innovative AI Solutions for
Cybersecurity in Critical Infrastructures", submission **Mon 28 September 2026**. **Repo:**
https://github.com/RMIT-BDSL/pafl (private). **Paper text:** Overleaf, not this repo.
**Dated record of runs and findings:** `LOG.md` (untracked, on Jeff's laptop). **Project introduction:** `README.md`.

---

## 1. Decisions taken

| Date | Decision | Reason |
|---|---|---|
| Thu 10 Sep | The paper is the pilot extended to real federated data plus a pared-back ZK extension (PA-FL Lite); ICS-NAD, Fabric and Soroban are out | 18 days; compute was never the constraint, attention is |
| Thu 10 Sep | All experiments run on the laptop (≈ 20 s per SWaT cell); no AWS, no Colab | measured |
| Fri 11 Sep | **SWaT is the primary real record** (10 clients, headline tables); **BATADAL is the support record** (5 clients, its own table); the simulated plant is the pilot setting | SWaT has the attack diversity, client count and detector baseline to carry claims about aggregation rules; BATADAL has 876 rows per client and 219 attack rows |
| Fri 11 Sep | **WADI added** as an attempted third real record with a one-day cap; criterion 1 passed the same day, so it enters as a second physical testbed for rejection behaviour | on disk; loader quirks known from `../zhu-2025-reprod` |
| Fri 11 Sep | **Report both invariant-set settings** (narrow: miner defaults, 5 SWaT rules; wide: r2 0.40 / off-ratio 0.10 / support 0.005, 9 rules), each with coverage, honest violation rate and damage removed | coverage becomes the explicit variable instead of a tuned threshold |
| Fri 11 Sep | **Channel-roll shift stated in plant time**: 5 min on SWaT (60 rows at the 5 s stride) | 7 rows was 35 s on SWaT and nearly free to repair |
| Fri 11 Sep | Damage on real data is **recall on the targeted attacks**, measured against the **honest-only** federation (same honest shards, attacker absent) | global F1 never moves under a targeted poison; the ten-client clean run differs by composition |
| Fri 11 Sep | Repo holds code, tests, scripts and the result JSON the paper reads; no data, no caches, no LaTeX, no pilot-only material | licences; Overleaf owns the paper |

**Open decision (Jeff):** whether the abstract's real-data sentence is the coverage sentence (§4, point 3).

---

## 2. Current state (Fri 11 Sep)

| Item | State | Evidence |
|---|---|---|
| Criterion 1, BATADAL (real benchmark) | Done, passed; unchanged by the miner fix | `results/c1_batadal_*.json` |
| Criterion 1, SWaT (physical testbed) | **Done, passed** with the narrow (5) and wide (9) invariant sets; honest false-reject 0 | `results/c1_swat_*.json` |
| Criterion 1, HAI | Done, fails; scope boundary | `results/c1_hai_mined.json` |
| Criterion 1, WADI | **Done Fri 11, passes** (7 couplings, 0 balances, default miner) | `results/c1_wadi_default_shift60.json` |
| Criteria 2–4b, simulated plant (pilot) | Done; re-run after the oversampling fix, result holds | `results/sim_adaptive_3seed.json`, `results/sim_defences_mal30_2seed.json` |
| Criteria 2–4b, **SWaT**: 7 rules × 8 attacks × 3 seeds baselines; adaptive attacker (channel roll, replay), 7 rules, 5 modes incl. gated, 5 seeds, two invariant sets; 4b traces | **Done** | `results/swat_sweep_wide_3seed.json`, `results/swat_adaptive_wide_*_5seed.json`, `results/swat_adaptive_narrow_roll60_3seed.json`, `results/swat_trust_traces_wide_3seed.json` |
| Criteria 2–4b, **BATADAL** (5 clients, 3 rules, 3 seeds) | Done; weak signal, support only | `results/batadal_adaptive_*_3seed.json` |
| Criteria 2–4b, **WADI** | Running Fri 11 (3 rules, 5 modes, 3 seeds, target budget 10 %); detector weak (F1 0.26), expected role: rejection behaviour, not removal ratios | `results/wadi_adaptive_*` (in progress) |
| Recipe B | Done on SWaT, 7 rules × 3 seeds | in `swat_sweep_wide_3seed.json` |
| ZK extension (PA-FL Lite) | Not started; toolchain present (circom, snarkjs, node) | `zk/README.md` |
| Paper | Pilot draft complete; MDPI port not started | `pilot-paper/pilot-paper.tex` |
| Repo | **On GitHub** (private, org): https://github.com/RMIT-BDSL/pafl, first push Fri 11 | — |
| Collaborators / editor | On board / interested; abstract and scope message are Jeff's | — |

---

## 3. Scope of the submission

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

---

## 4. The claims the paper makes (as the evidence stands on Fri 11 Sep)

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

---

## 5. The ZK extension: PA-FL Lite

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

---

## 6. Schedule, 10 to 28 September

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

---

## 7. Paper assembly (on Overleaf)

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

---

## 8. Defects found and fixed (Thu 10 Sep; details in LOG.md)

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

---

## 9. Open items

- [ ] Jeff: message collaborators (scope per §3, the claims in §4, PA-FL Lite instead of the full circuit); soften the "Full Study Plan" sentence in the pitch.
- [ ] Jeff: send the 250-word abstract to the *Information* editorial office.
- [ ] Jeff: the coverage sentence as the abstract's real-data claim.
- [ ] WADI adaptive runs finish; rename the two result files to the convention; commit.
- [ ] ZK Day A–D per §5.
- [ ] Figures and tables from `results/` for Overleaf (`scripts/tables.py`, a figure script to write).
