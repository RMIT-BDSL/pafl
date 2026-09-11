# Plan to date — Physics-Attested Federated Learning



## 1. Near term stuff

| Date | Decision | Reason |
|---|---|---|
| Thu 10 Sep | The paper is the pilot extended to real federated data plus a pared-back ZK extension (PA-FL Lite); ICS-NAD, Fabric and Soroban are out (for now) | short on time |
| Fri 11 Sep | **SWaT is the primary real record** (10 clients, headline tables); **BATADAL is the support record** (5 clients, its own table); the simulated plant is the pilot setting | SWaT has the attack diversity, client count and detector baseline to carry claims about aggregation rules; BATADAL has 876 rows per client and 219 attack rows |
| Fri 11 Sep | **WADI added and run** (criterion 1 and the adaptive set the same day). It enters as the second physical testbed for criterion 1 and admission behaviour; it carries no damage or removal numbers | detector recall on WADI attacks ≈ 0.2; on disk; loader quirks known from `../zhu-2025-reprod` |
| Fri 11 Sep | **Report both invariant-set settings** (narrow: miner defaults, 5 SWaT rules; wide: r2 0.40 / off-ratio 0.10 / support 0.005, 9 rules), each with coverage, honest violation rate and damage removed | coverage becomes the explicit variable instead of a tuned threshold |
| Fri 11 Sep | **Channel-roll shift stated in plant time**: 5 min on SWaT (60 rows at the 5 s stride) | 7 rows was 35 s on SWaT and nearly free to repair |
| Fri 11 Sep | Damage on real data is **recall on the targeted attacks**, measured against the **honest-only** federation (same honest shards, attacker absent) | global F1 never moves under a targeted poison; the ten-client clean run differs by composition |
| Fri 11 Sep | Repo holds code, tests, scripts and the result JSON the paper reads; no data, no caches, no LaTeX, no pilot-only material | licences; Overleaf owns the paper |


---

## 2. Current state (Fri 11 Sep)

| Item | State | Evidence |
|---|---|---|
| Criterion 1, BATADAL (real benchmark) | Done, passed; unchanged by the miner fix | `results/c1_batadal_*.json` |
| Criterion 1, SWaT (physical testbed) | **Done, passed** with the narrow (5) and wide (9) invariant sets; honest false-reject 0 | `results/c1_swat_*.json` |
| Criterion 1, HAI | Done, fails; scope boundary | `results/c1_hai_mined.json` |
| Criterion 1, WADI | **Done Fri 11, passes** (7 couplings, 0 balances, default miner) | `results/c1_wadi_default_shift60.json` |
| Criteria 2–4b, simulated plant (pilot) | Done; it was re-run after the oversampling fix, result holds | `results/sim_adaptive_3seed.json`, `results/sim_defences_mal30_2seed.json` |
| Criteria 2–4b, **SWaT**: 7 rules × 8 attacks × 3 seeds baselines; adaptive attacker (channel roll, replay), 7 rules, 5 modes incl. gated, 5 seeds, two invariant sets; 4b traces | **Done** | `results/swat_sweep_wide_3seed.json`, `results/swat_adaptive_wide_*_5seed.json`, `results/swat_adaptive_narrow_roll60_3seed.json`, `results/swat_trust_traces_wide_3seed.json` |
| Criteria 2–4b, **BATADAL** (5 clients, 3 rules, 3 seeds) | Done; weak signal, support only | `results/batadal_adaptive_*_3seed.json` |
| Criteria 2–4b, **WADI** | **Done Fri 11** (3 rules, 5 modes, 3 seeds). No measurable poison damage (detector recall on WADI attacks ≈ 0.2); gate rejects 100 % of rolled and 89 % of replay batches before adaptation, excludes 2 of 3 clients after. Role: rejection behaviour, not removal ratios | `results/wadi_adaptive_default_*_3seed.json` |
| Recipe B | Done on SWaT, 7 rules × 3 seeds | in `swat_sweep_wide_3seed.json` |
| ZK extension (PA-FL Lite) | Not started; toolchain present (circom, snarkjs, node) | `zk/README.md` |
| Paper | Pilot draft complete; MDPI port not started | `pilot-paper/pilot-paper.tex` |

---

## 3. Scope of the submission

The paper is the pilot paper extended to real federated data, plus a small zero-knowledge
extension that shows the enforcement path is real. It is not the full pitch.

| Pitch promised | Submission delivers | Why |
|---|---|---|
| Federation on ICS-NAD, BATADAL, SWaT | **SWaT** (10 clients, primary: all damage and removal numbers), **WADI** (10 clients, second physical testbed: criterion 1 and admission behaviour only), **BATADAL** (5 clients, support), plus the simulated plant | ICS-NAD has no loader and is 246 GB; BATADAL is too short for 10 clients; on WADI the detector's recall on attacks is ≈ 0.2, so poisoning has nothing to remove |
| Full defence set, three conditions | **Yes**: 7 rules × {honest, naive, physics-aware} × 3 seeds, for **two attackers**: fabricated (channel roll) and **exposure-only replay** (`splice_only`), under a narrow and a wide invariant set | cheap (20 s per cell); code exists |
| Recipe B (gradient matching) | First-order path only, **one day, cut if it misbehaves** | untested on real data |
| Update-space baselines | sign-flip, scaling, free-rider, min-max (drop ALIE, noise first) | code exists |
| FLTrust interaction, FoolsGold | **Yes**: 4b with trust traces on both rules | code exists |
| Groth16 circuit with Merkle commitment, sampling, invariant check, last-layer binding | **PA-FL Lite**: commitment + sampling + invariant check. **No gradient binding.** See §5 | 3 attention-days, not 3 weeks |
| Fabric and Soroban verification costs | Off-chain verification only; ledger costs as a stated next step | cut |
| HAI as a dataset | Scope boundary paragraph, as in the pilot paper | done |

RQ1 and RQ3 are the empirical core. RQ2 is answered in part by PA-FL Lite. RQ4 becomes a design
statement. **RQ3's real-data answer is a coverage statement** (see LOG.md, 10 Sep): the gate removes the
poison that rides on physics the invariant set covers, and it blocks every fabricated batch, but an
exposure-only replay of physics-consistent attacks passes it and does the same damage. The damage
measure on real data is recall on the targeted attacks, not global F1. 


---

## 4. The claims the paper makes (as the evidence stands on Fri 11 Sep)

1. **Fabricated telemetry is a solved problem for the gate.** Every fabricated batch (channel roll at
   any shift, permutation, scaling, Recipe B) was rejected on BATADAL, SWaT and WADI, with zero honest
   false rejections, by the same automatically mined invariant set (two physical testbeds from
   different processes, treatment and distribution, plus a simulated benchmark). The simulator result (100 % of the damage
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
6. **The gate helps a detector that detects.** On WADI the check rejects 100 % of fabricated and
   89 % of replayed batches and excludes two of three adapted attackers, but the autoencoder's recall
   on WADI attacks is ≈ 0.2, so the poison has nothing to remove and WADI carries no damage numbers.
   State this as the boundary: admission control governs what enters the model; it cannot supply
   detection the model lacks.
7. **Enforcement is buildable.** PA-FL Lite (§5) with a violation budget, on the nine-invariant set.

What this is not: it is not "physics removes 100 % of attack capability on real data". The
abstract's real-data sentence should be the coverage sentence in point 3.



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

**What is explicitly out** 
PA-FL Lite proves that the client
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
| **Thu 10** | Copy `pilot/` → `pafl/` (done) | | Plan written. Message collaborators on scope (§3). Send the 250-word abstract to the editorial office |
| Thu 10, night | Defects 1–8 fixed. Criterion 1 on SWaT. `scripts/overnight_sep10.sh`: SWaT adaptive (7 rules, roll and splice-only, wide set), SWaT baselines sweep, SWaT 4b, BATADAL support runs, Recipe B trial | | |
| **Fri 11** | Read the overnight results with `scripts/summarize_adaptive.py`. Reruns. Decide the invariant-set setting (narrow vs wide) and the roll shift for the paper. `git init`, first commit | Day A (toolchain) | Jeff: abstract to the editorial office; scope message to collaborators |
| **Sat 12** | ~~WADI~~ done Fri 11. ~~Coverage table~~ done Fri 11 (`scripts/coverage_table.py`, `results/{swat,wadi}_coverage.json`). Any missing SWaT cells | Day A (toolchain) | |
| **Sun 13** | Figure script for the paper's results figures from `results/` | Day B (circuit) | Port `pilot-paper.tex` into the MDPI template on Overleaf |
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

1. **Real-data federation results** for criteria 2–4b on SWaT (headline, all damage and removal
   numbers), with WADI as a row in the criterion-1 table and a row in the admission table plus two
   sentences (second physical testbed; no damage numbers because the detector's recall on its attacks
   is ≈ 0.2), BATADAL as the support record with its own small table, and the simulated plant kept as
   the pilot setting. Every number says which setting it came from. The pilot paper does this; the
   dashboard and pitch did not until 10 Sep.
2. **The full defence set** including FoolsGold, and the update-space attacks as the
   complementarity table (physics check catches data fabrications, robust rules catch update
   attacks).
3. **4b with both similarity rules** and the trust traces.
4. **PA-FL Lite** as a subsection of the enforcement section, with the measured table and the
   sentence from §5.
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

