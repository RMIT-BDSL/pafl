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
| Fri 11 Sep | **Emphasis decided from a 0–5 grading of every result (LOG.md, 13:00).** The abstract is carried by criterion 1 across three plants and by the coverage result. The **simulated plant moves to an appendix**; **WADI and BATADAL are mentions** (a row and two sentences each); the **FLTrust interaction is demoted** from a contribution to a reported observation showing both settings | the two graded 5 are the claims a reviewer can least argue with; the simulator is discounted beside real data; the pilot's FLTrust reversal does not reproduce on SWaT |
| Mon 14 Sep | **Two-paper split.** *Information* (28 Sep) = the requirement: criterion 1, coverage, damage and removal, complementarity, plus **PA-FL Lite as a feasibility result** (one measured circuit at k = 32, the three-proof demonstration, the analytic sampling curve). **AsiaCCS** (cycle 2, deadline 11 Dec 2026, CPS track) = the protocol: update binding, security argument with the v/u budgets, cost sweep over k, the optimising and rule-aware adversary, the FLTrust interaction analysis, a heterogeneous federation, ledger cost as a subsection. Table in `../paper-draft/draft-sept-14.tex` §0.4 | each paper whole on its own; AsiaCCS cites Information in the third person and reuses no prose; nothing in Information needs weakening later |


---

## 2. Current state (Tue 15 Sep)

| Item | State | Evidence |
|---|---|---|
| Criterion 1, BATADAL (real benchmark) | Done, passed; unchanged by the miner fix | `results/c1_batadal_*.json` |
| Criterion 1, SWaT (physical testbed) | **Done, passed** with the narrow (5) and wide (9) invariant sets; honest false-reject 0 | `results/c1_swat_*.json` |
| Criterion 1, HAI | Done, fails; scope boundary | `results/c1_hai_mined.json` |
| Criterion 1, WADI | **Done Fri 11, passes** (7 couplings, 0 balances, default miner) | `results/c1_wadi_default_shift60.json` |
| Criteria 2–4b, simulated plant (pilot) | Done; it was re-run after the oversampling fix, result holds | `results/sim_adaptive_3seed.json`, `results/sim_defences_mal30_2seed.json` |
| Criteria 2–4b, **SWaT**: 7 rules × 8 attacks × 3 seeds baselines; adaptive attacker (channel roll, replay), 7 rules, 5 modes incl. gated, 5 seeds, two invariant sets; 4b traces | **Done** for both invariant sets (narrow 7 × 5 × 5 finished Sat 12 15:49) | `results/swat_sweep_wide_3seed.json`, `results/swat_adaptive_wide_*_5seed.json`, `results/swat_adaptive_narrow_*_5seed.json`, `results/swat_trust_traces_wide_3seed.json` |
| Honest clients through the check (federated false-reject claim) | **Done Sat 12**: 0 of 100 honest shards rejected across SWaT (both sets), WADI, BATADAL; every run now records honest verdicts and the gate excludes any rejected client | `results/honest_verdicts.json`, `pafl/fl/gate.py` |
| Criteria 2–4b, **BATADAL** (5 clients, 3 rules, 3 seeds) | Done; weak signal, support only | `results/batadal_adaptive_*_3seed.json` |
| Criteria 2–4b, **WADI** | **Done Fri 11** (3 rules, 5 modes, 3 seeds). No measurable poison damage (detector recall on WADI attacks ≈ 0.2); gate rejects 100 % of rolled and 89 % of replay batches before adaptation, excludes 2 of 3 clients after. Role: rejection behaviour, not removal ratios | `results/wadi_adaptive_default_*_3seed.json` |
| Recipe B | Done on SWaT, 7 rules × 3 seeds | in `swat_sweep_wide_3seed.json` |
| ZK extension (PA-FL Lite) | **Step 1 done Sat 12** (fixed-point export of both invariant sets, integer reference model, tests). Steps 2–4 at k = 32 = the September feasibility result; **owned by the collaborator from Mon 14**; not started. Cut-lines Sat 19 / Wed 23 | `zk/data/invariants_swat_*.json`, `pafl/zk/fixed_point.py`, `zk/PLAN.md` |
| Paper | Figures done (14, incl. the wide hero figure); whole-paper plan done (`draft-sept-14.tex`); tables built; bibliography `../lit-papers/pafl-refs.bib` (53 entries); Results prose scaffold started (`results.tex`, Jeff); **no section written yet; Overleaf port not started** | `../paper-draft/{figures,tables,draft-sept-14.tex,results.tex}` |

---

## 3. Scope of the submission

The paper is the pilot extended to real federated data, plus a pared-back zero-knowledge extension
that shows the enforcement path is real. It is not the full pitch. Everything below is **done except
the ZK extension** (status as of Fri 11 Sep, 13:00).

| Pitch promised | Submission delivers | Status | Why |
|---|---|---|---|
| Federation on ICS-NAD, BATADAL, SWaT | **SWaT**, 10 clients — the primary record, carrying every damage and removal number. **WADI**, 10 clients — second physical testbed, a mention: one row in the criterion-1 table, one in the admission table, two sentences. **BATADAL**, 5 clients — a mention on the same footing. **Simulated plant** — appendix only | done | ICS-NAD has no loader and is 246 GB; BATADAL is too short for 10 clients; on WADI the detector's recall on attacks is ≈ 0.2, so poisoning has nothing to remove; a simulator is discounted beside real data |
| Full defence set, three conditions | Exceeded: 7 rules × **five modes** (honest, honest-only, naive, physics-aware, **gated** — the deployed system, where a batch that still fails the check is excluded) × **5 seeds** on the two headline SWaT files (3 seeds elsewhere), for **two attackers** — fabricated (channel roll) and **exposure-only replay** (`splice_only`) — under a narrow and a wide invariant set | done | 20 s per cell; the honest-only and gated modes were added on 10 Sep and are what make the removal numbers fair and deployable |
| Recipe B (gradient matching) | Kept. First-order path, 7 rules × 3 seeds on SWaT: rejected by the check in every cell, comparable damage to the simple attackers, and the one attack FoolsGold admits in full | done | ran in 22 s per cell; the full gradient-matching path is not needed |
| Update-space baselines | sign-flip, scaling, free-rider, min-max (ALIE and additive noise dropped as planned) | done | they form the complementarity table with the data attacks |
| FLTrust interaction, FoolsGold | Run on both rules with trust traces, but **demoted**: a one-paragraph observation showing both settings, not a contribution and not in the abstract. The simulator reversal does not reproduce on SWaT | done, demoted 11 Sep | see §4, claim 5 |
| Groth16 circuit with Merkle commitment, sampling, invariant check, last-layer binding | **PA-FL Lite as a feasibility result**: commitment + sampling + invariant check at one k. **No gradient binding** (AsiaCCS). See §5 and `zk/PLAN.md` | step 1 done 12 Sep; circuit not built (collaborator) | 3 attention-days, not 3 weeks |
| Fabric and Soroban verification costs | Off-chain verification only; ledger costs as a stated next step | cut | attention, not compute |
| HAI as a dataset | Scope boundary paragraph, as in the pilot paper | done | the invariant families are absent from its training record |
| *(not promised)* Coverage per attack segment | New: how many attacks each invariant set can see, at what honest-violation cost. The paper's organising idea | done 11 Sep | it explains why removal varies by seed and makes coverage a defender's dial |

RQ1 and RQ3 are the empirical core. RQ2 is answered in part by PA-FL Lite, and is the one open risk.
RQ4 becomes a design statement. **RQ3's real-data answer is a coverage statement** (evidence:
`results/swat_coverage.json`, LOG.md 11 Sep): the gate blocks every fabricated batch and removes the
poison that rides on physics the invariant set covers, but an exposure-only replay of
physics-consistent attacks passes it and does the same damage. The damage measure on real data is
recall on the targeted attacks, not global F1.

---

## 4. The claims the paper makes (as the evidence stands on Fri 11 Sep)

*Graded 0–5 for prominence in LOG.md (Fri 11, 13:00). The two claims graded 5 carry the abstract.*

1. **[5 — abstract] Fabricated telemetry is a solved problem for the gate.** Every fabricated batch
   (channel roll at any shift, permutation, scaling, Recipe B) was rejected on BATADAL, SWaT and
   WADI, with zero honest false rejections, by the same automatically mined invariant set: two
   physical testbeds from different processes, treatment and distribution, plus a simulated
   benchmark, with no per-plant tuning.
2. **[4] The real threat on a real plant is replay, not fabrication.** An attacker who splices real
   attack telemetry into an honest shard and presents it as normal does the same targeted damage as
   the fabricated attacker and needs no physics violation of its own. Whether the gate sees it
   depends on whether the *attacks* violate the plant's invariants.
3. **[5 — abstract] Coverage is the governing quantity, and it is a knob the defender controls.** Five mined
   invariants see 12 of 35 SWaT attacks (10 % of attack rows); nine see 20 (82 %), at 0.35 % honest
   violations. Under the wide set the replay attacker is rejected in every seed; after adapting it
   recovers admission for 56 % of its batches, because with actuator states held fixed some attack
   rows cannot be made consistent. With the gate enforced (rejected clients excluded), 70–100 % of
   the targeted damage is removed on SWaT for FedAvg, median, norm clip and trimmed mean (5 seeds,
   honest-only reference); projection alone removes 3–55 %. The poison that survives is the part that
   rides on physics-consistent attacks: 0 % removed in a seed whose targets are consistent.
4. **[4] Metric.** A targeted poison on 36 diverse attacks does not move global F1 (never more than
   1 pt tonight). Recall on the targeted attacks moves 5–17 pts. Report targeted and untargeted
   recall, AUC-PR and best-F1; explain why.
5. **[4] The gate is necessary, not sufficient, and it composes.** Krum stops the replay attacker
   outright on SWaT; FedAvg, median and norm clipping admit everything and the gate is what removes
   the poison for them.
   *Demoted to a reported observation (was a pitch contribution):* on the simulated plant, projecting
   onto the physics raised FLTrust's acceptance of the malicious clients from 0.34 to 0.96 and grew
   the damage; on SWaT the same projection leaves the malicious trust weight at 0.004–0.005 and
   *lowers* acceptance. Report both settings in one paragraph, attribute the difference to update
   geometry, generalise neither, and do not list it as a contribution.
6. **[3] The gate helps a detector that detects.** On WADI the check rejects 100 % of fabricated and
   89 % of replayed batches and excludes two of three adapted attackers, but the autoencoder's recall
   on WADI attacks is ≈ 0.2, so the poison has nothing to remove and WADI carries no damage numbers.
   State this as the boundary: admission control governs what enters the model; it cannot supply
   detection the model lacks.
7. **[not yet measured] Enforcement is buildable.** PA-FL Lite (§5) with a violation budget, on the nine-invariant set.

What this is not: it is not "physics removes 100 % of attack capability on real data". The
abstract's real-data sentence is the coverage sentence in point 3 (decided Fri 11).

**Appendix, not body:** the simulated plant's criteria 2–4b (graded 3). It is the upper-bound case,
where the plant's physics is known exactly and every attack violates it, so the invariant requirement
removes all measurable damage against FedAvg and trimmed mean. Keep it as the mechanism
demonstration and as the setting where the FLTrust observation originates; keep it out of the
headline tables, because a simulator is discounted beside real data.



---

## 5. The ZK extension: PA-FL Lite

**Purpose.** Show, with measured numbers on the real invariant set, that a client can prove its
training batch satisfies the plant's invariants without revealing the batch. Nothing more.

**Scope for the Information paper (decided Mon 14 Sep):** a feasibility result at one setting, k = 32 on the
nine-rule set, all three stages, plus the three-proof demonstration. The k sweep (8/16/32/64), update binding, the
formal soundness argument and the empirical detection-vs-k check are held back for the AsiaCCS paper (deadline
11 Dec 2026). The cut-lines below still apply to the feasibility result.

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

## 6. Schedule, re-baselined Tue 15 Sep (the 10 Sep schedule ran ahead on experiments and behind on writing)

What has happened against the original schedule: all experiments finished Thu 10–Fri 11 (five days early), the
figures on Sat 12, the tables, bibliography and whole-paper plan Sat 12–Mon 14. Nothing that the original schedule put
under "Writing" has been written, and the Overleaf port has not started. ZK days A–D did not run on Sat–Mon; the
circuit is now the collaborator's, scoped to the k = 32 feasibility result (§5).

| Date | ZK (collaborator) | Writing (Jeff + Claude) | Admin |
|---|---|---|---|
| **Tue 15** | steps 2–3: batch export, circuit stages 1–2 on the synthetic set | Overleaf: MDPI template, `pafl-refs.bib`, figure bundle uploaded; §4 Setup and §3 Method drafted from E1–E6, M1–M6 | |
| Wed 16 | stage 3; setup at k = 32 on the wide set | §5 Results R0–R9 (criterion 1, coverage, metric, replay) | |
| Thu 17 | three-proof demo; `zk/results.json` | §5 R10–R18 (removal, narrow set, complementarity) | |
| Fri 18 | measurements to R20 / Table R5 | §5 R19–R20; §6 Discussion D1–D5 | |
| **Sat 19** | **cut-line 1**: if not proving, R20 reports constraint counts only | §6 D6–D9; §7 Conclusions | |
| Sun 20 | | §1 Introduction, §2 Background | |
| Mon 21 | | abstract re-check against the tables; captions; back matter | |
| **Tue 22** | | **full draft to collaborators** | |
| **Wed 23** | **cut-line 2**: if not compiling, R20 keeps the design estimate and §5.6 becomes a specification | revisions from comments | |
| Thu 24 – Fri 25 | | co-author review; length check against §0.1 of the plan (apply cuts in order) | Zenodo DOI on the release commit; Data Availability wording (iTrust terms) |
| Sat 26 – Sun 27 | | full read; figure rebuild at 13.86 cm only if time (item 10) | |
| **Mon 28** | | | **Submit** |

After 28 Sep: the AsiaCCS paper (cycle 2, 11 Dec 2026), per `draft-sept-14.tex` §0.4.

---

## 7. Paper assembly (on Overleaf)

Start from `pilot-paper/pilot-paper.tex`. It already has the setting figure, the threat model, the
criteria table, five results figures generated from JSON, the enforcement design with the
constraint budget, and the limitations. Add:

1. **Results, in the order the grading implies.** (a) Criterion 1 across BATADAL, SWaT and WADI,
   one automatic miner, zero honest rejections — the opening result. (b) The **coverage table**
   (narrow vs wide invariant set: rules kept, honest violation rate, attacks and attack rows
   covered) — the paper's organising idea. (c) SWaT damage and removal: the five modes, seven rules,
   five seeds, against the honest-only reference. (d) The complementarity table from the sweep.
   **WADI and BATADAL are mentions**: one row each in the criterion-1 table and the admission table,
   plus two sentences saying what they add (WADI: second physical testbed, no damage numbers because
   detector recall on its attacks is ≈ 0.2; BATADAL: benchmark with a published hydraulic model,
   five clients, direction confirmed). **The simulated plant goes to an appendix.** Every number
   says which setting it came from.
2. **The full defence set** including FoolsGold, and the update-space attacks as the
   complementarity table (physics check catches data fabrications, robust rules catch update
   attacks).
3. **The similarity-rule observation**, one paragraph with both settings and the trust traces.
   Not a contribution, not in the abstract, not in the contribution list.
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
8. **Figures: done (Sat 12 Sep).** Twelve standalone LaTeX figures in `../paper-draft/figures/`
   (plan in its `FIGURES.md`; `make export` bundles sources, style, data and PDFs for Overleaf).
   Every number enters through `export_figure_data.py` from `results/*.json`. Panel (b) of the
   protocol figure gains the measured proving costs when PA-FL Lite lands.

9. **Results and Discussion planned (Sat 12 Sep)** in `../paper-draft/results-disc.tex`: paragraph map
   with figures and data sources, continuity check, tagged bullets, Discussion in the nine-move
   structure. Open items before prose: honest clients through `physics_verdicts`; splice-only under the
   narrow set at 60 rows with `honest_only`; fix the `umer2024invariant` author list; state the attack
   counts (35 SWaT, 14 WADI) once.

10. **To do (not now): rebuild the result figures at the article text width.** `mdpi.cls` gives a 13.86 cm
    column (A4, left 5.87 cm / right 1.27 cm); the figures were built at 12.9 cm (the class's Book branch) and
    sit centred 0.96 cm short of the column. Widen the axis widths in `../paper-draft/figures/fig-*.tex`
    (`\figfull` → 13.86 cm), rebuild, re-check collisions, `make export`. Decided 14 Sep to defer.

11. **Whole-paper plan written (Mon 14 Sep)**: `../paper-draft/draft-sept-14.tex` (+PDF), superseding
    `results-disc.tex`. Budget ≈7,000 body words (I1–I6, B1–B5, M1–M6, E1–E6, R0–R22, D1–D9, C1–C2, A1–A3), 11 body
    figures + 3 appendix, 5 tables; cut order if over length. Bibliography is `../lit-papers/pafl-refs.bib`. Results
    prose scaffold: `../paper-draft/results.tex`. Writing order: §4, §3, §5, §6, §1, §2, abstract check, §7.
