# results/

Every number in the paper is read from these files; none is typed by hand.

Naming: `<experiment>_<dataset>_<setting>_<seeds>.json`

| prefix | produced by | meaning |
|---|---|---|
| `c1_<dataset>_<invariant set>_<roll shift>` | `scripts/day1_residuals.py` | criterion 1: do the invariants separate honest from fabricated batches; honest false-reject rate; real-attack reference |
| `sim_defences_*`, `sim_adaptive_*`, `sim_go_nogo` | `day2_defences.py`, `day45_adaptive.py`, pilot decision script | the simulated plant (pilot setting) |
| `<dataset>_adaptive_<invariant set>_<attacker>_<seeds>` | `scripts/day45_adaptive.py` | clean / honest_only / fabricated / projected / gated federations per aggregation rule |
| `<dataset>_sweep_*` | `scripts/week2_baselines.py` | every defence against every attack (data and update attacks) |
| `<dataset>_trust_traces_*` | `scripts/week2_4b.py` | FLTrust and FoolsGold per-round trust weights on the malicious clients |

Invariant set: `narrow` = miner defaults (SWaT: 5 rules), `wide` = r2 0.40 / off-ratio 0.10 / support 0.005 (SWaT: 9 rules), `default` on WADI.
Attacker: `roll<N>` = channel roll shifted by N rows (60 rows = 5 min at the 5 s stride), `splice` = exposure-only replay of real attack rows.

Read any adaptive file with `python scripts/summarize_adaptive.py <file>`; LaTeX with `python scripts/tables.py <file>`.
`_probes/` and `logs/` are local scratch and are not committed. Pilot-era files live in `pilot-paper/data/` (not committed).
