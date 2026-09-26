# results/

Every number in the paper is read from these files; none is typed by hand.

Naming: `<experiment>_<dataset>_<setting>_<seeds>.json`

| prefix | produced by (`scripts/`) | meaning |
|---|---|---|
| `c1_<dataset>_<invariant set>_<roll shift>` | `separation.py` | criterion 1: do the invariants separate honest from fabricated batches; honest false-reject rate; real-attack reference |
| `<dataset>_coverage` | `coverage.py` | per labelled attack segment, the share of its rows each invariant set flags |
| `honest_verdicts` | `honest_verdicts.py` | the check's verdict on every honest client shard of the federated runs |
| `<dataset>_adaptive_<invariant set>_<attacker>_<seeds>` | `adaptive.py` | clean / honest_only / fabricated (naive) / projected (physics-aware) / gated federations per aggregation rule |
| `<dataset>_sweep_*` | `sweep.py` | every defence against every attack (data and update attacks) |
| `<dataset>_trust_traces_*` | `trust_traces.py` | FLTrust and FoolsGold per-round trust weights on the malicious clients |

Invariant set: `narrow` = miner defaults (SWaT: 5 rules), `wide` = r2 0.40 / off-ratio 0.10 / support 0.005 (SWaT: 9 rules), `default` on WADI (the narrow thresholds).
Attacker: `roll<N>` = channel roll shifted by N rows (60 rows = 5 min at the 5 s stride), `splice` = exposure-only replay of real attack rows.

**Rerunning.** `scripts/reproduce.sh` has the exact command for every file here. It writes to
`../results_archive/reproduce/`; `python scripts/compare_results.py results/<name>.json results_archive/reproduce/<name>.json`
checks a rerun number by number.

**Reading a file.** `python scripts/summarize_adaptive.py <file>` prints any adaptive file, including the damage-removal
numbers the paper reports; `python scripts/tables.py <file>` prints it as LaTeX.

**Two things a file does not tell you.**
- An `args` block records only the invocation that created the file. Several files were extended later with more seeds,
  rules, modes or attacks, so read those from the cell keys (`<seed>|<rule>|<mode>`). The `out` field inside `args` may
  also carry a file's name from before it was renamed.
- The `c1_*` files do not record the miner thresholds; the file name and `n_invariants` identify the setting.

Only the result files live here, and all of them are committed. Plots, logs, probes, smoke tests and reruns go to
`../results_archive/`, which is gitignored: `separation.py` writes its histogram there as `<stem of --out>.png`, and the
drivers' default `--out` points there. Pilot-era inputs live in `pilot-paper/data/` (not committed).
