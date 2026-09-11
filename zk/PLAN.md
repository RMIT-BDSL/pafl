# PA-FL Lite — the zero-knowledge extension

*Written 11 September 2026. The implementation plan for the paper's enforcement section. Dated
progress goes in `../LOG.md`, as for the rest of the project; decisions that change scope or
schedule go in `../PLAN-to-DATE.md` §5.*

## Context

Every experiment in the paper computes the physics check directly on a client's raw batch. That
requires the server to see the telemetry federated learning exists to hide, so the empirical result
currently rests on a mechanism that cannot be deployed as tested. PA-FL Lite closes that gap: it
shows a client can prove its training batch satisfies the plant's invariants while the batch stays
private, and it replaces the paper's back-of-envelope constraint budget with measured numbers.

It is the only unfinished item in the submission's scope (`PLAN-to-DATE.md` §3) and the only thing
standing between research question 2 and an unanswered slot. Cut-lines are already fixed: if the
circuit is not proving by **Sat 19 Sep**, report compiled constraint counts only; if it does not
compile by **Wed 23 Sep**, keep the existing design estimate and drop the extension.

Two decisions taken on 11 Sep shape the scope:

- **Sweep the sample count and also test the real attackers.** Measure at k = 8, 16, 32, 64, and run
  the sampled check against the actual fabricated and replay batches, so the cost-versus-confidence
  trade-off is shown rather than asserted.
- **On-chain cost is optional.** Add the analytic Fabric and Soroban estimate only if days C and D
  finish early.

## What is proved

The prover holds a batch of N = 1,024 rows, committed as a Poseidon Merkle root R. For each of k
indices chosen by the verifier, the rows at i and i−1 satisfy every declared invariant within its
tolerance, with at most v violations and at most u rules rendered inapplicable across the sample.

It does **not** prove the submitted update was computed from that batch. Last-layer gradient binding
stays in the design section as the next step; the paper must say so in the same paragraph.

## Design

**Affine form.** Every mined invariant is affine in the channels, so residuals are
`r = J_prev · x_{t−1} + J_cur · x_t + c`. Do not try to read coefficients off the `Invariant`
objects: they are closed over inside the residual function, the `note` string carries only four
significant figures, and `swat_invariants` discards balance coefficients from its report. Instead
reuse **`affine_model(inv_set, df, columns)`** in `pafl/attacks/adaptive.py`, which returns exactly
`(J, c)` with `J` of shape `(n_inv, 2 · n_col)`, previous-row block first, column order equal to the
caller's list. Guard three things it does not guard:

- assert `applicable_rows(inv_set, df).all(axis=1).any()`, because `affine_model` recovers `c` at a
  single probe row and silently returns nonsense if no row satisfies every rule;
- snap finite-difference noise (entries below ~1e-9 relative to the row maximum go to zero);
- assert every channel an invariant touches is present in `columns`. This is currently true for the
  wide SWaT set, verified 11 Sep, but `build_real_scenario` mines on an unfiltered frame while its
  `columns` list excludes analyser channels, so a different miner setting could produce an invariant
  the projection cannot repair, which would corrupt the post-projection admission rate.

**Fixed point.** Scale both channel values and coefficients by S = 2^16; products then live at 2^32
and no division is needed anywhere. Measured ranges justify it: channels reach 1,015, coefficients
span 0.0097 to 8.9, so a residual term is under 2^46 and a nine-term sum under 2^49. Use offset
2^60 and 64-bit range checks. The tightest coefficient quantises to 1,169 units, an error under a
tenth of a percent.

**Applicability, not just range.** A coupling does not apply when its actuator is mid-transition or
changed since the previous row, and the float code treats those rows as passing. Replicate the
predicate in-circuit with equality gates on the quantised status (about three constraints each)
rather than absorbing it into the violation budget. Carry two budgets: `v` violations and `u`
inapplicable checks. The second closes the loophole that `batch_verdict`'s `not_applicable_fraction`
already flags, namely an attacker toggling actuators every row to disable the couplings.

**Two-level leaf.** `leaf_i = Poseidon(h_inv_i, h_rest_i)` where `h_inv_i` hashes only the eighteen
channels the invariants touch, and `h_rest_i` is an opaque private input. The full row stays bound
while the circuit pays to hash eighteen values instead of forty-two. Expect this to be a reportable
saving.

**Sampling.** The verifier derives indices from `Poseidon(R, nonce, m) mod (N−1) + 1` outside the
circuit and passes them as public inputs; the circuit spends ten constraints per index decomposing
it into path selectors. Zero verification cost, and the protocol requirement is that the client
publishes R before learning the nonce.

**Build in three stages**, each compiling and reporting its own constraint count, so the component
breakdown the paper wants falls out of the build and a mid-way stop still yields numbers:

| Stage | Adds | Answers |
|---|---|---|
| 1 | residual and applicability checks only | what the physics costs |
| 2 | leaf hashing | what committing a row costs |
| 3 | Merkle inclusion | the full circuit |

## Files

```
zk/PLAN.md                      this document
zk/package.json                 circomlib, circomlibjs
zk/circuits/invariant_check.circom   parameterised by k, depth, n_inv, n_chan, stage
zk/export_invariants.py         affine_model -> fixed-point JSON (J, c, eps, channel map, S, budgets)
zk/export_batches.py            honest / roll60 / splice / projected batches -> quantised rows
zk/sample_check.py              empirical detection vs k, pure Python, no circuit needed
zk/build_inputs.mjs             Poseidon tree, root, challenges, snarkjs input.json
zk/run_bench.sh                 compile, setup, prove, verify across k; writes results.json
zk/results.json                 every measurement
tests/test_zk_export.py         quantisation fidelity, affine round-trip, channel-subset guard
```

Batches come from `build_variant` in `pafl/fl/variants.py` with
`invariant_kw = dict(r2_min=0.40, coupling_off_ratio=0.10, coupling_support=0.005)`, modes
`fabricated` and `projected`, taking `client.raw` for one honest and one malicious client.

## Schedule

**Day A, half a day.** `npm i circomlib circomlibjs` in `zk/`; download
`powersOfTau28_hez_final_20.ptau` (about 2.4 GB, covers every k including 64); compile a two-input
Poseidon and prove it end to end to confirm the toolchain. circom 2.1.9, snarkjs 0.7.4 and node
23.10 are already installed; 36 GiB RAM and 89 GiB disk are ample.

**Day B, one day.** `export_invariants.py` and `export_batches.py` with the guards above, plus
`tests/test_zk_export.py`. Then stages 1 and 2 of the circuit, tested at k = 4 on the synthetic
plant before touching SWaT.

**Day C, one day.** Stage 3. The k sweep at 8, 16, 32, 64 on the wide SWaT set. `sample_check.py`
for empirical detection against the real attackers. Three proofs: an honest batch verifies, a
fabricated batch cannot be proved at all, a projected batch verifies. All measurements to
`results.json`.

**Day D, half a day.** Write the subsection and its table. If ahead of schedule, add the analytic
on-chain cost.

## Verification

- `pytest tests/test_zk_export.py -q`: integer-arithmetic admission decisions match the float
  decisions of `InvariantSet.batch_verdict` on at least fifty real SWaT batches; affine residuals
  match `inv_set.residuals` to 1e-6 on applicable rows; every invariant channel is in `columns`.
- `bash zk/run_bench.sh` completes for every k and populates `results.json` with constraints by
  stage, compile, setup, witness, prove and verify times, proof size, zkey size and peak memory.
- `snarkjs groth16 verify` returns OK for the honest and projected batches; witness generation
  aborts on the fabricated batch, which is the demonstration that the attacker cannot prove what is
  false.
- `zk/sample_check.py` reproduces the analytic soundness table within sampling error and reports
  detection probability against each real attacker at each k.
- Existing suite still passes: `.venv/bin/python -m pytest tests/ -q`.

## What to expect, and what to write down either way

Channel roll violates about 30% of rows under the wide set, so a handful of samples catch it almost
surely. The replay attacker violates about 1.5%, so even sixty-four samples miss it more often than
not, and a violation budget makes that worse. That asymmetry is the honest finding and it echoes the
coverage result: sampling is cheap against gross fabrication and blunt against light replay.

The residual checks will cost more than the paper's current estimate of 297 constraints per sample,
which charges a single thirty-two-bit range check per invariant and ignores comparator overhead.
Report the measured figure and the revision.

## Risks

| Risk | Response |
|---|---|
| Stage 3 at k = 64 exceeds the powers-of-tau ceiling | estimated near 590k constraints against a 1,048,576 ceiling; if it overruns, report k = 64 from stage 2 and say so |
| Proving-key generation exhausts memory | raise the node heap limit; 36 GiB is comfortable for a circuit this size |
| Finite-difference noise corrupts small coefficients | snap and verify against the float residuals in the test |
| Nothing proves by 19 Sep | fall back to compiled constraint counts, which stages 1 and 2 already deliver |
