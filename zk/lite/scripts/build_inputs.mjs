#!/usr/bin/env node
// Prover input for circuits/invariant_check.circom.
//
// Loads a quantised batch (data/batches_*.json, written by export_batches.py) or makes a
// synthetic one, hashes every row into a leaf exactly as the circuit does, builds the
// Poseidon Merkle tree, derives the k challenge indices from Poseidon(root, nonce, ctr)
// as the verifier would, and writes input.json plus a side file with the integer
// model's own count of violations / inapplicable checks over the chosen samples.
//
//   node scripts/build_inputs.mjs --meta build/wide_k32/circuit_meta.json \
//        --batches data/batches_swat_wide_seed0.json --batch honest \
//        --nonce 1 --vmax 1 --umax 8 --out build/wide_k32/input_honest.json
//   node scripts/build_inputs.mjs --meta ... --synthetic random --vmax 6 --umax 12 --out ...
import fs from "node:fs";
import { buildPoseidon } from "circomlibjs";

function arg(name, def = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const metaPath = arg("meta");
const batchesPath = arg("batches");
const batchName = arg("batch", "honest");
const synthetic = arg("synthetic");
const nonce = BigInt(arg("nonce", "1"));
const vMax = BigInt(arg("vmax", "1"));
const uMax = BigInt(arg("umax", "8"));
const outPath = arg("out");
const seed = Number(arg("seed", "1"));
if (!metaPath || !outPath || (!batchesPath && !synthetic)) {
  console.error("usage: build_inputs.mjs --meta circuit_meta.json (--batches file --batch name | --synthetic random) --out input.json [--nonce n --vmax v --umax u]");
  process.exit(2);
}

const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
const { k, depth, N, columns, inv_channels, rest_channels } = meta;
const colIdx = Object.fromEntries(columns.map((c, i) => [c, i]));
const invIdx = inv_channels.map((c) => colIdx[c]);
const restIdx = rest_channels.map((c) => colIdx[c]);

// ---------------------------------------------------------------- the batch
let rows; // N x columns, BigInt
let batchInfo = {};
if (synthetic) {
  // deterministic LCG; values in [0, 2^20): couplings never apply (status is neither
  // off nor on), balances are violated, so per sample v = #balances, u = #couplings
  let s = BigInt(seed) * 6364136223846793005n + 1442695040888963407n;
  const next = () => { s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return s >> 44n; };
  rows = Array.from({ length: N }, () => columns.map(() => next()));
  batchInfo = { source: "synthetic", seed };
} else {
  const data = JSON.parse(fs.readFileSync(batchesPath, "utf8"));
  const b = data.batches[batchName];
  if (!b) { console.error(`no batch ${batchName}; have ${Object.keys(data.batches)}`); process.exit(2); }
  if (data.columns.join() !== columns.join()) { console.error("column order differs between batches file and circuit meta"); process.exit(2); }
  if (b.rows.length !== N) { console.error(`batch has ${b.rows.length} rows, circuit expects ${N}`); process.exit(2); }
  rows = b.rows.map((r) => r.map((v) => BigInt(v)));
  batchInfo = { source: batchesPath, batch: batchName, client: b.client, start: b.start,
                float_verdict: b.float_verdict, integer_verdict: b.integer_verdict };
}
// signed readings are biased into [0, 2^xBits) before hashing and before entering the circuit
const B = BigInt(meta.x_bias);
for (const r of rows) for (const v of r) if (v < -B || v >= B) { console.error(`value ${v} outside [-2^${meta.x_bits - 1}, 2^${meta.x_bits - 1})`); process.exit(2); }
const enc = rows.map((r) => r.map((v) => v + B));

// ---------------------------------------------------------------- hashing (mirror of the circuit)
const P = await buildPoseidon();
const F = P.F;
const H = (xs) => F.toObject(P(xs));
function chunkedHashPlus(xs, extra) {
  const n = xs.length, nc = Math.ceil(n / 16), cs = Math.ceil(n / nc);
  const digests = [];
  for (let c = 0; c < nc; c++) {
    const chunk = [];
    for (let i = 0; i < cs; i++) { const j = c * cs + i; chunk.push(j < n ? xs[j] : 0n); }
    digests.push(H(chunk));
  }
  return H([...digests, extra]);
}
const t0 = Date.now();
const hRest = enc.map((r) => chunkedHashPlus(restIdx.map((i) => r[i]), 0n));
const leaves = enc.map((r, t) => chunkedHashPlus(invIdx.map((i) => r[i]), hRest[t]));
const levels = [leaves];
for (let l = 0; l < depth; l++) {
  const prev = levels[l], nxt = [];
  for (let i = 0; i < prev.length; i += 2) nxt.push(H([prev[i], prev[i + 1]]));
  levels.push(nxt);
}
const root = levels[depth][0];
const siblings = (i) => Array.from({ length: depth }, (_, l) => levels[l][(i >> l) ^ 1]);
const tHash = (Date.now() - t0) / 1000;

// ---------------------------------------------------------------- challenge indices
const idx = [];
for (let ctr = 0; idx.length < k; ctr++) {
  const i = Number(H([root, nonce, BigInt(ctr)]) % BigInt(N - 1)) + 1;
  if (!idx.includes(i)) idx.push(i);
}

// ---------------------------------------------------------------- integer model on the samples
function evalPair(xPrev, xCur) {
  let v = 0, u = 0; const per = [];
  for (const rule of meta.rules) {
    let r = BigInt(rule.c_hat);
    for (let d = 0; d < inv_channels.length; d++) r += BigInt(rule.coef_prev[d]) * xPrev[d] + BigInt(rule.coef_cur[d]) * xCur[d];
    const ok = (r < 0n ? -r : r) <= BigInt(rule.eps_hat);
    let app = true;
    if (rule.is_coupling) {
      const sp = xPrev[rule.status_idx], sc = xCur[rule.status_idx], off = BigInt(rule.off_hat), on = BigInt(rule.on_hat);
      app = (sp === off && sc === off) || (sp === on && sc === on);
    }
    if (!app) u++; else if (!ok) v++;
    per.push(!app ? "n/a" : ok ? "ok" : "VIOL");
  }
  return { v, u, per };
}
const samples = idx.map((i) => {
  const xPrev = invIdx.map((c) => rows[i - 1][c]), xCur = invIdx.map((c) => rows[i][c]);
  return { i, xPrev, xCur, ...evalPair(xPrev, xCur) };
});
const vTot = samples.reduce((a, s) => a + s.v, 0), uTot = samples.reduce((a, s) => a + s.u, 0);

// cross-check against the Python integer model's per-row counts shipped with the batch
let crossCheck = null;
if (!synthetic) {
  const b = JSON.parse(fs.readFileSync(batchesPath, "utf8")).batches[batchName];
  if (b.row_violations) {
    const bad = samples.filter((s) => s.v !== b.row_violations[s.i - 1] || s.u !== b.row_inapplicable[s.i - 1]);
    crossCheck = { compared: samples.length, mismatches: bad.map((s) => ({ i: s.i, js: [s.v, s.u], py: [b.row_violations[s.i - 1], b.row_inapplicable[s.i - 1]] })) };
    if (bad.length) console.error(`WARNING: JS and Python integer models disagree on ${bad.length} samples`, crossCheck.mismatches);
  }
}

// ---------------------------------------------------------------- write
const S = (x) => x.toString();
const input = {
  root: S(root), idx: idx.map(S), vMax: S(vMax), uMax: S(uMax),
  xPrev: samples.map((s) => s.xPrev.map((v) => S(v + B))), xCur: samples.map((s) => s.xCur.map((v) => S(v + B))),
  hRestPrev: samples.map((s) => S(hRest[s.i - 1])), hRestCur: samples.map((s) => S(hRest[s.i])),
  pathPrev: samples.map((s) => siblings(s.i - 1).map(S)), pathCur: samples.map((s) => siblings(s.i).map(S)),
};
fs.writeFileSync(outPath, JSON.stringify(input));
const expect = {
  ...batchInfo, k, N, nonce: S(nonce), root: S(root), idx, vMax: Number(vMax), uMax: Number(uMax),
  violations: vTot, inapplicable: uTot, within_budget: vTot <= Number(vMax) && uTot <= Number(uMax),
  per_sample: samples.map((s) => ({ i: s.i, v: s.v, u: s.u, rules: s.per })),
  python_cross_check: crossCheck,
  hash_seconds: tHash,
};
fs.writeFileSync(outPath.replace(/\.json$/, "") + ".expect.json", JSON.stringify(expect, null, 1));
console.log(`${batchInfo.batch ?? "synthetic"}: root ${S(root).slice(0, 12)}…  k=${k}  violations ${vTot} (budget ${vMax})  inapplicable ${uTot} (budget ${uMax})  ` +
            `${expect.within_budget ? "within budget: witness should exist" : "OVER BUDGET: witness generation must fail"}  [tree ${tHash.toFixed(1)} s]`);
