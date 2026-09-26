#!/usr/bin/env node
// The aggregator's side of PA-FL Lite for one submitted proof.
//
// The circuit takes the challenge indices as public inputs and proves nothing about how they
// were chosen, so the verifier must (1) recompute them from the published root and the round
// nonce, (2) check the budgets in the public inputs are the policy it announced, and only then
// (3) run the pairing check.  Public signal order (no outputs): root, idx[0..k-1], vMax, uMax.
//
//   node scripts/verify.mjs --build build/wide_k32 --batch honest --nonce 1 --vmax 1 --umax 8
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { buildPoseidon } from "circomlibjs";

const arg = (n, d = null) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const build = arg("build"), batch = arg("batch", "honest");
const nonce = BigInt(arg("nonce", "1")), vMax = BigInt(arg("vmax", "1")), uMax = BigInt(arg("umax", "8"));
if (!build) { console.error("usage: verify.mjs --build dir --batch name [--nonce n --vmax v --umax u]"); process.exit(2); }

const meta = JSON.parse(fs.readFileSync(`${build}/circuit_meta.json`, "utf8"));
const pub = JSON.parse(fs.readFileSync(`${build}/public_${batch}.json`, "utf8")).map(BigInt);
const { k, N } = meta;
if (pub.length !== k + 3) { console.log(`REJECT: ${pub.length} public signals, expected ${k + 3}`); process.exit(1); }
const root = pub[0], idxPub = pub.slice(1, 1 + k), vPub = pub[1 + k], uPub = pub[2 + k];

// (1) the indices this root and nonce commit the prover to
const P = await buildPoseidon();
const H = (xs) => P.F.toObject(P(xs));
const idx = [];
for (let ctr = 0; idx.length < k; ctr++) {
  const i = BigInt(Number(H([root, nonce, BigInt(ctr)]) % BigInt(N - 1)) + 1);
  if (!idx.includes(i)) idx.push(i);
}
const idxOk = idx.every((v, m) => v === idxPub[m]);
// (2) the announced policy
const policyOk = vPub === vMax && uPub === uMax;
// (3) the pairing check
const t0 = Date.now();
const r = spawnSync("snarkjs", ["groth16", "verify", `${build}/vk.json`, `${build}/public_${batch}.json`, `${build}/proof_${batch}.json`], { encoding: "utf8" });
const pairingOk = r.status === 0 && /OK!/.test(r.stdout + r.stderr);
const ms = Date.now() - t0;

console.log(`root ${root.toString().slice(0, 16)}…  k=${k}  nonce=${nonce}`);
console.log(`  indices match Poseidon(root, nonce, ctr): ${idxOk ? "yes" : "NO"}`);
console.log(`  budgets are the announced policy (vMax=${vMax}, uMax=${uMax}): ${policyOk ? "yes" : `NO (proof carries ${vPub}, ${uPub})`}`);
console.log(`  Groth16 pairing check: ${pairingOk ? "OK" : "FAILED"} (${ms} ms incl. process start)`);
const accept = idxOk && policyOk && pairingOk;
console.log(accept ? "ACCEPT: the committed batch satisfies the invariants on the sampled rows within budget" : "REJECT");
process.exit(accept ? 0 : 1);
