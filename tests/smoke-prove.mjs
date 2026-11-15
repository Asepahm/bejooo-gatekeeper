// Smoke test: fullProve the event page's VALID sample, verify locally,
// check public-signal order + Poseidon(salt, taskId) commitment hypothesis,
// and try a few candidate derivations of the registered vkHash.
import { readFileSync } from 'node:fs';
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import { createHash } from 'node:crypto';

const OFFICIAL_VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const dir = new URL('../circuits/', import.meta.url);
const wasm = new URL('gatekeeper.wasm', dir).pathname;
const zkey = new URL('gatekeeper_final.zkey', dir).pathname;
const vk = JSON.parse(readFileSync(new URL('verification_key.json', dir), 'utf8'));

const SALT = '987654321';
const input = {
  taskId: 24,
  minimum: 1000,
  publicBalance: 1460,
  expiryBlock: 19842201,
  currentBlock: 19832000,
  recipient: BigInt('0xDe429f01').toString(), // sample address truncated on the page; any consistent value works here
  conditionRecipient: BigInt('0xDe429f01').toString(),
  amount: 500,
  maxTransfer: 1000,
  registeredVkHash: BigInt(OFFICIAL_VK_HASH).toString(),
  proofVkHash: BigInt(OFFICIAL_VK_HASH).toString(),
  salt: SALT,
  decision: 1,
};

const t0 = Date.now();
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
const tProve = Date.now() - t0;
console.log('fullProve ms:', tProve);
console.log('publicSignals:', JSON.stringify(publicSignals));

const t1 = Date.now();
const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
console.log('verify:', ok, 'in', Date.now() - t1, 'ms');

const poseidon = await buildPoseidon();
const F = poseidon.F;
const commit = F.toString(poseidon([BigInt(SALT), BigInt(24)]));
console.log('Poseidon(salt, taskId) == publicSignals[0]:', commit === publicSignals[0]);

// --- vkHash derivation attempts (timeboxed candidates) ---
const target = BigInt(OFFICIAL_VK_HASH);
function flatG1(p) { return [BigInt(p[0]), BigInt(p[1])]; }
function flatG2(p) { return [BigInt(p[0][0]), BigInt(p[0][1]), BigInt(p[1][0]), BigInt(p[1][1])]; }
const seq = [
  ...flatG1(vk.vk_alpha_1), ...flatG2(vk.vk_beta_2), ...flatG2(vk.vk_gamma_2), ...flatG2(vk.vk_delta_2),
  ...vk.IC.flatMap(flatG1),
];
function poseidonSponge(elems) {
  // chain in chunks of 16: state = Poseidon(prev, ...chunk)
  let state = 0n;
  for (let i = 0; i < elems.length; i += 15) {
    const chunk = [state, ...elems.slice(i, i + 15)];
    state = F.toObject(poseidon(chunk));
  }
  return state;
}
const tries = {
  'poseidon-sponge(alpha,beta,gamma,delta,IC)': poseidonSponge(seq),
  'poseidon-sponge(no IC)': poseidonSponge(seq.slice(0, 14)),
};
for (const [name, v] of Object.entries(tries)) console.log(name, '== vkHash:', v === target);
const rawJson = readFileSync(new URL('verification_key.json', dir));
console.log('sha256(vk json file) == vkHash:', '0x' + createHash('sha256').update(rawJson).digest('hex') === OFFICIAL_VK_HASH);
console.log('keccak? (sha3-256 of vk json) == vkHash:', '0x' + createHash('sha3-256').update(rawJson).digest('hex') === OFFICIAL_VK_HASH);
process.exit(0);
