// zkVerify Agent Games — Proof Gatekeeper: shared core logic.
// Used by BOTH entry points, so behaviour is identical everywhere:
//   - src/gatekeeper.mjs  local long-running server (`npm start`)
//   - api/agent.mjs       Vercel serverless function
// Pipeline: raw-body HMAC verify (x-agent-games-signature, HMAC-SHA256 hex)
// BEFORE parsing -> preflight handler -> task handler: run every documented
// check -> decision -> Groth16 proof of THAT decision with the official
// gatekeeper circuit -> signed JSON response. Fail closed everywhere.
//
// Circuit artifacts: the .wasm/.zkey binaries are NOT in the GitHub repo.
// Resolution order in ensureArtifacts():
//   1. $GATEKEEPER_CIRCUIT_DIR (if set): use files there, download if absent
//   2. ../circuits/ next to this package (local dev checkouts)
//   3. download from the official URLs into os.tmpdir()/gatekeeper-circuits
// Downloads are size- and SHA-256-checked against the known official values.
import { createHmac, timingSafeEqual, randomBytes, createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, stat, writeFile, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as snarkjs from 'snarkjs';

export const OFFICIAL_CIRCUIT_BASE = 'https://agentgames.zkverify.io/circuits/';
const ARTIFACTS = [
  { name: 'gatekeeper.wasm', bytes: 1755820, sha256: 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f' },
  { name: 'gatekeeper_final.zkey', bytes: 309750, sha256: 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d' },
];

export const HEALTH = { ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1' };

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const seenProofTx = new Set();

export function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function secret() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!s) throw new Error('AGENT_GAMES_HMAC_SECRET is not set');
  return s;
}
export function hmacHex(data) {
  return createHmac('sha256', secret()).update(data).digest('hex');
}
export function signatureOk(headerValue, rawBody) {
  if (!headerValue) return false;
  const given = String(headerValue).trim().toLowerCase().replace(/^sha256=/, '');
  const expected = hmacHex(rawBody);
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

// ---------- circuit artifacts ----------
let artifactsPromise = null;
export function ensureArtifacts() {
  if (!artifactsPromise) {
    artifactsPromise = resolveArtifacts().catch((e) => {
      artifactsPromise = null; // allow a later retry after a transient failure
      throw e;
    });
  }
  return artifactsPromise;
}

async function fileHasSize(path, bytes) {
  try {
    return (await stat(path)).size === bytes;
  } catch {
    return false;
  }
}

async function downloadArtifact(artifact, destPath) {
  const url = OFFICIAL_CIRCUIT_BASE + artifact.name;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`artifact download failed: ${url} -> HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length !== artifact.bytes) {
    throw new Error(`artifact size mismatch for ${artifact.name}: got ${buf.length}, want ${artifact.bytes}`);
  }
  const digest = createHash('sha256').update(buf).digest('hex');
  if (digest !== artifact.sha256) {
    throw new Error(`artifact sha256 mismatch for ${artifact.name}: got ${digest}`);
  }
  await mkdir(join(destPath, '..'), { recursive: true });
  const tmp = `${destPath}.tmp-${process.pid}`;
  await writeFile(tmp, buf);
  await rename(tmp, destPath);
  log(`circuit artifact ready: ${artifact.name} (${buf.length} B, sha256 ok)`);
}

async function resolveArtifacts() {
  const t0 = Date.now();
  const localDir = new URL('../circuits/', import.meta.url).pathname;
  const overrideDir = process.env.GATEKEEPER_CIRCUIT_DIR || null;
  const cacheDir = overrideDir || join(tmpdir(), 'gatekeeper-circuits');
  const paths = {};
  for (const artifact of ARTIFACTS) {
    const localPath = join(localDir, artifact.name);
    if (!overrideDir && existsSync(localPath)) {
      paths[artifact.name] = localPath;
      continue;
    }
    const cachedPath = join(cacheDir, artifact.name);
    if (await fileHasSize(cachedPath, artifact.bytes)) {
      paths[artifact.name] = cachedPath;
      continue;
    }
    log(`circuit artifact missing, downloading ${artifact.name} from official URL`);
    await downloadArtifact(artifact, cachedPath);
    paths[artifact.name] = cachedPath;
  }
  log(`circuit artifacts resolved in ${Date.now() - t0} ms`);
  return { wasm: paths['gatekeeper.wasm'], zkey: paths['gatekeeper_final.zkey'] };
}

// ---------- field conversions ----------
function toBig(v, field) {
  if (v === undefined || v === null) throw new Error(`missing field: ${field}`);
  if (typeof v === 'number') return BigInt(v);
  const s = String(v).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^-?\d+$/.test(s)) return BigInt(s);
  throw new Error(`field ${field} is not numeric: ${s}`);
}
function normHex(v) {
  return String(v ?? '').trim().toLowerCase();
}
function addressBig(v) {
  const s = String(v ?? '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(s)) throw new Error(`bad address: ${s}`);
  return BigInt(s);
}
// The platform's task_id is a string like "gk_24_9d1"; the circuit needs a
// field element. Deterministic mapping: pure number -> itself; else the
// first embedded integer group; else sha256 of the string mod p.
// (Mapping is NOT published by the platform — see STATUS.md uncertainties.)
function taskIdField(taskId) {
  const s = String(taskId ?? '');
  if (/^\d+$/.test(s)) return BigInt(s);
  const m = s.match(/(\d+)/);
  if (m) return BigInt(m[1]);
  let h = 0n;
  for (const c of Buffer.from(s, 'utf8')) h = (h * 257n + BigInt(c)) % FIELD_P;
  return h;
}

// ---------- decision ----------
export function decide(input) {
  const proofTx = input.proof_tx ? String(input.proof_tx) : null;
  if (proofTx && seenProofTx.has(proofTx)) {
    return { decision: 'REJECT', reason: 'PROOF_REUSED', proofTx, provable: false };
  }
  let reason = null;
  if (normHex(input.registered_vk) !== normHex(input.proof_vk)) reason = 'VK_SUBSTITUTION';
  else if (toBig(input.current_block, 'current_block') > toBig(input.expiry_block, 'expiry_block')) reason = 'EXPIRED_CONDITION';
  else if (normHex(input.recipient) !== normHex(input.condition_recipient)) reason = 'RECIPIENT_MISMATCH';
  else if (toBig(input.amount, 'amount') > toBig(input.max_transfer, 'max_transfer')) reason = 'AMOUNT_OVERFLOW';
  else if (toBig(input.public_balance, 'public_balance') < toBig(input.minimum, 'minimum')) reason = 'THRESHOLD_MISMATCH';

  if (proofTx) seenProofTx.add(proofTx);
  if (reason) return { decision: 'REJECT', reason, proofTx, provable: true };
  return { decision: 'APPROVE', reason: 'VALID_CONDITION', proofTx, provable: true };
}

export async function buildProof(taskId, input, decision) {
  const { wasm, zkey } = await ensureArtifacts();
  const circuitInput = {
    taskId: taskIdField(taskId).toString(),
    minimum: toBig(input.minimum, 'minimum').toString(),
    publicBalance: toBig(input.public_balance, 'public_balance').toString(),
    expiryBlock: toBig(input.expiry_block, 'expiry_block').toString(),
    currentBlock: toBig(input.current_block, 'current_block').toString(),
    recipient: addressBig(input.recipient).toString(),
    conditionRecipient: addressBig(input.condition_recipient).toString(),
    amount: toBig(input.amount, 'amount').toString(),
    maxTransfer: toBig(input.max_transfer, 'max_transfer').toString(),
    registeredVkHash: toBig(input.registered_vk, 'registered_vk').toString(),
    proofVkHash: toBig(input.proof_vk, 'proof_vk').toString(),
    salt: BigInt('0x' + randomBytes(16).toString('hex')).toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasm, zkey);
  return { proof, publicSignals };
}

// ---------- request pipeline ----------
// Input: the RAW request body bytes + the signature header value.
// Output: { status, body, signature } — body is the exact JSON string to
// send back, signature its x-agent-games-signature header value.
// Identical for the local server and the serverless function.
export async function processPost(raw, signatureHeader) {
  const t0 = Date.now();
  const signed = (status, obj) => {
    const body = JSON.stringify(obj);
    let signature = null;
    try { signature = hmacHex(body); } catch { /* secret missing: cannot sign */ }
    return { status, body, signature };
  };
  try {
    // 1. HMAC over the RAW body, before parsing anything.
    if (!signatureOk(signatureHeader, raw)) {
      log('REFUSED bad/missing signature');
      return signed(401, { error: 'invalid signature' });
    }
    let msg;
    try {
      msg = JSON.parse(raw.toString('utf8'));
    } catch {
      return signed(400, { error: 'invalid json' });
    }
    // 2. Preflight.
    if (msg.type === 'agent-games.preflight.v1') {
      log('preflight ok for agent', msg.agent_id ?? '?');
      return signed(200, { ok: true, protocolVersion: 'v1' });
    }
    // 3. Gatekeeper task.
    if (msg.type === 'agent-games.proof-gatekeeper.v1') {
      const input = msg.input || {};
      const d = decide(input);
      let proof = null;
      let publicSignals = null;
      if (d.provable) {
        try {
          const out = await buildProof(msg.task_id, input, d.decision);
          proof = out.proof;
          publicSignals = out.publicSignals;
        } catch (e) {
          // Fail closed: never approve without a proof; report the failure.
          log('PROOF GENERATION FAILED for task', msg.task_id, '-', e.message);
          return signed(200, {
            task_id: msg.task_id ?? null,
            decision: 'REJECT',
            reason_code: 'PROOF_GENERATION_FAILED',
            proof: null,
            public_signals: null,
            proof_tx: d.proofTx,
          });
        }
      }
      log('task', msg.task_id, '->', d.decision, d.reason, `(${Date.now() - t0} ms)`);
      return signed(200, {
        task_id: msg.task_id ?? null,
        decision: d.decision,
        reason_code: d.reason,
        proof,
        public_signals: publicSignals,
        proof_tx: d.proofTx,
      });
    }
    return signed(400, { error: 'unknown type' });
  } catch (e) {
    log('ERROR', e.message);
    return signed(500, { error: 'internal' });
  }
}
