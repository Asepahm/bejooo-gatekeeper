// zkVerify Agent Games — Proof Gatekeeper agent endpoint.
// Plain Node http server. Behaviour per the official field guide (/build),
// the event page (/events/proof-gatekeeper) and the official circuit:
//   raw-body HMAC verify (x-agent-games-signature, HMAC-SHA256 hex) BEFORE
//   parsing -> preflight handler -> task handler: run every documented
//   check -> decision -> Groth16 proof of THAT decision with the official
//   gatekeeper circuit -> signed JSON response. Fail closed everywhere.
import { createServer } from 'node:http';
import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as snarkjs from 'snarkjs';

const PORT = Number(process.env.PORT || 8731);
const HOST = process.env.HOST || '0.0.0.0';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) {
  console.error('FATAL: AGENT_GAMES_HMAC_SECRET is not set');
  process.exit(1);
}

const CIRCUITS = new URL('../circuits/', import.meta.url);
const WASM = new URL('gatekeeper.wasm', CIRCUITS).pathname;
const ZKEY = new URL('gatekeeper_final.zkey', CIRCUITS).pathname;
const VK = JSON.parse(readFileSync(new URL('verification_key.json', CIRCUITS), 'utf8'));

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const seenProofTx = new Set();

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}
function hmacHex(data) {
  return createHmac('sha256', SECRET).update(data).digest('hex');
}
function signatureOk(headerValue, rawBody) {
  if (!headerValue) return false;
  const given = String(headerValue).trim().toLowerCase().replace(/^sha256=/, '');
  const expected = hmacHex(rawBody);
  const a = Buffer.from(given, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}
function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': hmacHex(body),
  });
  res.end(body);
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
function decide(input) {
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

async function buildProof(taskId, input, decision) {
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
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}

// ---------- HTTP ----------
const server = createServer((req, res) => {
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1' }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'method not allowed' }));
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    const t0 = Date.now();
    try {
      // 1. HMAC over the RAW body, before parsing anything.
      if (!signatureOk(req.headers['x-agent-games-signature'], raw)) {
        log('REFUSED bad/missing signature from', req.socket.remoteAddress);
        sendSigned(res, 401, { error: 'invalid signature' });
        return;
      }
      let msg;
      try {
        msg = JSON.parse(raw.toString('utf8'));
      } catch {
        sendSigned(res, 400, { error: 'invalid json' });
        return;
      }
      // 2. Preflight.
      if (msg.type === 'agent-games.preflight.v1') {
        log('preflight ok for agent', msg.agent_id ?? '?');
        sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
        return;
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
            sendSigned(res, 200, {
              task_id: msg.task_id ?? null,
              decision: 'REJECT',
              reason_code: 'PROOF_GENERATION_FAILED',
              proof: null,
              public_signals: null,
              proof_tx: d.proofTx,
            });
            return;
          }
        }
        log('task', msg.task_id, '->', d.decision, d.reason, `(${Date.now() - t0} ms)`);
        sendSigned(res, 200, {
          task_id: msg.task_id ?? null,
          decision: d.decision,
          reason_code: d.reason,
          proof,
          public_signals: publicSignals,
          proof_tx: d.proofTx,
        });
        return;
      }
      sendSigned(res, 400, { error: 'unknown type' });
    } catch (e) {
      log('ERROR', e.message);
      try { sendSigned(res, 500, { error: 'internal' }); } catch { /* socket gone */ }
    }
  });
});

// Warm the prover once so the first real task is fast, then listen.
(async () => {
  try {
    const t = Date.now();
    await buildProof('warmup', {
      minimum: '1000', public_balance: '1460', expiry_block: 19842201, current_block: 19832000,
      recipient: '0x0000000000000000000000000000000000000001',
      condition_recipient: '0x0000000000000000000000000000000000000001',
      amount: '500', max_transfer: '1000',
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    }, 'APPROVE');
    log(`prover warm-up ok in ${Date.now() - t} ms`);
  } catch (e) {
    console.error('FATAL: prover warm-up failed:', e.message);
    process.exit(1);
  }
  server.listen(PORT, HOST, () => log(`gatekeeper listening on http://${HOST}:${PORT} (POST any path; GET = health)`));
})();
