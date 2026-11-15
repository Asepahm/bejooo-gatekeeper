// Serverless simulation harness: imports api/agent.mjs the way Vercel's
// Node runtime would (default-export handler, bodyParser disabled) and
// feeds it mock req/res pairs carrying RAW body bytes. Forces the
// download path for the circuit artifacts (fresh GATEKEEPER_CIRCUIT_DIR),
// so the first task measures a true cold start: import + artifact
// download + first prove.
// Run: node tests/serverless-harness.mjs
import { Readable } from 'node:stream';
import { createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as snarkjs from 'snarkjs';

const SECRET = 'local-test-secret-throwaway';
process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
process.env.GATEKEEPER_CIRCUIT_DIR = mkdtempSync(join(tmpdir(), 'gk-serverless-sim-'));
console.log('simulated cold start, circuit cache dir:', process.env.GATEKEEPER_CIRCUIT_DIR);

const VK = JSON.parse(readFileSync(new URL('../circuits/verification_key.json', import.meta.url), 'utf8'));
const GK_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VFY_POLICY_VK = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
const RECIPIENT = '0xDe42' + '0'.repeat(32) + '9f01';
const tx = (n) => '0x' + String(n).padStart(2, '0').repeat(32);
const sign = (body, secret = SECRET) => createHmac('sha256', secret).update(body).digest('hex');

const tImport0 = Date.now();
const { default: handler } = await import('../api/agent.mjs');
const importMs = Date.now() - tImport0;
console.log(`handler import (cold start): ${importMs} ms`);

function invoke(method, rawBody, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = Readable.from(rawBody ? [Buffer.from(rawBody)] : []);
    req.method = method;
    req.headers = headers;
    const res = {
      status: null,
      headers: null,
      body: null,
      writeHead(status, hdrs) { this.status = status; this.headers = hdrs; },
      end(body) { this.body = body ?? null; resolve(this); },
    };
    Promise.resolve(handler(req, res)).catch(reject);
  });
}

async function post(obj, { badSig = false } = {}) {
  const body = JSON.stringify(obj);
  const t0 = Date.now();
  const r = await invoke('POST', body, {
    'content-type': 'application/json',
    'x-agent-games-signature': badSig ? 'deadbeef'.repeat(8) : sign(body),
  });
  return { status: r.status, ms: Date.now() - t0, text: r.body, json: JSON.parse(r.body), respSig: r.headers['x-agent-games-signature'] };
}

function envelope(taskId, overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: GK_VK,
      proof_vk: GK_VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: '500',
      max_transfer: '1000',
      proof_tx: tx(1),
      ...overrides,
    },
  };
}

let failures = 0;
const check = (name, ok, detail) => {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`);
};

// GET health
const health = await invoke('GET', null);
check('GET health', health.status === 200 && JSON.parse(health.body).ok === true, health.body);

// Preflight (before any task; may still be during artifact download —
// preflight needs no artifacts, so this also proves it is not blocked).
const pf = await post({ type: 'agent-games.preflight.v1', agent_id: 'test-agent', issued_at: Date.now(), nonce: 'n-1' });
check('preflight', pf.status === 200 && pf.json.ok === true && pf.json.protocolVersion === 'v1' && pf.respSig === sign(pf.text), `${pf.ms} ms`);

// First real task = cold end-to-end (artifact download + first prove).
const tCold0 = Date.now();
const cold = await post(envelope('gk_201_a'));
const coldMs = Date.now() - tCold0;
const coldProofOk = cold.json.proof ? await snarkjs.groth16.verify(VK, cold.json.public_signals, cold.json.proof) : false;
check('COLD task VALID_CONDITION', cold.status === 200 && cold.json.decision === 'APPROVE' && cold.json.reason_code === 'VALID_CONDITION' && coldProofOk && cold.respSig === sign(cold.text),
  `end-to-end ${coldMs} ms (import ${importMs} ms + this request ${cold.ms} ms), proofVerified=${coldProofOk}`);

// Warm task: a reject case with proof.
const warm = await post(envelope('gk_202_b', { proof_vk: VFY_POLICY_VK, proof_tx: tx(2) }));
const warmProofOk = warm.json.proof ? await snarkjs.groth16.verify(VK, warm.json.public_signals, warm.json.proof) : false;
check('WARM task VK_SUBSTITUTION', warm.status === 200 && warm.json.decision === 'REJECT' && warm.json.reason_code === 'VK_SUBSTITUTION' && warmProofOk,
  `${warm.ms} ms, proofVerified=${warmProofOk}`);

// Bad HMAC -> 401
const bad = await post(envelope('gk_203_c', { proof_tx: tx(3) }), { badSig: true });
check('BAD_HMAC refused', bad.status === 401, `http=${bad.status} ${bad.ms} ms`);

console.log(`\nSUMMARY: ${failures === 0 ? 'ALL PASS' : failures + ' FAILURES'} | import ${importMs} ms, cold task end-to-end ${coldMs} ms, warm task ${warm.ms} ms`);
process.exit(failures === 0 ? 0 : 1);
