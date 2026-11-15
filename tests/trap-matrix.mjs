// Trap-matrix acceptance test: start the gatekeeper with a throwaway secret,
// send correctly HMAC-signed envelopes for every documented trap type, and
// check (a) the decision + reason_code, (b) the response HMAC, and
// (c) snarkjs groth16 verify of the returned proof against the official VK.
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import * as snarkjs from 'snarkjs';

const SECRET = 'local-test-secret-throwaway';
const PORT = 8731;
const BASE = `http://127.0.0.1:${PORT}`;
const VK = JSON.parse(readFileSync(new URL('../circuits/verification_key.json', import.meta.url), 'utf8'));

const GK_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VFY_POLICY_VK = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047'; // real but wrong VK = substitution
const RECIPIENT = '0xDe42' + '0'.repeat(32) + '9f01';
const RECIPIENT_OTHER = '0xDe42' + '0'.repeat(32) + '9f02';
const tx = (n) => '0x' + String(n).padStart(2, '0').repeat(32);

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

const sign = (body, secret = SECRET) => createHmac('sha256', secret).update(body).digest('hex');

async function post(obj, { secret = SECRET, badSig = false } = {}) {
  const body = JSON.stringify(obj);
  const t0 = Date.now();
  const r = await fetch(BASE + '/agent', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': badSig ? 'deadbeef'.repeat(8) : sign(body, secret),
    },
    body,
  });
  const text = await r.text();
  return { status: r.status, ms: Date.now() - t0, text, json: JSON.parse(text), respSig: r.headers.get('x-agent-games-signature') };
}

const results = [];
async function runCase(name, obj, expect, opts = {}) {
  const r = await post(obj, opts);
  const entry = { name, http: r.status, ms: r.ms, got: r.json.decision ?? null, reason: r.json.reason_code ?? null };
  entry.decisionOk = r.json.decision === expect.decision && (expect.reason ? r.json.reason_code === expect.reason : true);
  entry.respSigOk = r.respSig === sign(r.text);
  if (expect.proof === 'verify') {
    entry.proofPresent = !!r.json.proof;
    entry.proofVerified = entry.proofPresent
      ? await snarkjs.groth16.verify(VK, r.json.public_signals, r.json.proof)
      : false;
    entry.decisionSignal = r.json.public_signals ? r.json.public_signals[11] : null;
  } else if (expect.proof === 'none') {
    entry.proofPresent = !!r.json.proof;
  }
  results.push(entry);
  console.log(
    `${entry.decisionOk && (expect.proof !== 'verify' || entry.proofVerified) ? 'PASS' : 'FAIL'} ${name}: ` +
    `${entry.got}/${entry.reason} http=${entry.http} ${entry.ms}ms` +
    (expect.proof === 'verify' ? ` proofVerified=${entry.proofVerified} decisionSignal=${entry.decisionSignal}` : '') +
    ` respSigOk=${entry.respSigOk}`
  );
  return r;
}

// start server
const server = spawn('node', ['src/gatekeeper.mjs'], {
  cwd: new URL('..', import.meta.url).pathname,
  env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT) },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let serverLog = '';
server.stdout.on('data', (d) => { serverLog += d; });
server.stderr.on('data', (d) => { serverLog += d; });
await new Promise((resolve, reject) => {
  const iv = setInterval(() => {
    if (serverLog.includes('listening')) { clearInterval(iv); resolve(); }
  }, 100);
  setTimeout(() => reject(new Error('server did not start: ' + serverLog)), 30000);
});
console.log('server up (warm-up done)');

try {
  // preflight
  const pf = await post({ type: 'agent-games.preflight.v1', agent_id: 'test-agent', issued_at: Date.now(), nonce: 'n-1' });
  const pfOk = pf.status === 200 && pf.json.ok === true && pf.json.protocolVersion === 'v1' && pf.respSig === sign(pf.text);
  results.push({ name: 'preflight', http: pf.status, ms: pf.ms, preflightOk: pfOk, respSigOk: pf.respSig === sign(pf.text) });
  console.log(`${pfOk ? 'PASS' : 'FAIL'} preflight: ${pf.text} ${pf.ms}ms`);

  await runCase('VALID_CONDITION', envelope('gk_101_a'), { decision: 'APPROVE', reason: 'VALID_CONDITION', proof: 'verify' });
  await runCase('VK_SUBSTITUTION', envelope('gk_102_b', { proof_vk: VFY_POLICY_VK, proof_tx: tx(2) }), { decision: 'REJECT', reason: 'VK_SUBSTITUTION', proof: 'verify' });
  await runCase('THRESHOLD_MISMATCH', envelope('gk_103_c', { public_balance: '900', proof_tx: tx(3) }), { decision: 'REJECT', reason: 'THRESHOLD_MISMATCH', proof: 'verify' });
  await runCase('EXPIRED_CONDITION', envelope('gk_104_d', { current_block: 19843000, proof_tx: tx(4) }), { decision: 'REJECT', reason: 'EXPIRED_CONDITION', proof: 'verify' });
  await runCase('RECIPIENT_MISMATCH', envelope('gk_105_e', { recipient: RECIPIENT_OTHER, proof_tx: tx(5) }), { decision: 'REJECT', reason: 'RECIPIENT_MISMATCH', proof: 'verify' });
  await runCase('AMOUNT_OVERFLOW', envelope('gk_106_f', { amount: '1500', proof_tx: tx(6) }), { decision: 'REJECT', reason: 'AMOUNT_OVERFLOW', proof: 'verify' });
  // reuse of case 1's proof_tx under a fresh task id, everything else valid
  await runCase('PROOF_REUSED', envelope('gk_107_g', { proof_tx: tx(1) }), { decision: 'REJECT', reason: 'PROOF_REUSED', proof: 'none' });
  // bad HMAC must be refused
  const bad = await post(envelope('gk_108_h', { proof_tx: tx(8) }), { badSig: true });
  const badOk = bad.status === 401;
  results.push({ name: 'BAD_HMAC', http: bad.status, refused: badOk, ms: bad.ms });
  console.log(`${badOk ? 'PASS' : 'FAIL'} BAD_HMAC: http=${bad.status} ${bad.ms}ms`);
} finally {
  server.kill('SIGTERM');
}

writeFileSync(new URL('trap-matrix-results.json', import.meta.url), JSON.stringify(results, null, 2));
const taskCases = results.filter((r) => r.got !== undefined && r.got !== null);
const proofs = results.filter((r) => r.proofVerified !== undefined);
console.log(`\nSUMMARY: decisions correct ${taskCases.filter((r) => r.decisionOk).length}/${taskCases.length}, ` +
  `proofs verified ${proofs.filter((r) => r.proofVerified).length}/${proofs.length}, ` +
  `response sigs ok ${results.filter((r) => r.respSigOk).length}/${results.filter((r) => r.respSigOk !== undefined).length}`);
process.exit(0);
