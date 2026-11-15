// zkVerify Agent Games — Proof Gatekeeper agent endpoint (local server mode).
// Plain Node http server around the shared core (src/core.mjs), which is
// also what the Vercel serverless entry (api/agent.mjs) runs — behaviour
// is identical in both shapes:
//   raw-body HMAC verify (x-agent-games-signature, HMAC-SHA256 hex) BEFORE
//   parsing -> preflight handler -> task handler -> Groth16 proof of the
//   decision with the official gatekeeper circuit -> signed JSON response.
import { createServer } from 'node:http';
import { processPost, buildProof, HEALTH, log } from './core.mjs';

const PORT = Number(process.env.PORT || 8731);
const HOST = process.env.HOST || '0.0.0.0';
if (!process.env.AGENT_GAMES_HMAC_SECRET) {
  console.error('FATAL: AGENT_GAMES_HMAC_SECRET is not set');
  process.exit(1);
}

const server = createServer((req, res) => {
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(HEALTH));
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
    const { status, body, signature } = await processPost(raw, req.headers['x-agent-games-signature']);
    const headers = { 'content-type': 'application/json' };
    if (signature) headers['x-agent-games-signature'] = signature;
    res.writeHead(status, headers);
    res.end(body);
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
