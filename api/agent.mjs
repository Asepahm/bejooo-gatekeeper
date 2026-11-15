// Vercel serverless entry for the Proof Gatekeeper agent.
// All logic lives in ../src/core.mjs, shared with the local server
// (src/gatekeeper.mjs) — responses are byte-identical in both shapes.
//
// The dashboard endpoint URL is: https://<project>.vercel.app/api/agent
//
// Raw body: bodyParser is disabled and the request stream is read by hand,
// because the platform's HMAC (x-agent-games-signature) is computed over
// the RAW request bytes — a pre-parsed body would break verification.
// Env: AGENT_GAMES_HMAC_SECRET (required). Circuit .wasm/.zkey are not in
// this repo; core.mjs downloads them from the official URLs on cold start
// and caches them in /tmp for the life of the function instance.
import { processPost, ensureArtifacts, HEALTH } from '../src/core.mjs';

export const config = {
  api: { bodyParser: false },
};

// Cold start: fetch the circuit artifacts in the background so the first
// task does not pay the full download inside its own 60 s window. The
// first task still awaits the same promise via buildProof if needed.
ensureArtifacts().catch(() => { /* retried on first task */ });

export default async function handler(req, res) {
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
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks);
  const { status, body, signature } = await processPost(raw, req.headers['x-agent-games-signature']);
  const headers = { 'content-type': 'application/json' };
  if (signature) headers['x-agent-games-signature'] = signature;
  res.writeHead(status, headers);
  res.end(body);
}
