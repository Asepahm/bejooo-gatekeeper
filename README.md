# bejooo-gatekeeper

Proof Gatekeeper agent for **zkVerify Agent Games — Season 01**, built for
@Bejo2703nasib (agent identity bejooo.ai).

The agent is a public HTTPS endpoint. The platform POSTs a signed task
envelope describing a proof-backed payment request; the agent verifies the
HMAC signature (`x-agent-games-signature`, over the raw body, before parsing),
checks every documented trap condition, decides **APPROVE** or **REJECT**
within the 60-second window, and proves its decision with a Groth16 proof
generated with the tournament's official gatekeeper circuit — the platform
re-verifies the proof against its own registered verification key.

## Checks (fail closed — any doubt is a REJECT)

- verification-key hash matches the registered gatekeeper vkHash
- condition not expired (expiry vs current block)
- recipient matches the condition recipient
- amount within the transfer cap
- public balance meets the condition threshold
- proof / public inputs not replayed (proof-reuse guard)

## Circuit

Groth16 / BN128, Circom 2.x. The official artifacts are **not** vendored in
this repo. For local runs you can download them into `circuits/` yourself:

- `https://agentgames.zkverify.io/circuits/gatekeeper.wasm`
- `https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey`

If they are absent, the endpoint downloads them from those URLs itself on
startup and caches them (see `ensureArtifacts()` in `src/core.mjs`) — this
is how the Vercel deployment gets them.

Registered gatekeeper vkHash:
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
(also served at `https://agentgames.zkverify.io/api/circuit-info`).
`circuits/verification_key.json` in this repo is the key exported from the
official zkey, used for local proof verification in the tests.

## Run

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<your agent secret> PORT=8731 npm start
# POST the full handler path (e.g. /agent); GET = health check
```

The HMAC secret is read from the environment only — never commit it.

## Deploy on Vercel (serverless)

The endpoint also ships as a Vercel serverless function. Both shapes run
the **same** shared logic (`src/core.mjs`), so responses are identical.

1. Import this repo in Vercel (New Project → Import Git Repository →
   `Asepahm/bejooo-gatekeeper`). No build settings needed: no build
   command, no output directory — the `api/` folder is picked up
   automatically, and `vercel.json` sets the function `maxDuration` to
   60 s (the free-tier maximum).
2. Add the environment variable **`AGENT_GAMES_HMAC_SECRET`** (Project →
   Settings → Environment Variables) with the agent secret from the
   dashboard's Rotate Secret. Never commit it.
3. Deploy. The function URL is:

   ```
   https://<project>.vercel.app/api/agent
   ```

   Register exactly that URL as the agent endpoint in the Agent Games
   dashboard. `GET` on it returns the health JSON; `POST` is the task
   handler (any path works locally, but `/api/agent` is the Vercel path).

Serverless specifics:

- `api/agent.mjs` disables Vercel's body parser and reads the raw request
  stream itself — the HMAC is over the raw body bytes, so a pre-parsed
  body would break signature verification.
- The circuit binaries are **not** in this repo. On cold start the
  function downloads `gatekeeper.wasm` + `gatekeeper_final.zkey` from the
  official URLs above (size- and SHA-256-checked), caches them in `/tmp`,
  and reuses them for the life of the instance. A background fetch starts
  at cold start; the first task awaits it if it is not done yet.
- Measured locally (simulated cold start, tests/serverless-harness.mjs):
  import 3 ms, artifact download ~2.1 s, first task end-to-end ~3.5 s,
  warm tasks ~0.5 s — far inside the platform's 60 s deadline.

## Tests

```bash
npm test             # trap matrix vs the local server: decisions + proof verification
npm run test:serverless   # simulated Vercel cold start: import api/agent.mjs,
                          # forced artifact download, raw-body HMAC, decisions
```

Local verification (2026-11-15): 7/7 trap decisions correct, 6/6 Groth16
proofs verified against the exported key, ~0.5 s per task; serverless
simulation all-pass. See `STATUS.md` for the full record.
