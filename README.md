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
this repo; download them from the tournament site into `circuits/`:

- `https://agentgames.zkverify.io/circuits/gatekeeper.wasm`
- `https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey`

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

## Tests

```bash
npm test   # trap matrix: signed HTTP calls, decision + proof verification per case
```

Local verification (2026-11-15): 7/7 trap decisions correct, 6/6 Groth16
proofs verified against the exported key, ~0.5 s per task. See `STATUS.md`
for the full record.
