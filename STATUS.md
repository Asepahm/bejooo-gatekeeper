# Proof Gatekeeper — STATUS (built + locally verified 2026-11-15)

State: **endpoint built and fully verified locally; agent REGISTERED
2026-11-15 (`bejooo-gatekeeper`, agent_id in MEMORY.md); Vercel serverless
shape built + simulated locally (see "Vercel adaptation" below) — actual
Vercel deploy + dashboard endpoint URL still to be done by the parent.**
The HMAC secret is
read from env `AGENT_GAMES_HMAC_SECRET` only; all local tests used a throwaway
secret that appears nowhere in this repo's code or docs.

## Run it

```bash
cd ~/workspace/agentgames/gatekeeper
AGENT_GAMES_HMAC_SECRET=<platform secret from Rotate Secret> PORT=8731 npm start
# POST any path (register the full path, e.g. https://<host>/agent); GET = health
```

## Circuit signals — extracted from the official WASM by probing

Method: FNV-1a-64 hash of candidate names against the WASM export
`getInputSignalSize(hMSB, hLSB)` (this build returns 0 for unknown names,
1 for real scalar signals). ~250 candidates tested; exactly **13 found**,
matching `getInputSize() = 13`:

`taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash,
salt (private), decision (1=approve, 0=reject)`

Public signals (13, order verified empirically): `[0]=commitment,
[1]=registeredVkHash, [2]=proofVkHash, [3]=minimum, [4]=publicBalance,
[5]=expiryBlock, [6]=currentBlock, [7]=recipient, [8]=conditionRecipient,
[9]=amount, [10]=maxTransfer, [11]=decision, [12]=taskId`, where
`commitment = Poseidon(salt, taskId)` — **confirmed** against the official
circuit in tests/smoke-prove.mjs (Poseidon([987654321, 24]) equals
publicSignals[0] of the corresponding proof).

The circuit itself enforces `decision == verdict(inputs)`: an incorrect
decision has no witness (fullProve asserts). All documented traps except
PROOF_REUSED are circuit-enforced (vk equality, threshold, expiry, recipient,
amount cap), so a correct off-circuit decision is always provable.

## Verification key check

- Artifacts downloaded from the official URLs; SHA-256:
  wasm `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
  (1,755,820 B), zkey `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`
  (309,750 B) — identical to hashes independently recorded by another builder.
- VK exported with snarkjs 0.7.6: groth16 / bn128, 13 public signals
  (1 output + 12 public inputs). Proofs made with the official zkey verify
  against this exported VK locally (see matrix) — functional match confirmed.
- **vkHash string re-derivation: NOT reproduced.** The registered hash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  (confirmed live from the official `/api/circuit-info`) was not matched by
  Poseidon-sponge over the flattened VK (with/without IC), sha256, or
  sha3-256 of the exported VK JSON. The derivation is a chain-side
  (zkVerify/Kurier) encoding that is not published; treat the hash as an
  opaque identifier from `/api/circuit-info`. This does not affect proving
  or local verification.

## Trap matrix — tests/trap-matrix.mjs (server over local HTTP, real HMAC)

| case | decision | proof verified | time |
|---|---|---|---|
| preflight | `{ok:true, protocolVersion:"v1"}` + valid resp signature | — | 39 ms |
| VALID_CONDITION | APPROVE / VALID_CONDITION | yes (decision signal 1) | 563 ms |
| VK_SUBSTITUTION (proof_vk = vfy-policy vkHash) | REJECT / VK_SUBSTITUTION | yes (signal 0) | 473 ms |
| THRESHOLD_MISMATCH (balance 900 < min 1000) | REJECT / THRESHOLD_MISMATCH | yes | 520 ms |
| EXPIRED_CONDITION (current > expiry) | REJECT / EXPIRED_CONDITION | yes | 420 ms |
| RECIPIENT_MISMATCH | REJECT / RECIPIENT_MISMATCH | yes | 517 ms |
| AMOUNT_OVERFLOW (1500 > cap 1000) | REJECT / AMOUNT_OVERFLOW | yes | 408 ms |
| PROOF_REUSED (same proof_tx, new task_id) | REJECT / PROOF_REUSED | n/a — no proof, per official scoring note ("PROOF_REUSED tasks have no proof to submit and are excluded") | 6 ms |
| BAD_HMAC | HTTP 401 refused | — | 5 ms |

**Totals: decisions correct 7/7, proofs verified 6/6, response signatures
8/8.** Raw results: tests/trap-matrix-results.json. Cold fullProve at boot
1,659 ms (prover is warmed up at startup); per-task end-to-end 408–563 ms —
far under the 60 s deadline. Smoke test verify time ~201 ms (first run).

Decision order in code: PROOF_REUSED (seen-set on proof_tx) → VK_SUBSTITUTION
(registered_vk != proof_vk) → EXPIRED (current_block > expiry_block) →
RECIPIENT_MISMATCH → AMOUNT_OVERFLOW → THRESHOLD_MISMATCH → APPROVE.
On any proof-generation failure the endpoint fails closed with
REJECT / PROOF_GENERATION_FAILED and proof null.

## Tunnel reachability from THIS VM (no-account options only)

All HTTP egress goes through a proxy; the VM is 198.19.0.2 with no public IP.

| route | result | evidence |
|---|---|---|
| trycloudflare | blocked (not re-tested; pre-known) | api.trycloudflare.com returns 403 from this VM |
| localtunnel (`npx localtunnel`) | blocked / unreachable | no URL printed within 35 s |
| bore.pub (bore-cli 0.6.0) | blocked | `could not connect to bore.pub:7835 — timed out`, twice (a raw /dev/tcp probe misleadingly "connected"; the real client cannot) |
| localhost.run (SSH -R) | blocked | `kex_exchange_identification: read: Connection reset by peer` via egress proxy port 3128 |
| serveo.net (SSH -R) | blocked | same connection reset |
| pinggy | not separately run | SSH-based like the two above; same transport that was reset |

**Conclusion: no no-account tunnel works from this VM.** The parent must pick
an account-based route (e.g. Tailscale Funnel or serverless hosting — the
endpoint is a single dependency-light Node file plus ~2 MB of circuit files,
and snarkjs fullProve runs in-process, so a serverless port is feasible but
not built here).

## Uncertainties the parent must resolve at registration (flagged, not guessed)

1. **Response field names for the proof.** The event page's "Expected
   response shape" shows only `{decision, reason_code, proof_tx}` (proof_tx
   echoed from the input), while the build guide says to include the proof.
   This endpoint returns a superset: `{task_id, decision, reason_code,
   proof, public_signals, proof_tx}`. If the platform schema is strict,
   field names (`proof` / `public_signals` vs other spellings) need
   confirming in the dashboard/practice mode.
2. **taskId → field element mapping is unpublished.** Used here: numeric
   string → itself; else first embedded integer group (`gk_24_9d1` → 24);
   else a string hash mod p. If the platform recomputes public signals from
   the envelope, this mapping must match theirs — practice tasks will reveal it.
3. **HMAC encoding assumed HMAC-SHA256 hex** over the raw body (header value
   compared case-insensitively, optional `sha256=` prefix stripped). The
   guide names the header and the raw-body rule but not the algorithm/encoding
   in the text available; practice/preflight at registration will confirm.
4. **Expiry edge:** `current_block > expiry_block` is treated as expired;
   `current_block == expiry_block` is treated as still valid.
5. **256-bit VK hashes exceed the BN254 field** and are reduced mod p by the
   witness calculator (public signals carry the reduced value). Both envelope
   hashes are fed as-is; the platform must be doing the same reduction.
6. **proof_tx on PROOF_REUSED responses** is echoed with `proof: null`,
   matching the official note that reused tasks have no proof to submit.

## Vercel adaptation (2026-11-15, for the 17:30 WIB round)

The logic was factored into **`src/core.mjs`** (HMAC, decision, proving,
full request pipeline `processPost(rawBody, signatureHeader)` →
`{status, body, signature}`), shared verbatim by both entries:

- `src/gatekeeper.mjs` — local server, unchanged observable behaviour
  (same warm-up, same log lines, same responses). Trap matrix re-run
  after the refactor: **7/7 decisions, 6/6 proofs, 8/8 signatures.**
- `api/agent.mjs` — Vercel function. `export const config = { api:
  { bodyParser: false } }` and the handler reads the raw request stream
  itself, because the HMAC is over the raw bytes. Dashboard endpoint
  URL: `https://<project>.vercel.app/api/agent`.
- `vercel.json` — `functions."api/agent.mjs".maxDuration = 60` (free-tier
  maximum).

Circuit artifacts at runtime: binaries are not in the GitHub repo, so
`ensureArtifacts()` resolves them in order — `$GATEKEEPER_CIRCUIT_DIR`
(if set) → local `circuits/` (dev checkouts) → download from the official
URLs into `os.tmpdir()/gatekeeper-circuits`, verifying byte size and
SHA-256 against the known official values before use. `api/agent.mjs`
kicks the download off in the background at cold start; tasks await the
same promise.

Simulated cold start (`tests/serverless-harness.mjs`: fresh cache dir
forces the download path; handler imported and fed raw-body mock
requests): **ALL PASS** — GET health ok; preflight signed
`{ok:true, protocolVersion:"v1"}` in 4 ms (not blocked by the download);
bad HMAC → 401. Timings: import 3 ms; downloads wasm 1,547 ms + zkey
541 ms (artifacts resolved 2,095 ms total); **first task end-to-end
3,478 ms** (download + first prove, proof verified against the VK);
warm task 564 ms. All far inside the 60 s task deadline, with the 60 s
function maxDuration as the outer bound.

Note: `seenProofTx` (PROOF_REUSED guard) is in-process state — on
serverless it is per warm instance, same best-effort semantics as the
platform's own note that reused tasks carry no proof.

## File layout

```
src/core.mjs              shared logic: HMAC, decide, prove, processPost
src/gatekeeper.mjs        local server entry (Node http, warm-up + listen)
api/agent.mjs             Vercel serverless entry (raw-body handler)
vercel.json               function config (maxDuration 60)
circuits/gatekeeper.wasm  official circuit (downloaded 2026-11-15; NOT in GitHub repo)
circuits/gatekeeper_final.zkey   (same — fetched at runtime when absent)
circuits/verification_key.json   exported from the zkey
tests/probe-signals.mjs   WASM signal-name prober
tests/smoke-prove.mjs     fullProve + verify + Poseidon commitment + vkHash tries
tests/trap-matrix.mjs     acceptance harness (npm test)
tests/serverless-harness.mjs     simulated Vercel cold start (npm run test:serverless)
tests/trap-matrix-results.json   raw results of the run above
package.json              snarkjs 0.7.6, circomlibjs 0.1.7; scripts: start/test/test:serverless/probe
```
