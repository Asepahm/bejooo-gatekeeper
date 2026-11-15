// Probe the official gatekeeper.wasm for its input signal names.
// Circom 2.x resolves input signals by FNV-1a-64 hash of the name; the WASM
// export getInputSignalSize(hMSB, hLSB) returns < 0 for unknown names.
import { readFileSync } from 'node:fs';
import { WitnessCalculatorBuilder } from 'circom_runtime';

function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt('0xCBF29CE484222325');
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str[i].charCodeAt(0));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  return hash.toString(16).padStart(16, '0');
}

const bases = [
  'taskId', 'task_id', 'taskID', 'id', 'task', 'taskid',
  'minimum', 'min', 'minBalance', 'minimumBalance', 'threshold', 'minThreshold', 'requiredMinimum',
  'publicBalance', 'public_balance', 'balance', 'bal',
  'expiryBlock', 'expiry_block', 'expiry', 'expiryHeight', 'expirationBlock',
  'currentBlock', 'current_block', 'blockHeight', 'blockNumber', 'currentHeight', 'nowBlock',
  'recipient', 'to', 'payee', 'recipientAddress',
  'conditionRecipient', 'condition_recipient', 'expectedRecipient', 'condRecipient',
  'amount', 'value', 'transferAmount', 'paymentAmount', 'amt',
  'maxTransfer', 'max_transfer', 'cap', 'maxAmount', 'transferCap', 'limit', 'max',
  'registeredVkHash', 'registered_vk', 'registeredVk', 'registeredVKHash', 'registeredVK',
  'proofVkHash', 'proof_vk', 'proofVk', 'proofVKHash', 'proofVK',
  'vkHash', 'vk', 'vk_hash',
  'salt', 'nonce', 'secret', 'privateSalt', 'randomness',
  'decision', 'verdict', 'approve', 'approved', 'outcome', 'result', 'isApproved',
  'proofTx', 'proof_tx', 'proofReference', 'proofRef', 'txHash', 'proofHash',
  'commitment', 'output', 'decisionProof',
];
// add case variants + "main." prefixed variants (circom sometimes uses component paths)
const candidates = new Set();
for (const b of bases) {
  candidates.add(b);
  candidates.add('main.' + b);
  candidates.add(b.charAt(0).toUpperCase() + b.slice(1));
}

const wasm = readFileSync(new URL('../circuits/gatekeeper.wasm', import.meta.url));
const wc = await WitnessCalculatorBuilder(wasm);
const ex = wc.instance.exports;
console.log('getInputSize() =', ex.getInputSize());
console.log('getWatchedSignals / version exports present:', Object.keys(ex).filter(k => /input|version/i.test(k)).join(', '));

const found = [];
for (const name of candidates) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  let size = -1;
  try { size = ex.getInputSignalSize(hMSB, hLSB); } catch { size = -1; }
  // this WASM build returns 0 for unknown names, >= 1 for real signals
  if (size > 0) found.push({ name, size });
}
console.log('FOUND', found.length, 'input signals:');
for (const f of found) console.log(' -', f.name, '(size ' + f.size + ')');
process.exit(0);
