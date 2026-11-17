// Prabowo — Proof Gatekeeper agent endpoint, Vercel serverless version
// (zkVerify Agent Games). Ported from server.js (Node built-ins only:
// http + crypto + fs + path, zero dependencies).
// Env: AGENT_GAMES_HMAC_SECRET (set as a Vercel env var, never committed).
//
// Routes (all paths rewrite to this function via vercel.json):
//   GET  * -> 200 {"status":"ok", ...}
//   POST * -> task / preflight (HMAC verified, signed reply)
// Notes:
//   - HMAC-SHA256 over the RAW request body, header x-agent-games-signature.
//   - Every response is signed with x-agent-games-signature over the raw body.
//   - Decision logic is deterministic; fail closed (REJECT on uncertainty).
//   - No Groth16 proof is generated: the circuit input schema is not
//     documented on the site, so proof/public_signals are omitted. Per the
//     scoring rules that costs -2 per provable task + no reliability bonus;
//     the decision itself still scores (+12 / -6 / -3).
//   - proof_tx seen-set persists to /tmp/seen-proof-tx.json (warm-instance
//     only). On serverless the file does NOT survive a cold start on a new
//     instance, so PROOF_REUSED protection can reset — accepted degradation
//     vs being fully down (the platform does not replay proofs).

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
if (!SECRET) console.error('[gatekeeper] WARNING: AGENT_GAMES_HMAC_SECRET is empty — HMAC verification will fail closed (all signed requests rejected).');

// proof_tx seen-set, persisted to /tmp so warm invocations on the same
// instance keep the PROOF_REUSED protection.
const SEEN_FILE = path.join('/tmp', 'seen-proof-tx.json');
const seenProofTx = new Set();
try {
  const saved = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
  if (Array.isArray(saved)) for (const v of saved) seenProofTx.add(String(v));
  if (seenProofTx.size) console.log(`[gatekeeper] loaded ${seenProofTx.size} seen proof_tx from /tmp`);
} catch { /* no saved set yet — start empty */ }
function saveSeenProofTx() {
  try {
    fs.writeFileSync(SEEN_FILE, JSON.stringify([...seenProofTx]));
  } catch (e) {
    console.error('[gatekeeper] failed to persist seen proof_tx:', e.message);
  }
}
let stats = { tasks: 0, approved: 0, rejected: 0, preflights: 0, rejectedAuth: 0 };

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function safeEqual(a, b) {
  const ba = Buffer.from(a || '', 'utf8');
  const bb = Buffer.from(b || '', 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function signResponse(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'x-agent-games-signature': hmacHex(SECRET, body),
  });
  res.end(body);
}

function toBig(v) {
  // Task numeric fields arrive as decimal strings; compare as BigInt.
  try { return BigInt(String(v)); } catch { return null; }
}

// Returns {decision, reason_code} for a well-formed task input.
function decide(input) {
  const { registered_vk, proof_vk, minimum, public_balance,
    expiry_block, current_block, recipient, condition_recipient,
    amount, max_transfer, proof_tx } = input;

  // 1. VK substitution — proof verifies but against the wrong key.
  if (String(proof_vk).toLowerCase() !== String(registered_vk).toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  // 2. Threshold — public balance below the required minimum.
  const min = toBig(minimum), bal = toBig(public_balance);
  if (min === null || bal === null || bal < min) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  // 3. Proof reused — reference already accepted in a previous task.
  if (proof_tx && seenProofTx.has(String(proof_tx))) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  }
  // 4. Expired condition — current block past the expiry block.
  const exp = toBig(expiry_block), cur = toBig(current_block);
  if (exp === null || cur === null || cur > exp) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  // 5. Recipient mismatch — proof recipient != condition recipient.
  if (String(recipient).toLowerCase() !== String(condition_recipient).toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  // 6. Amount overflow — requested amount above the single-transfer cap.
  const amt = toBig(amount), cap = toBig(max_transfer);
  if (amt === null || cap === null || amt > cap) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// Vercel serverless handler. Path-agnostic on purpose: vercel.json rewrites
// every path here, and the function may see the rewritten URL, so GET always
// answers health and POST always runs the signed task flow.
module.exports = async (req, res) => {
  if (req.method === 'GET') {
    return signResponse(res, 200, {
      status: 'ok',
      agent: 'prabowo-gatekeeper',
      protocolVersion: 'v1',
      tasks: stats.tasks,
      approved: stats.approved,
      rejected: stats.rejected,
    });
  }

  if (req.method !== 'POST') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'not found' }));
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks);

    // Verify HMAC over the RAW body before parsing anything.
    const sig = req.headers['x-agent-games-signature'];
    if (!SECRET || !sig || !safeEqual(sig, hmacHex(SECRET, raw))) {
      stats.rejectedAuth += 1;
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'bad signature' }));
    }

    let body;
    try {
      body = JSON.parse(raw.toString('utf8'));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'invalid json' }));
    }

    // Preflight: signed handshake before any task.
    if (body && (typeof body.type === 'string' && /preflight/i.test(body.type) || body.mode === 'preflight')) {
      stats.preflights += 1;
      return signResponse(res, 200, { ok: true, protocolVersion: 'v1' });
    }

    // Task envelope.
    if (!body || body.type !== 'agent-games.proof-gatekeeper.v1' || !body.input || typeof body.input !== 'object') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'unknown envelope' }));
    }

    const input = body.input;
    const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance',
      'expiry_block', 'current_block', 'recipient', 'condition_recipient',
      'amount', 'max_transfer'];
    const missing = required.filter((k) => input[k] === undefined || input[k] === null || input[k] === '');
    if (missing.length > 0) {
      // Fail closed: cannot evaluate -> reject the decision.
      stats.tasks += 1; stats.rejected += 1;
      return signResponse(res, 200, {
        decision: 'REJECT',
        reason_code: 'INVALID_TASK',
        proof_tx: input.proof_tx || null,
      });
    }

    const out = decide(input);
    stats.tasks += 1;
    if (out.decision === 'APPROVE') {
      stats.approved += 1;
      if (input.proof_tx) { seenProofTx.add(String(input.proof_tx)); saveSeenProofTx(); }
    } else {
      stats.rejected += 1;
    }
    console.log(`[gatekeeper] ${body.task_id || '?'} -> ${out.decision} ${out.reason_code}`);
    return signResponse(res, 200, {
      decision: out.decision,
      reason_code: out.reason_code,
      proof_tx: input.proof_tx || null,
    });
  });
};
