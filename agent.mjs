// Proof Gatekeeper agent — Agent Games by zkVerify.
// Receives signed task envelopes, decides deterministically, answers with a
// Groth16 proof of the decision (snarkjs, official gatekeeper circuit).
import http from "node:http";
import { createHmac, createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8787;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const SALT_KEY = readFileSync(path.join(DIR, "salt-key.txt"), "utf8").trim();
const WASM = path.join(DIR, "gatekeeper.wasm");
const ZKEY = path.join(DIR, "gatekeeper_final.zkey");
const STATE_FILE = path.join(DIR, "state.json");
const LOG_FILE = path.join(DIR, "agent.log");
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function log(obj) {
  const line = JSON.stringify({ t: new Date().toISOString(), ...obj });
  try { writeFileSync(LOG_FILE, line + "\n", { flag: "a" }); } catch {}
  console.log(line);
}

// ---------- persistent state: seen proof refs + task response cache ----------
let state = { seen: {}, tasks: {} };
if (existsSync(STATE_FILE)) {
  try { state = JSON.parse(readFileSync(STATE_FILE, "utf8")); } catch {}
}
function saveState() {
  try { writeFileSync(STATE_FILE, JSON.stringify(state), { mode: 0o600 }); } catch {}
}

// ---------- HMAC (dual convention: secret as utf8 text or as hex bytes) ----
let matchedKey = null; // Buffer, locked after first successful verify
let matchedPrefix = ""; // "sha256=" if the sender used it
function keyCandidates() {
  const keys = [];
  if (SECRET) {
    keys.push(Buffer.from(SECRET, "utf8"));
    if (/^[0-9a-fA-F]+$/.test(SECRET) && SECRET.length % 2 === 0) {
      keys.push(Buffer.from(SECRET, "hex"));
    }
  }
  return keys;
}
function verifySignature(rawBody, headerValue) {
  if (!headerValue || !SECRET) return false;
  let given = String(headerValue).trim();
  let prefix = "";
  if (given.toLowerCase().startsWith("sha256=")) { prefix = "sha256="; given = given.slice(7); }
  let givenBuf;
  try { givenBuf = Buffer.from(given, "hex"); } catch { return false; }
  if (givenBuf.length !== 32) return false;
  const keys = matchedKey ? [matchedKey] : keyCandidates();
  for (const key of keys) {
    const mac = createHmac("sha256", key).update(rawBody).digest();
    if (timingSafeEqual(mac, givenBuf)) {
      if (!matchedKey) { matchedKey = key; matchedPrefix = prefix; log({ ev: "hmac_convention_locked", prefix: prefix || "(none)" }); }
      return true;
    }
  }
  return false;
}
function signBody(bodyStr) {
  const key = matchedKey || keyCandidates()[0];
  const mac = createHmac("sha256", key).update(bodyStr, "utf8").digest("hex");
  return matchedPrefix + mac;
}
function sendSigned(res, obj, status = 200) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": signBody(body),
  });
  res.end(body);
}

// ---------- field encodings (per official circuit conventions) -------------
const field = (s) => (BigInt(s) % FIELD).toString();
const uint = (s) => BigInt(s);
function taskField(taskId) {
  if (/^0x[0-9a-f]+$/i.test(taskId)) return (BigInt(taskId) % FIELD).toString();
  return (BigInt("0x" + createHash("sha256").update(taskId).digest("hex")) % FIELD).toString();
}
function saltFor(mode, taskId) {
  const h = createHmac("sha256", SALT_KEY).update(`gatekeeper-salt-v1:${mode}:${taskId}`).digest("hex");
  return (BigInt("0x" + h) % FIELD).toString();
}

// ---------- deterministic decision -----------------------------------------
function decide(input, mode, taskId) {
  const seenKey = `${mode}:${String(input.proof_tx).toLowerCase()}`;
  if (state.seen[seenKey] && state.seen[seenKey] !== taskId) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", reused: true };
  }
  if (field(input.proof_vk) !== field(input.registered_vk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  }
  if (uint(input.public_balance) < uint(input.minimum)) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  }
  if (uint(input.current_block) >= uint(input.expiry_block)) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  }
  if (field(input.recipient) !== field(input.condition_recipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  }
  if (uint(input.amount) > uint(input.max_transfer)) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

async function prove(task, decisionStr) {
  const i = task.input;
  const witness = {
    registeredVkHash: field(i.registered_vk),
    proofVkHash: field(i.proof_vk),
    minimum: uint(i.minimum).toString(),
    publicBalance: uint(i.public_balance).toString(),
    expiryBlock: uint(i.expiry_block).toString(),
    currentBlock: uint(i.current_block).toString(),
    recipient: field(i.recipient),
    conditionRecipient: field(i.condition_recipient),
    amount: uint(i.amount).toString(),
    maxTransfer: uint(i.max_transfer).toString(),
    decision: decisionStr === "APPROVE" ? "1" : "0",
    taskId: taskField(task.task_id),
    salt: saltFor(task.mode || "competition", task.task_id),
  };
  const { proof, publicSignals } = await groth16.fullProve(witness, WASM, ZKEY);
  return { proof, public_signals: publicSignals };
}

// ---------- task handling ----------------------------------------------------
async function handleTask(task) {
  const mode = task.mode || "competition";
  const taskId = task.task_id;
  const cacheKey = `${mode}:${taskId}`;
  if (state.tasks[cacheKey]) {
    log({ ev: "task_retry_cached", taskId, mode });
    return state.tasks[cacheKey]; // stored response object (idempotent retry)
  }
  const started = Date.now();
  const d = decide(task.input, mode, taskId);
  const resp = { decision: d.decision, reason_code: d.reason_code, proof_tx: task.input.proof_tx };
  if (!d.reused) {
    try {
      const p = await prove(task, d.decision);
      resp.proof = p.proof;
      resp.public_signals = p.public_signals;
    } catch (e) {
      log({ ev: "prove_failed", taskId, mode, err: String(e && e.message || e).slice(0, 200) });
      // Fail closed: keep the decision, ship without proof rather than time out.
    }
  }
  // record the proof reference as seen (all tasks, after deciding)
  state.seen[`${mode}:${String(task.input.proof_tx).toLowerCase()}`] = taskId;
  state.tasks[cacheKey] = resp;
  saveState();
  log({ ev: "task", taskId, mode, decision: d.decision, reason: d.reason_code, proved: !!resp.proof, ms: Date.now() - started });
  return resp;
}

// ---------- HTTP server -------------------------------------------------------
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && (url.pathname === "/agent" || url.pathname === "/" || url.pathname === "/health")) {
      const body = JSON.stringify({ ok: true, protocolVersion: "v1", service: "proof-gatekeeper" });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }
    if (req.method !== "POST" || url.pathname !== "/agent") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "not_found" }));
      return;
    }
    const sig = req.headers["x-agent-games-signature"];
    if (!verifySignature(raw, sig)) {
      log({ ev: "bad_signature", len: raw.length });
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "invalid_signature" }));
      return;
    }
    let msg;
    try { msg = JSON.parse(raw.toString("utf8")); } catch {
      sendSigned(res, { ok: false, error: "invalid_json" }, 400);
      return;
    }
    try {
      if (msg.type === "agent-games.preflight.v1") {
        log({ ev: "preflight", agent_id: msg.agent_id || null });
        sendSigned(res, { ok: true, protocolVersion: "v1" });
        return;
      }
      if (msg.type === "agent-games.proof-gatekeeper.v1") {
        const resp = await handleTask(msg);
        sendSigned(res, resp);
        return;
      }
      log({ ev: "unknown_type", type: msg.type || null });
      sendSigned(res, { ok: false, error: "unknown_type" });
    } catch (e) {
      log({ ev: "handler_error", err: String(e && e.message || e).slice(0, 200) });
      try { sendSigned(res, { ok: false, error: "internal" }, 500); } catch {}
    }
  });
});
server.listen(PORT, () => log({ ev: "listening", port: Number(PORT), secretSet: !!SECRET }));
