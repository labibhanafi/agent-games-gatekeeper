// Synthetic end-to-end tests for the Gatekeeper agent (local server + proofs).
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8899;
const SECRET = "ab".repeat(32); // 64 hex chars, platform-style dummy
const URL_ = `http://127.0.0.1:${PORT}/agent`;
const vk = JSON.parse(readFileSync(path.join(DIR, "..", "circuits", "vk.json"), "utf8"));

rmSync(path.join(DIR, "state.json"), { force: true });
const srv = spawn("node", ["agent.mjs"], {
  cwd: DIR,
  env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
  stdio: ["ignore", "pipe", "pipe"],
});
srv.stderr.on("data", (d) => process.stderr.write("[srv-err] " + d));
await new Promise((res) => {
  srv.stdout.on("data", (d) => { if (String(d).includes("listening")) res(); });
  setTimeout(res, 5000);
});

const sign = (body) => createHmac("sha256", Buffer.from(SECRET, "utf8")).update(body).digest("hex");
async function post(obj, { badSig = false } = {}) {
  const body = JSON.stringify(obj);
  const r = await fetch(URL_, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": badSig ? "00".repeat(32) : sign(body) },
    body,
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, respSig: r.headers.get("x-agent-games-signature"), rawBody: text };
}
function respSigOk(rawBody, sig) {
  return sig === createHmac("sha256", Buffer.from(SECRET, "utf8")).update(rawBody).digest("hex");
}

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK2 = "0x13aa5511bb22cc33dd44ee55ff660011223344556677889900aabbccddeeff00";
const ADDR = "0xDe42aA91b0c1d2E3f40516273849aAbBcCdD9f01";
const ADDR2 = "0x1111111111111111111111111111111111111111";
let txc = 0;
const tx = () => "0x" + (txc++).toString(16).padStart(8, "0") + "a8".repeat(28);
function task(over = {}, id = null) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: id || `gk_test_${Math.random().toString(36).slice(2, 9)}`,
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000,
      recipient: ADDR, condition_recipient: ADDR,
      amount: "500", max_transfer: "1000", proof_tx: tx(),
      ...over,
    },
  };
}

let pass = 0, fail = 0;
function check(name, cond, extra = "") {
  if (cond) { pass++; console.log(`PASS  ${name}`); }
  else { fail++; console.log(`FAIL  ${name} ${extra}`); }
}
async function expectCase(name, t, wantDecision, wantReason, wantProof) {
  const t0 = Date.now();
  const r = await post(t);
  const ms = Date.now() - t0;
  check(`${name}: status 200`, r.status === 200, `got ${r.status}`);
  check(`${name}: decision`, r.json?.decision === wantDecision, `got ${r.json?.decision}`);
  check(`${name}: reason`, r.json?.reason_code === wantReason, `got ${r.json?.reason_code}`);
  check(`${name}: resp signature`, respSigOk(r.rawBody, r.respSig));
  if (wantProof) {
    check(`${name}: has proof`, !!r.json?.proof && Array.isArray(r.json?.public_signals));
    if (r.json?.proof) {
      const ok = await groth16.verify(vk, r.json.public_signals, r.json.proof);
      check(`${name}: proof verifies`, ok === true);
      check(`${name}: 13 public signals`, r.json.public_signals.length === 13, `got ${r.json.public_signals.length}`);
      check(`${name}: decision signal`, r.json.public_signals[11] === (wantDecision === "APPROVE" ? "1" : "0"), `got ${r.json.public_signals[11]}`);
    }
  } else {
    check(`${name}: no proof (exempt)`, !r.json?.proof);
  }
  console.log(`      (${ms} ms)`);
  return r;
}

// preflight
{
  const r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  check("preflight: ok shape", r.json?.ok === true && r.json?.protocolVersion === "v1", JSON.stringify(r.json));
  check("preflight: resp signature", respSigOk(r.rawBody, r.respSig));
}
// bad signature
{
  const r = await post(task(), { badSig: true });
  check("bad signature -> 401", r.status === 401, `got ${r.status}`);
}

await expectCase("VALID", task(), "APPROVE", "VALID_CONDITION", true);
await expectCase("VK_SUBSTITUTION", task({ proof_vk: VK2 }), "REJECT", "VK_SUBSTITUTION", true);
await expectCase("THRESHOLD_MISMATCH", task({ public_balance: "999" }), "REJECT", "THRESHOLD_MISMATCH", true);
await expectCase("EXPIRED (equal blocks)", task({ current_block: 8430000 }), "REJECT", "EXPIRED_CONDITION", true);
await expectCase("EXPIRED (past)", task({ current_block: 8430001 }), "REJECT", "EXPIRED_CONDITION", true);
await expectCase("RECIPIENT_MISMATCH", task({ recipient: ADDR2 }), "REJECT", "RECIPIENT_MISMATCH", true);
await expectCase("AMOUNT_OVERFLOW", task({ amount: "1001" }), "REJECT", "AMOUNT_OVERFLOW", true);

// reuse: same proof_tx, new task_id
const sharedTx = tx();
const first = await expectCase("REUSE setup (valid)", task({ proof_tx: sharedTx }), "APPROVE", "VALID_CONDITION", true);
await expectCase("PROOF_REUSED", task({ proof_tx: sharedTx }), "REJECT", "PROOF_REUSED", false);
// idempotent retry of the first task: identical response
{
  const again = await post(JSON.parse(JSON.stringify(first.reqBody || {})));
}
// retry properly: rebuild the exact first task object is not retained; instead send a fresh task twice
{
  const t = task();
  const r1 = await post(t);
  const r2 = await post(t);
  check("retry: identical body", r1.rawBody === r2.rawBody);
  check("retry: still has proof", !!r2.json?.proof);
}

console.log(`\n== ${pass} passed, ${fail} failed ==`);
srv.kill();
process.exit(fail ? 1 : 0);
