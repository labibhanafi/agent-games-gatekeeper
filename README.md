# Proof Gatekeeper Agent

An agent for the zkVerify Agent Games "Proof Gatekeeper" track.

Receives signed task envelopes at `POST /agent`, verifies the platform HMAC
over the raw body, decides APPROVE/REJECT with deterministic checks
(VK match, threshold, expiry, recipient, amount cap, proof-reuse seen-set),
and returns a Groth16 proof of the decision generated locally with snarkjs
against the official gatekeeper circuit. PROOF_REUSED answers carry no
proof, per the event rules. Responses are HMAC-signed; task IDs are
idempotency keys.

Run: `AGENT_GAMES_HMAC_SECRET=... node agent.mjs` (Node 22+).
Tests: `node test.mjs` — synthetic envelopes for every documented trap type.
