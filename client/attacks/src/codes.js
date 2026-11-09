"use strict";
// Proposed gateway denial codes for the Attack Lab (PROPOSAL for the P3 gateway: the contract
// names obligations, not codes). Wire shape: HTTP status + {"error":{"code":"<CODE>"}}.
// `obligation` is the access.public_signals v4 obligation (docs/CONTRACTS.md) that produces it.
// Texts are public and carry no attribute (floor 7).
const CODES = {
  MALFORMED_REQUEST: { status: 400, obligation: null, text: "Request is not {resource, nonce, proof, publicSignals} with 12 canonical decimal signals" },
  UNKNOWN_RESOURCE: { status: 404, obligation: null, text: "No such service" },
  NONCE_UNKNOWN: { status: 403, obligation: 6, text: "Nonce was not issued by this gateway" },
  NONCE_USED: { status: 403, obligation: 6, text: "Nonce already used (replayed proof)" },
  NONCE_EXPIRED: { status: 403, obligation: 6, text: "Nonce expired (older than the 120 s TTL)" },
  POLICY_MISMATCH: { status: 403, obligation: 4, text: "Proof is for another service or policy than the one requested" },
  CHALLENGE_MISMATCH: { status: 403, obligation: 5, text: "Proof's now, epoch or resource differ from the challenge stored with the nonce" },
  ISSUER_NOT_PINNED: { status: 403, obligation: 2, text: "Credential not signed by the pinned issuer key" },
  ROOT_NOT_CURRENT: { status: 403, obligation: 3, text: "Registry root is not current (credential revoked or proof stale)" },
  PROOF_INVALID: { status: 403, obligation: 1, text: "Groth16 verification failed" },
  RATE_LIMITED: { status: 429, obligation: 7, text: "Same nullifier already admitted in this epoch" },
};

module.exports = { CODES };
