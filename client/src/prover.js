"use strict";
// Prover (M4). Profile-driven. The circuit input holds every private value (secret, salt,
// attributes, signature, Merkle path) and exists only in memory: snarkjs fullProve is called
// in-process, no input or witness file is written, and only {proof, publicSignals} is returned
// (floor 6). Every proof is verified locally with circuits/scripts/verify.js before it is returned.
//
// v3: committed artefacts circuits/setup/integrated_access_v3.* (DEV keys, see ARTIFACTS.md).
// v4: same layout, integrated_access_v4.* (committed by G1-S1-CIRC-037). The local policy check runs
// first (no artefacts, no network); then the proof's public signals are compared with
// expectedPublicSignals and the proof is verified with verify.js before it is returned.
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const zk = require("../../circuits/lib");
const verifier = require("../../circuits/scripts/verify.js");
const { ClientError, fromLib } = require("./errors");
const { parseChallenge } = require("./challenge");

const ARTEFACT_DIR = path.resolve(__dirname, "..", "..", "circuits", "setup");

function artefactPaths(profileName, dir) {
  const name = zk.profiles[profileName].artefacts.name;
  return {
    name,
    wasm: path.join(dir, `${name}.wasm`),
    zkey: path.join(dir, `${name}.zkey`),
    vkey: path.join(dir, `${name}.verification_key.json`),
  };
}

function requireArtefacts(profileName, dir) {
  const a = artefactPaths(profileName, dir);
  const missing = [a.wasm, a.zkey, a.vkey].filter((f) => !fs.existsSync(f)).map((f) => path.basename(f));
  if (missing.length) {
    throw new ClientError("ARTEFACTS_MISSING", `proving artefacts for ${a.name} not found (${missing.join(", ")}); set ZKGATE_ARTEFACTS or build them with circuits/scripts/setup.sh`);
  }
  return a;
}

const requireIssued = (credential) => {
  if (!credential || credential.status !== "issued") {
    throw new ClientError("NOT_ISSUED", "the credential has not been issued yet; run `zkgate request` first");
  }
};

const libArgs = (credential, merkleProof) => ({
  credentialSecret: credential.secrets.credentialSecret,
  credentialSalt: credential.secrets.credentialSalt,
  commitment: credential.commitment,
  attributes: credential.attributes,
  signature: credential.signature,
  issuer: credential.issuer,
  merkleProof,
});

/** v3: refuse locally when FileShareAccess would reject, then fetch the path and build the input. */
async function prepareV3({ credential, issuer }) {
  requireIssued(credential);
  try {
    const v = zk.checkFileShareV3(credential.attributes);
    if (!v.ok) throw new ClientError("POLICY_NOT_SATISFIED", "policy not satisfied: " + v.reasons.map((r) => r.code).join(", "), { reasons: v.reasons });
    const mp = await issuer.getPath(credential.leafIndex);
    return { input: await zk.buildInputV3(libArgs(credential, mp)) };
  } catch (e) {
    throw fromLib(e);
  }
}

/** The lib's refusal precedence (credential v4): expired, inactive, then the policy reasons. */
function refuseUnlessSatisfied(attributes, policy, now) {
  const v = zk.checkPolicyLocally(attributes, policy, now);
  if (v.ok) return;
  const codes = v.reasons.map((r) => r.code);
  const code = codes.includes("CREDENTIAL_EXPIRED") ? "CREDENTIAL_EXPIRED"
    : codes.includes("EMPLOYEE_INACTIVE") ? "EMPLOYEE_INACTIVE" : "POLICY_NOT_SATISFIED";
  throw new ClientError(code, "policy not satisfied: " + codes.join(", "), { reasons: v.reasons });
}

/** v4: local policy check against the gateway's challenge, then path and input. */
async function prepareV4({ credential, issuer, challenge }) {
  requireIssued(credential);
  if (!challenge) throw new ClientError("CHALLENGE_REQUIRED", "a v4 proof needs a gateway challenge {nonce, resourceId, epoch, now, policy}");
  try {
    const ch = parseChallenge(challenge);
    const policy = { ...ch.policy, resourceId: ch.resourceId };
    refuseUnlessSatisfied(credential.attributes, policy, ch.now);
    const mp = await issuer.getPath(credential.leafIndex);
    const input = await zk.buildInputV4({
      ...libArgs(credential, mp), policy,
      challenge: { nonce: ch.nonce, resourceId: ch.resourceId, epoch: ch.epoch, now: ch.now },
    });
    return { input, expectedSignals: await zk.expectedPublicSignals("v4", input), challenge: ch };
  } catch (e) {
    throw fromLib(e);
  }
}

/**
 * Produce a verified Groth16 proof. Returns {profile, proof, publicSignals}.
 *   credential   Wallet.load() result (status "issued")
 *   issuer       IssuerClient
 *   challenge    required for v4 (gateway challenge)
 *   artefactDir  default ZKGATE_ARTEFACTS or circuits/setup
 */
async function prove({ credential, issuer, challenge, artefactDir }) {
  requireIssued(credential);
  const profile = credential.profile;
  const dir = artefactDir || process.env.ZKGATE_ARTEFACTS || ARTEFACT_DIR;
  let prep;
  if (profile === "v4") {
    // local policy refusal comes first: it needs no artefacts and no network
    if (!challenge) throw new ClientError("CHALLENGE_REQUIRED", "a v4 proof needs a gateway challenge {nonce, resourceId, epoch, now, policy}");
    try {
      const ch = parseChallenge(challenge);
      refuseUnlessSatisfied(credential.attributes, { ...ch.policy, resourceId: ch.resourceId }, ch.now);
    } catch (e) {
      throw fromLib(e);
    }
  } else {
    try {
      const v = zk.checkFileShareV3(credential.attributes);
      if (!v.ok) throw new ClientError("POLICY_NOT_SATISFIED", "policy not satisfied: " + v.reasons.map((r) => r.code).join(", "), { reasons: v.reasons });
    } catch (e) {
      throw fromLib(e);
    }
  }
  const art = requireArtefacts(profile, dir);
  prep = profile === "v4" ? await prepareV4({ credential, issuer, challenge }) : await prepareV3({ credential, issuer });

  let result;
  try {
    result = await snarkjs.groth16.fullProve(prep.input, art.wasm, art.zkey);
  } catch (_) {
    // snarkjs messages can name signals; keep them out of the user-facing error
    throw new ClientError("PROVE_FAILED", "the prover rejected the witness (the credential does not satisfy the circuit)");
  }
  const expected = prep.expectedSignals || (await zk.expectedPublicSignals(profile, prep.input));
  if (JSON.stringify(result.publicSignals) !== JSON.stringify(expected)) {
    throw new ClientError("PROOF_INVALID", "the proof's public signals differ from the expected ones");
  }
  const ok = await verifier.verify(verifier.loadVerificationKey(art.vkey), result.publicSignals, result.proof);
  if (!ok) throw new ClientError("PROOF_INVALID", "the generated proof failed local verification");
  return { profile, proof: result.proof, publicSignals: result.publicSignals };
}

/** Release snarkjs worker threads (CLI exit, test teardown). Not for per-request use. */
async function shutdown() {
  await verifier.terminate();
}

module.exports = { prove, prepareV3, prepareV4, shutdown, ARTEFACT_DIR, artefactPaths };
