"use strict";
// Poseidon and EdDSA-Poseidon from circomlibjs 0.1.7, the one off-circuit implementation shared by
// circuit tests, issuer and client (Common rules; floor 8). The lib never stores a key: `sign` and
// `publicKey` take the issuer's private key as an argument from `issuer/` and keep nothing.
const { buildPoseidon, buildEddsa } = require("circomlibjs");
const { fail, parseField, below, L } = require("./field");

let poseidonP;
let eddsaP;
const getPoseidon = () => (poseidonP ||= buildPoseidon());
const getEddsa = () => (eddsaP ||= buildEddsa());

/** Poseidon(n)(inputs), 1 <= n <= 16, as F.toObject(poseidon([...])). Returns a decimal string. */
async function poseidon(inputs) {
  if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > 16) {
    fail("BAD_LENGTH", `poseidon: expected 1..16 inputs`);
  }
  const xs = inputs.map((x, i) => parseField(`poseidon input[${i}]`, x));
  const h = await getPoseidon();
  return h.F.toObject(h(xs)).toString();
}

/** credentialCommitment = Poseidon(2)(credentialSecret, credentialSalt) (ADR 0005). */
const commitment = (credentialSecret, credentialSalt) =>
  poseidon([parseField("credentialSecret", credentialSecret), parseField("credentialSalt", credentialSalt)]);

/** v4 nullifier = Poseidon(3)(credentialSecret, resourceId, epoch) (access.public_signals v4 #0). */
const nullifier = (credentialSecret, resourceId, epoch) =>
  poseidon([parseField("credentialSecret", credentialSecret), parseField("resourceId", resourceId), parseField("epoch", epoch)]);

function privKeyBytes(privKey) {
  if (!(privKey instanceof Uint8Array) || privKey.length !== 32) {
    fail("INVALID_KEY", "issuer private key: expected 32 raw bytes (Buffer/Uint8Array)");
  }
  return Buffer.from(privKey);
}

/** Issuer public key {Ax, Ay} for a 32-byte private key (eddsa.prv2pub). */
async function publicKey(privKey) {
  const e = await getEddsa();
  const A = e.prv2pub(privKeyBytes(privKey));
  return { Ax: e.F.toObject(A[0]).toString(), Ay: e.F.toObject(A[1]).toString() };
}

/** EdDSA-Poseidon signature {R8x, R8y, S} over field element `msg` (eddsa.signPoseidon). */
async function sign(privKey, msg) {
  const prv = privKeyBytes(privKey);
  const m = parseField("message", msg);
  const e = await getEddsa();
  const s = e.signPoseidon(prv, e.F.e(m));
  return { R8x: e.F.toObject(s.R8[0]).toString(), R8y: e.F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/**
 * true iff `sig` = {R8x, R8y, S} verifies over `msg` under `issuer` = {Ax, Ay}. Throws
 * AccessInputError on malformed values (S >= l is OUT_OF_RANGE); false on a well-formed
 * signature that does not verify (including points off the curve).
 */
async function verifySignature(msg, sig, issuer) {
  if (!sig || typeof sig !== "object") fail("MISSING_FIELD", "signature: missing");
  if (!issuer || typeof issuer !== "object") fail("MISSING_FIELD", "issuer: missing");
  const m = parseField("message", msg);
  const R8x = parseField("signature.R8x", sig.R8x);
  const R8y = parseField("signature.R8y", sig.R8y);
  const S = below("signature.S", sig.S, L, "l (BabyJubJub subgroup order)");
  const Ax = parseField("issuer.Ax", issuer.Ax);
  const Ay = parseField("issuer.Ay", issuer.Ay);
  const e = await getEddsa();
  const F = e.F;
  try {
    return e.verifyPoseidon(F.e(m), { R8: [F.e(R8x), F.e(R8y)], S }, [F.e(Ax), F.e(Ay)]) === true;
  } catch (_) {
    return false;
  }
}

module.exports = { poseidon, commitment, nullifier, publicKey, sign, verifySignature, getPoseidon, getEddsa };
