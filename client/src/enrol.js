"use strict";
// Enrolment (issuer.api v2): send {commitment, enrolmentCode} to the issuer, then verify what comes
// back before it is stored (credential.file v1): issuer key == expected key, the admin-assigned
// attributes well-formed, signature valid under that key over the profile's message and those
// attributes, and the issuer's path starts at our own leaf. The client chooses no attribute.
//
// Expected issuer key, in order: explicit `expectedIssuer` (config / --issuer-key) > the pin stored
// for this issuer URL > trust on first use (the key from GET /issuer, then pinned). TOFU protects
// against a credential signed by a different key than the one the issuer advertises, not against an
// issuer that is malicious from the first contact: deployments should pass `expectedIssuer`.
const zk = require("../../circuits/lib");
const { ClientError, fromLib } = require("./errors");
const { nowSeconds } = require("./wallet");

/**
 * The attributes come from the issuer (the admin assigned them): require exactly the profile's
 * attribute set, each a non-negative safe integer. Whether they are what the user expected is for
 * the user to read in `zkgate status`; the signature check below proves they are what was signed.
 */
function checkIssuedAttributes(profile, attrs) {
  const names = zk.profiles[profile].attributes;
  const ok = attrs && typeof attrs === "object" && !Array.isArray(attrs)
    && Object.keys(attrs).length === names.length
    && names.every((k) => Number.isSafeInteger(attrs[k]) && attrs[k] >= 0);
  if (!ok) throw new ClientError("ISSUER_BAD_RESPONSE", `the issuer returned attributes that do not match profile ${profile}; not stored`);
  const out = {};
  for (const k of names) out[k] = attrs[k];
  return out;
}

const sameKey = (a, b) => a && b && String(a.Ax) === String(b.Ax) && String(a.Ay) === String(b.Ay);

async function requestCredential({ wallet, name, issuer, enrolmentCode, expectedIssuer }) {
  const cred = wallet.load(name);
  if (cred.status !== "pending") throw new ClientError("ALREADY_ISSUED", `credential "${name}" has already been issued`);
  const info = await issuer.getIssuer();
  if (info.profile !== cred.profile) {
    throw new ClientError("PROFILE_MISMATCH", `credential "${name}" is profile ${cred.profile} but the issuer serves ${info.profile}; run keygen with --profile ${info.profile} under a new name`);
  }
  const expected = expectedIssuer || wallet.getPin(issuer.baseUrl) || info.issuer;
  if (!sameKey(expected, info.issuer)) {
    throw new ClientError("ISSUER_KEY_MISMATCH", "the issuer's advertised key differs from the expected (pinned) issuer key; nothing was sent");
  }

  const { credential: got } = await issuer.requestCredential({ commitment: cred.commitment, enrolmentCode });

  const profile = zk.profiles[cred.profile];
  if (got.profile !== cred.profile) throw new ClientError("PROFILE_MISMATCH", "issuer returned a credential for a different profile");
  if (!sameKey(got.issuer, expected)) {
    throw new ClientError("ISSUER_KEY_MISMATCH", "the credential names an issuer key other than the expected one; not stored");
  }
  const assigned = checkIssuedAttributes(cred.profile, got.attributes);
  if (!Number.isSafeInteger(got.leafIndex) || got.leafIndex < 0) {
    throw new ClientError("ISSUER_BAD_RESPONSE", "issuer returned an invalid leaf index");
  }

  const body = { commitment: cred.commitment, attributes: assigned };
  let leaf;
  try {
    const M = await profile.message(body);
    leaf = await profile.leaf(body);
    if (!(await zk.verifySignature(M, got.signature, got.issuer))) {
      throw new ClientError("BAD_SIGNATURE", "the issuer's signature does not verify under the issuer key; not stored");
    }
  } catch (e) {
    if (e instanceof ClientError) throw e;
    throw new ClientError("BAD_SIGNATURE", "the credential's signature or issuer key is malformed; not stored");
  }

  const path = await issuer.getPath(got.leafIndex);
  try {
    if (path.leaf !== leaf) throw new ClientError("LEAF_MISMATCH", "the registry's leaf at that index is not this credential's leaf; not stored");
    const root = await zk.merkleRoot(leaf, path.pathElements, path.pathIndices);
    if (root !== path.root) throw new ClientError("ROOT_MISMATCH", "the registry's path does not reach its root; not stored");
  } catch (e) {
    throw fromLib(e);
  }

  wallet.save(name, {
    ...cred,
    issuerUrl: issuer.baseUrl,
    status: "issued",
    attributes: assigned,
    issuer: { Ax: String(got.issuer.Ax), Ay: String(got.issuer.Ay) },
    signature: { R8x: String(got.signature.R8x), R8y: String(got.signature.R8y), S: String(got.signature.S) },
    leafIndex: got.leafIndex,
    issuedAt: nowSeconds(),
  });
  try {
    if (!wallet.getPin(issuer.baseUrl)) wallet.setPin(issuer.baseUrl, info.issuer);
  } catch (e) {
    // A corrupt pin file already failed closed before anything was sent unless the caller passed an
    // explicit expected key (the documented way around it); then the credential is verified and
    // stored, and only the convenience pin is skipped.
    if (!(expectedIssuer && e instanceof ClientError && e.code === "PINS_CORRUPT")) throw e;
  }
  return wallet.summary(name);
}

module.exports = { requestCredential, checkIssuedAttributes };
