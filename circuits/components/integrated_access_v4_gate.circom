pragma circom 2.2.3;

// IntegratedAccessGateV4(depth) — G1-S1-CIRC-036. The template lives here (not in the main file)
// because circom refuses to include a file that declares `component main`, and the depth-16 main
// plus the depth-8/20 benchmark mains all instantiate it. Contracts `credential v4`,
// `access.public_signals v4`; ADR 0006, ADR 0007, ADR 0008. Depth 16 is the product; the
// depth-8 and depth-20 mains (integrated_access_v4_d8/_d20.circom) exist only for benchmarks.
//
// Statement: the prover knows (credentialSecret, credentialSalt, attributes, signature, path) with
//   credentialCommitment = Poseidon(2)(credentialSecret, credentialSalt)
//   attrHash             = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive,
//                                      expiry, credentialCommitment)
//   EdDSA-Poseidon signature (R8, S) over M = attrHash under the PUBLIC issuer key (issuerAx, issuerAy)
//   issuer key and R8 on BabyJubJub
//   attrHash is a member of the tree with the PUBLIC root (leaf = attrHash)
//   the attributes satisfy the PUBLIC policy (roleMask, deptMask, minClearance, requireDevice) and
//   employeeActive = 1
//   now < expiry (64-bit ranged)
//   nullifier = Poseidon(3)(credentialSecret, resourceId, epoch); nonce bound by nonce^2
//
// No `M`, `leaf`, `Ax` or `Ay` input: the signed message and the leaf are the in-circuit attrHash
// (closes G-1), the issuer key is public (closes G-2, together with the gateway's pin).
//
// Public signals (snarkjs order = output first, then the public inputs in DECLARATION order, which
// is the order of the `signal input` lines below, not the order of the `public [...]` list):
//   0 nullifier, 1 root, 2 issuerAx, 3 issuerAy, 4 roleMask, 5 deptMask, 6 minClearance,
//   7 requireDevice, 8 now, 9 nonce, 10 resourceId, 11 epoch
// Asserted from the .sym file by circuits/test/v4.test.js.
//
// Range checks are owned by the components: AttributeHash (role/dept/clearance 2 bits, flags
// boolean), AccessPolicyV4 (role/dept/clearance and policy fields), ExpiryCheck (expiry, now 64
// bits). No range checks on nonce/resourceId/epoch (gateway obligations 4-7). This template only
// wires; it has no `<--` and no `===` of its own. Every `<==` below has a killing negative test in
// v4.test.js (floor 1; circuits/reports/mutation-v4.md).
include "./attribute_hash.circom";
include "./eddsa_verifier.circom";
include "./issuer_key.circom";
include "./merkle_membership_n.circom";
include "./access_policy_v4.circom";
include "./expiry.circom";
include "./challenge_binding.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

template IntegratedAccessGateV4(depth) {
    // ---- private inputs (credential v4) ----
    signal input credentialSecret;
    signal input credentialSalt;
    signal input role;
    signal input dept;
    signal input clearance;
    signal input deviceCompliant;
    signal input employeeActive;
    signal input expiry;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // ---- public inputs, in access.public_signals v4 order (declaration order is normative) ----
    signal input root;
    signal input issuerAx;
    signal input issuerAy;
    signal input roleMask;
    signal input deptMask;
    signal input minClearance;
    signal input requireDevice;
    signal input now;
    signal input nonce;
    signal input resourceId;
    signal input epoch;

    // ---- output (publicSignals[0]) ----
    signal output nullifier;

    // W1-W3: credentialCommitment = Poseidon(2)(credentialSecret, credentialSalt) (her v3 style).
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== credentialSecret;
    commitmentHasher.inputs[1] <== credentialSalt;

    signal credentialCommitment;
    credentialCommitment <== commitmentHasher.out;

    // W4-W10: attrHash over the attributes and the commitment (ranges checked inside).
    component attr = AttributeHash();
    attr.role <== role;
    attr.dept <== dept;
    attr.clearance <== clearance;
    attr.deviceCompliant <== deviceCompliant;
    attr.employeeActive <== employeeActive;
    attr.expiry <== expiry;
    attr.credentialCommitment <== credentialCommitment;

    // W11-W16: her IssuerSignatureCheck, key = the PUBLIC issuer key, M = attrHash.
    component signature = IssuerSignatureCheck();
    signature.Ax <== issuerAx;
    signature.Ay <== issuerAy;
    signature.R8x <== R8x;
    signature.R8y <== R8y;
    signature.S <== S;
    signature.M <== attr.attrHash;

    // W17-W20: issuer key and R8 on BabyJubJub (the same signals the verifier sees).
    component points = SignaturePointsOnCurve();
    points.Ax <== issuerAx;
    points.Ay <== issuerAy;
    points.R8x <== R8x;
    points.R8y <== R8y;

    // W21-W24: leaf = attrHash is a member of the tree with the public root.
    component merkle = MerkleMembershipN(depth);
    merkle.leaf <== attr.attrHash;
    merkle.root <== root;
    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }

    // W25-W33: the public policy over the private attributes (employeeActive === 1 inside).
    component policy = AccessPolicyV4();
    policy.role <== role;
    policy.dept <== dept;
    policy.clearance <== clearance;
    policy.deviceCompliant <== deviceCompliant;
    policy.employeeActive <== employeeActive;
    policy.roleMask <== roleMask;
    policy.deptMask <== deptMask;
    policy.minClearance <== minClearance;
    policy.requireDevice <== requireDevice;

    // W34-W35: now < expiry, both 64-bit.
    component expiryCheck = ExpiryCheck();
    expiryCheck.expiry <== expiry;
    expiryCheck.now <== now;

    // W36-W40: nonce bound, nullifier = Poseidon(3)(credentialSecret, resourceId, epoch).
    component binding = ChallengeBinding();
    binding.credentialSecret <== credentialSecret;
    binding.nonce <== nonce;
    binding.resourceId <== resourceId;
    binding.epoch <== epoch;
    nullifier <== binding.nullifier;
}

