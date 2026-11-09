pragma circom 2.2.3;

// TEST MAIN (G1-S1-CIRC-031 + 032): the v4 credential-signature slice in isolation.
//
//   attrHash = AttributeHash(role, dept, clearance, deviceCompliant, employeeActive, expiry,
//                            credentialCommitment)                     (credential v4, ADR 0006)
//   IssuerSignatureCheck(Ax = issuerAx, Ay = issuerAy, R8, S, M = attrHash)   (her component)
//   SignaturePointsOnCurve(issuerAx, issuerAy, R8x, R8y)
//
// issuerAx/issuerAy are PUBLIC (access.public_signals v4 slots 2, 3) so a verifier can pin them.
// publicSignals = [attrHash, issuerAx, issuerAy]: attrHash is exposed only so tests can read it;
// the v4 main does NOT output it (it feeds the Merkle leaf instead).
include "../../components/attribute_hash.circom";
include "../../components/eddsa_verifier.circom";
include "../../components/issuer_key.circom";

template SignedAttributes() {
    signal input issuerAx;
    signal input issuerAy;

    signal input role;
    signal input dept;
    signal input clearance;
    signal input deviceCompliant;
    signal input employeeActive;
    signal input expiry;
    signal input credentialCommitment;
    signal input R8x;
    signal input R8y;
    signal input S;

    signal output attrHash;

    component attrs = AttributeHash();
    attrs.role <== role;
    attrs.dept <== dept;
    attrs.clearance <== clearance;
    attrs.deviceCompliant <== deviceCompliant;
    attrs.employeeActive <== employeeActive;
    attrs.expiry <== expiry;
    attrs.credentialCommitment <== credentialCommitment;
    attrHash <== attrs.attrHash;

    component points = SignaturePointsOnCurve();
    points.Ax <== issuerAx;
    points.Ay <== issuerAy;
    points.R8x <== R8x;
    points.R8y <== R8y;

    component signature = IssuerSignatureCheck();
    signature.Ax <== issuerAx;
    signature.Ay <== issuerAy;
    signature.R8x <== R8x;
    signature.R8y <== R8y;
    signature.S <== S;
    signature.M <== attrs.attrHash;
}

component main {public [issuerAx, issuerAy]} = SignedAttributes();
