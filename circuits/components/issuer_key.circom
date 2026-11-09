pragma circom 2.2.3;

// SignaturePointsOnCurve() — G1-S1-CIRC-032 (credential v4; closes gap G-2 together with the v4
// main declaring the issuer key PUBLIC).
//
// circomlib's EdDSAPoseidonVerifier (wrapped by her IssuerSignatureCheck) does not check that the
// issuer key A = (Ax, Ay) or the signature point R8 = (R8x, R8y) lie on BabyJubJub. This
// component adds both checks with circomlib BabyCheck (a*x^2 + y^2 = 1 + d*x^2*y^2).
//
// What closes G-2 is NOT this component alone: it is that the v4 main takes the key as the public
// inputs issuerAx/issuerAy (access.public_signals v4 slots 2, 3) and wires the SAME signals into
// IssuerSignatureCheck and here. A self-signed credential then verifies only with the forger's
// key in the public signals, which the gateway rejects by pinning the issuer key (gateway
// obligation 2). The on-curve checks are defence in depth (no off-curve key or R8 can be fed to
// the verifier's addition formulas). Not checked here: subgroup membership (the pinned key is
// honest; circomlib's verifier rejects a small-order A via its 8*A != 0 check). No `<--`.
include "../../node_modules/circomlib/circuits/babyjub.circom";

template SignaturePointsOnCurve() {
    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;

    // K1: issuer key on BabyJubJub.
    component keyOnCurve = BabyCheck();
    keyOnCurve.x <== Ax;
    keyOnCurve.y <== Ay;

    // K2: R8 on BabyJubJub.
    component r8OnCurve = BabyCheck();
    r8OnCurve.x <== R8x;
    r8OnCurve.y <== R8y;
}
