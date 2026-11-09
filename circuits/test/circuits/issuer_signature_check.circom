pragma circom 2.2.3;

// Test main (G1-S1-CIRC-036): her IssuerSignatureCheck standalone, used by v4.test.js to splice an
// honest `main.signature.*` sub-witness into a v4 witness (harness `main.X` = v4 `main.signature.X`).
include "../../components/eddsa_verifier.circom";

component main = IssuerSignatureCheck();
