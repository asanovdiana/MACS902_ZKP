pragma circom 2.2.3;

// v4 access circuit, depth 16 (65,536 leaves): THE product main (credential v4, access.public_signals v4).
// Template and statement: components/integrated_access_v4_gate.circom (G1-S1-CIRC-036).
// Public signals: nullifier, then root, issuerAx, issuerAy, roleMask, deptMask, minClearance,
// requireDevice, now, nonce, resourceId, epoch (access.public_signals v4; declaration order).
include "./components/integrated_access_v4_gate.circom";

component main {public [root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch]} = IntegratedAccessGateV4(16);
