pragma circom 2.2.3;

// v4 access circuit at depth 8: BENCHMARK ONLY (M8 depth sweep); not keyed, not served.
// Template and statement: components/integrated_access_v4_gate.circom (G1-S1-CIRC-036).
// Public signals: nullifier, then root, issuerAx, issuerAy, roleMask, deptMask, minClearance,
// requireDevice, now, nonce, resourceId, epoch (access.public_signals v4; declaration order).
include "./components/integrated_access_v4_gate.circom";

component main {public [root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch]} = IntegratedAccessGateV4(8);
