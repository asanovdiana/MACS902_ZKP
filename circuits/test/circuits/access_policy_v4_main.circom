pragma circom 2.2.3;

// Test main for AccessPolicyV4 (G1-S1-CIRC-033). The policy fields are public, as in the v4 main.
include "../../components/access_policy_v4.circom";

component main {public [roleMask, deptMask, minClearance, requireDevice]} = AccessPolicyV4();
