pragma circom 2.2.3;

// Generic v4 access policy (G1-S1-CIRC-033; contracts `credential v4`, `access.public_signals v4`;
// ADR 0007, ADR 0008). Replaces the hard-coded v3 `FileShareAccess` (components/access_policy.circom,
// kept unchanged for the v3 profile).
//
// Statement: role is allowed by roleMask, dept by deptMask, clearance >= minClearance, the device
// is compliant if the policy requires it, and the employee is active (always required, ADR 0007).
//
// Self-contained: every input this template relies on is range-checked here, including the
// private role/dept/clearance (2 bits each). The v4 attribute component may range-check them
// too; whether to keep both is the main-wiring task's call (G1-S1-CIRC-036). role/dept bits are
// needed here anyway as mux selectors.
//
// deviceCompliant is not range-checked here: with requireDevice boolean, P11 forces
// deviceCompliant == 1 when requireDevice == 1 and says nothing otherwise, so its booleanness is
// not needed for this statement (the attribute component enforces it for the attribute hash).
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/mux2.circom";

template AccessPolicyV4() {
    // private attributes
    signal input role;            // 0..3 (ADR 0008)
    signal input dept;            // 0..3 (ADR 0008)
    signal input clearance;       // 0..3
    signal input deviceCompliant; // 0 | 1
    signal input employeeActive;  // must be 1

    // policy (public signals 4..7 in the v4 main)
    signal input roleMask;        // 0..15, bit i allows role i
    signal input deptMask;        // 0..15, bit i allows dept i
    signal input minClearance;    // 0..3
    signal input requireDevice;   // 0 | 1

    // P1: role in 0..3; its bits select the mask bit.
    component roleBits = Num2Bits(2);
    roleBits.in <== role;
    // P2: roleMask in 0..15; its bits are the mux inputs.
    component roleMaskBits = Num2Bits(4);
    roleMaskBits.in <== roleMask;
    // P3: bit `role` of roleMask is 1.
    component roleSel = Mux2();
    for (var k = 0; k < 4; k++) {
        roleSel.c[k] <== roleMaskBits.out[k];
    }
    roleSel.s[0] <== roleBits.out[0];
    roleSel.s[1] <== roleBits.out[1];
    roleSel.out === 1;

    // P4-P6: the same for dept.
    component deptBits = Num2Bits(2);
    deptBits.in <== dept;
    component deptMaskBits = Num2Bits(4);
    deptMaskBits.in <== deptMask;
    component deptSel = Mux2();
    for (var k = 0; k < 4; k++) {
        deptSel.c[k] <== deptMaskBits.out[k];
    }
    deptSel.s[0] <== deptBits.out[0];
    deptSel.s[1] <== deptBits.out[1];
    deptSel.out === 1;

    // P7, P8: comparator inputs range-checked to the comparator width.
    component clearanceBits = Num2Bits(2);
    clearanceBits.in <== clearance;
    component minClearanceBits = Num2Bits(2);
    minClearanceBits.in <== minClearance;
    // P9: clearance >= minClearance.
    component clearanceOk = GreaterEqThan(2);
    clearanceOk.in[0] <== clearance;
    clearanceOk.in[1] <== minClearance;
    clearanceOk.out === 1;

    // P10: requireDevice is boolean.
    requireDevice * (requireDevice - 1) === 0;
    // P11: a required device must be compliant.
    requireDevice * (1 - deviceCompliant) === 0;

    // P12: active employees only, under every policy (ADR 0007, D5).
    employeeActive === 1;
}
