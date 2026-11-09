pragma circom 2.2.3;

// AttributeHash() — G1-S1-CIRC-031 (credential v4, ADR 0006; closes gaps G-1 and G-7).
//
//   attrHash = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry,
//                          credentialCommitment)
//
// Input order is normative (docs/CONTRACTS.md `credential v4`). In the v4 main attrHash is BOTH
// the EdDSA-signed message M and the Merkle leaf, so changing any attribute after issuance breaks
// the signature and the membership proof.
//
// Attribute well-formedness lives here:
//   role, dept, clearance  in 0..3   (Num2Bits(2), ADR 0008 enums)
//   deviceCompliant, employeeActive  boolean
// NOT here: expiry < 2^64 (Num2Bits(64)) belongs to the expiry component next to its comparator,
// and employeeActive === 1 belongs to the policy component (ADR 0007). The v4 main must wire both.
// credentialCommitment is a Poseidon(2) output and needs no range check. No `<--` anywhere.
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

template AttributeHash() {
    signal input role;
    signal input dept;
    signal input clearance;
    signal input deviceCompliant;
    signal input employeeActive;
    signal input expiry;
    signal input credentialCommitment;

    signal output attrHash;

    // A1-A3: 2-bit enums.
    component roleBits = Num2Bits(2);
    roleBits.in <== role;
    component deptBits = Num2Bits(2);
    deptBits.in <== dept;
    component clearanceBits = Num2Bits(2);
    clearanceBits.in <== clearance;

    // A4, A5: boolean flags.
    deviceCompliant * (deviceCompliant - 1) === 0;
    employeeActive * (employeeActive - 1) === 0;

    // A6: the hash, in contract order.
    component hasher = Poseidon(7);
    hasher.inputs[0] <== role;
    hasher.inputs[1] <== dept;
    hasher.inputs[2] <== clearance;
    hasher.inputs[3] <== deviceCompliant;
    hasher.inputs[4] <== employeeActive;
    hasher.inputs[5] <== expiry;
    hasher.inputs[6] <== credentialCommitment;

    attrHash <== hasher.out;
}
