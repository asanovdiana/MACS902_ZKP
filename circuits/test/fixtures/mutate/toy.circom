pragma circom 2.2.3;
// Harness fixture (G1-S1-CIRC-036): "I know a secret whose Poseidon(1) hash is the public h".
// Two mutation sites: S1 `hasher.inputs[0] <== secret` (line 11), S2 `h === hasher.out` (line 12).
include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template KnowSecret() {
    signal input secret;   // private
    signal input h;        // public

    component hasher = Poseidon(1);
    hasher.inputs[0] <== secret;
    h === hasher.out;      // C-TOY-1
}

component main {public [h]} = KnowSecret();
