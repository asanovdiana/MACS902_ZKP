pragma circom 2.2.3;
// Harness fixture: an anonymous component admits only <==, so its M1 mutant (<--) is a circom
// compile error; the harness must report it as compile_error, not as a test kill.
include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template Anon() {
    signal input a;
    signal output o <== Poseidon(1)([a]);
}

component main = Anon();
