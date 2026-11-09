pragma circom 2.2.3;

// Credential expiry (G1-S1-CIRC-034; contract `credential v4`): expiry > now, strictly
// (expiry == now is expired). `now` is public signal 8 of the v4 main; the gateway binds it to the
// challenge it issued (contract `access.public_signals v4`, obligation 5).
//
// Both comparator inputs are range-checked to the comparator width first: LessThan(64) alone
// accepts e.g. expiry = now + 2^64 or now = p - 1.
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

template ExpiryCheck() {
    signal input expiry; // private: unix seconds, < 2^64
    signal input now;    // public:  unix seconds, < 2^64

    // E1, E2: 64-bit range checks.
    component expiryBits = Num2Bits(64);
    expiryBits.in <== expiry;
    component nowBits = Num2Bits(64);
    nowBits.in <== now;

    // E3: now < expiry.
    component notExpired = LessThan(64);
    notExpired.in[0] <== now;
    notExpired.in[1] <== expiry;
    notExpired.out === 1;
}
