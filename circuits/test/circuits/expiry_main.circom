pragma circom 2.2.3;

// Test main for ExpiryCheck (G1-S1-CIRC-034). `now` is public, as in the v4 main.
include "../../components/expiry.circom";

component main {public [now]} = ExpiryCheck();
