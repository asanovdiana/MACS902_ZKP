pragma circom 2.2.3;

// TEST MAIN (G1-S1-CIRC-030): MerkleMembershipN at depth 4, root public as in v3.
include "../../components/merkle_membership_n.circom";

component main {public [root]} = MerkleMembershipN(4);
