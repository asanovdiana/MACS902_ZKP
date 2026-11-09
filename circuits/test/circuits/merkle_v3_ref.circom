pragma circom 2.2.3;

// TEST MAIN (G1-S1-CIRC-030): her depth-2 MerkleMembership() unchanged, the reference that
// MerkleMembershipN(2) must reproduce constraint for constraint.
include "../../components/merkle_membership.circom";

component main {public [root]} = MerkleMembership();
