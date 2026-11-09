pragma circom 2.2.3;

// TEST-ONLY main for circuits/components/challenge_binding.circom (G1-S1-CIRC-035).
// Public inputs nonce, resourceId, epoch in the v4 declaration order (contract
// `access.public_signals v4`: ..., nonce, resourceId, epoch) and nullifier as the only output, so
// publicSignals = [nullifier, nonce, resourceId, epoch] mirrors slots 0, 9, 10, 11 of v4.

include "../../components/challenge_binding.circom";

component main {public [nonce, resourceId, epoch]} = ChallengeBinding();
