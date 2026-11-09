pragma circom 2.2.3;

// ChallengeBinding (G1-S1-CIRC-035; contract `access.public_signals v4`, ADR 0005, ADR 0007).
//
// Binds a v4 proof to the gateway's challenge and derives the per-(resource, epoch) nullifier:
//
//   nullifier    = Poseidon(3)(credentialSecret, resourceId, epoch)
//   nonceSquared = nonce * nonce            (dummy quadratic constraint)
//
// Inputs (the v4 main wires its own signals of the same names to these):
//   credentialSecret  private; the salt is deliberately NOT an input (ADR 0005)
//   nonce             public in the v4 main (publicSignals[9])
//   resourceId        public in the v4 main (publicSignals[10])
//   epoch             public in the v4 main (publicSignals[11])
// Output:
//   nullifier         the v4 main's only output (publicSignals[0])
//
// Why every input is constrained (contract "Circuit obligation"):
//   - nonce enters no computation, so without a constraint its wire would appear in no circuit
//     R1CS row. That alone does NOT make a proof verify for any nonce under snarkjs: `zkey new`
//     (snarkjs 0.7.6, src/zkey_new.js) appends one input-binding row per public signal, so every
//     public input gets a non-identity IC point and the proof is bound to the value it was proved
//     with (checked G1-S1-CIRC-039 / SR-11: a public input in no circuit row, --O2, pot15 setup;
//     verify OK for the proved value, "Invalid proof" for value + 1). `nonceSquared <== nonce *
//     nonce` is kept as defence in depth: it binds nonce in the circuit's own R1CS, independent
//     of the backend adding those rows, at one constraint.
//   - resourceId and epoch are constrained through the Poseidon(3) wiring below, so changing
//     either changes the nullifier, which is itself public; no dummy constraint is needed.
//
// Range checks: none, by design. The contract lists the in-circuit range checks for v4
// (`credential v4`: role, dept, clearance, expiry, now) and states none for nonce, resourceId or
// epoch; all three are plain field elements to the circuit and enter no comparator, so no
// out-of-range value can satisfy anything it should not. Their ranges (resourceId in {1,2,3},
// epoch = floor(now / 600), nonce issued and unused) are gateway obligations 4-7: the gateway
// compares each one with the challenge it stored for the nonce. In particular the circuit does
// NOT prove epoch = floor(now / 600); the gateway does.
//
// Constraints (all killed by circuits/test/challenge_binding.test.js):
//   CB1  nonceSquared <== nonce * nonce
//   CB2  hasher.inputs[0] <== credentialSecret
//   CB3  hasher.inputs[1] <== resourceId
//   CB4  hasher.inputs[2] <== epoch
//   CB5  nullifier <== hasher.out
// plus circomlib Poseidon(3) internals.

include "../../node_modules/circomlib/circuits/poseidon.circom";

template ChallengeBinding() {
    signal input credentialSecret;
    signal input nonce;
    signal input resourceId;
    signal input epoch;
    signal output nullifier;

    // CB1: bind nonce (otherwise unconstrained) into the R1CS.
    signal nonceSquared;
    nonceSquared <== nonce * nonce;

    // CB2-CB5: nullifier = Poseidon(3)(credentialSecret, resourceId, epoch).
    component hasher = Poseidon(3);
    hasher.inputs[0] <== credentialSecret;
    hasher.inputs[1] <== resourceId;
    hasher.inputs[2] <== epoch;
    nullifier <== hasher.out;
}
