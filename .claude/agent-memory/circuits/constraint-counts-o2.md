# Tests compile at --O2; counts asserted against it

`test/helpers.js` `compile()` passes `O: 2` to circom_tester (its default is circom's --O1).
Toy KnowSecret: 213 at --O2, but 216 non-linear + 199 linear = 415 at --O1 — the first red run hit
this. Measured at --O2 (circom 2.2.2, circomlib 2.0.5): Poseidon(1) 213, (2) 240, (3) 261,
(6) 354; EdDSAPoseidonVerifier 4207. AccessGate measured (G1-S1-CIRC-001): depth 8 / 16 / 20 = 7199 / 9135 / 10103, all
non-linear; 242 per Merkle level on a fixed 5263. Asserted in `test/access.test.js`.
--O2 can eliminate signals, so witness-tamper tests may need a lower level: [[witness-tamper-for-mutants]].
