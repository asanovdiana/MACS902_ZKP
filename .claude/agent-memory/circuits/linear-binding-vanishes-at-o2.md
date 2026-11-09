# Linear-only bindings vanish at --O2

A public input bound only by a LINEAR constraint (e.g. mutant `nonceSquared <== nonce` with an
intermediate `nonceSquared`) passes every --O0 witness tamper (the row exists at O0), but --O2
substitutes the linear row away and the public wire ends up in no R1CS row: Groth16 would then
accept any value. Kill it with a tamper on the --O2 witness public slots (`w[slot]+1` then
`checkConstraints` must throw), not only static "slot appears in a row" checks. Found by the
G1-S1-CIRC-035 sweep (`circuits/test/challenge_binding.test.js`). See [[witness-tamper-for-mutants]],
[[static-killers-mask-weak-negatives]], [[challenge-binding-costs]].
