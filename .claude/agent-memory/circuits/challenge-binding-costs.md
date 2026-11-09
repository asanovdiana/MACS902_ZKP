# ChallengeBinding costs and range decision

`circuits/components/challenge_binding.circom` (G1-S1-CIRC-035): --O2 262 non-linear + 0 linear
(Poseidon(3) 261 + nonceSquared 1); --O0 265 + 671. No in-circuit range checks on nonce,
resourceId, epoch: the contract lists none (only role/dept/clearance/expiry/now), they enter no
comparator, and their ranges plus `epoch = floor(now/600)` are gateway obligations 4-7. helpers.js
does not export compileCached, so the test compiles its own main via circom_tester into
`build/test/challenge-binding-O{0,2}` (recompile each run, ~1 s). See [[component-costs-o2]],
[[linear-binding-vanishes-at-o2]].
