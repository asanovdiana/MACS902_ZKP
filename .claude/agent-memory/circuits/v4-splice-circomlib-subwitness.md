# Splice circomlib sub-witnesses from templateName harness builds

Generalises the v3 Poseidon(2) trick ([[v3-one-violated-row-tamper]]) to any circomlib template:
circom_tester `wasm(file, { O: 0, templateName: "GreaterEqThan", templateParams: [2] })` on
`node_modules/circomlib/circuits/<file>.circom` builds a standalone main; copy every `main.X` of
its witness to `<prefix>.X` of the NamedWitness. Used for Num2Bits, Mux2, GreaterEqThan, LessThan
in `circuits/test/policy_v4.test.js` and `expiry.test.js` (G1-S1-CIRC-033/034).
`helpers.js` does not export `compileCached`, so those files carry a small memoised `build()`
with build names prefixed `policy-v4-` / `expiry-` to stay clear of peers' build/test dirs.
Sweep result: input-level negatives kill only the 7 `===` deletions of 25 mutants; the 18 `<==`
links die only to these one-row tampers ([[deleted-assert-vs-unconstrained-assign]]).
