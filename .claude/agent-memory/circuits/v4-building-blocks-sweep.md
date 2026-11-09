# v4 building-block sweep: 25/25 killed by targeted tests

Throwaway script (not committed): per mutant copy `circuits/` (no build/node_modules) to a
scratch dir, symlink root `node_modules`, mutate one line (`<==`→`<--`, `===` line → `{}`), run
`npx mocha --no-config --require circuits/test/setup.js --reporter json --grep
"identical R1CS|layout|control:" --invert <3 spec files>`; parse JSON after the first `{\n`
(circom warnings precede it). The invert regex removes static killers (R1CS-identity and count
tests would kill everything). 4 parallel, ~25 mutants in a few minutes. Every `<==` wiring mutant
fell only to its one-violated-row witness tamper; deleted `===` fell to input-level negatives.
Poseidon(7) splice harness: circom_tester on circomlib poseidon.circom with
`templateName: "Poseidon", templateParams: [7]`, O0. See [[v4-building-blocks-components]],
[[mutation-sweep-adhoc]], [[static-killers-mask-weak-negatives]].
