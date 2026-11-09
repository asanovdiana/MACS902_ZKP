# Deleting `===` is caught by input-level tests; `<==`→`<--` is not

Deleting an `===` also deletes the witness generator's `Assert`, so an input-level negative
("bad input → Assert Failed") stops throwing and kills the mutant. Weakening `<==` to `<--` keeps
the honest assignment, so every input-level test behaves as before, and only a witness-level tamper
(overwrite the signal by `.sym` index, expect `checkConstraints` to throw) kills it. First harness
run: toy `hasher.inputs[0] <-- secret` survived `toy.test.js`, and the fix is
the "secret was overwritten" C-TOY-1 test, now in `test/toy.test.js`. Refines [[witness-tamper-for-mutants]].
