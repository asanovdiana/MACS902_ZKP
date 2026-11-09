# Mutation harness runs each mutant in a copy of circuits/

`scripts/mutate.js` copies `circuits/` (minus node_modules/build/reports) to a temp dir and symlinks
node_modules. `test/helpers.js` resolves `src/` and `build/` from its own `__dirname`, so specs run
unmodified against the copy. No `CIRCUITS_SRC_DIR` env var is needed, and parallel jobs never share
a build dir. Circom grammar facts it relies on: a bare `;` is illegal (P1012), so a deleted `===`
becomes `{}`. `<--` on an anonymous component is TAC01, which the harness reports as
`compile_error`, not a kill. circom_tester prefixes compile failures with "circom compiler error".
See [[mocha-cli-spec-merges-with-mocharc]], [[deleted-assert-vs-unconstrained-assign]].
