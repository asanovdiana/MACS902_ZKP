# Mutation harness in the P2 layout (`npm run mutate:v4`)

Ported from the removed circuits prototype by G1-S1-CIRC-036 to `circuits/scripts/mutate.js` (+ `mutate/`). Paths are
repo-root relative and must be under `circuits/`. A workspace = copy of `circuits/` minus
build/reports/setup/node_modules, plus root `.mocharc.json` + `package.json`, symlinked root
`node_modules`; `MUTATE_TMPDIR` relocates it (rm -rf of /tmp paths is denied to agents, so use the
scratchpad). Spec ORDER matters: the reporter aborts at the first non-forbidden failure, so put the
cheap component specs before v4.test.js. `--annotations` documents equivalent / redundant mutants;
an annotation that matches no site exits 2. Annotations are read at start: write them BEFORE the
run. Baseline ~47 s. Without `--seed-builds` every mutant recompiles every test build (~3 min
per mutant under --jobs 4, ~2 h for 95); with it the baseline `build/` is copied into each workspace
and only builds stamped with the mutated file recompile (~30 s per mutant). `circuits/test/mutate.test.js` pins the
committed report to current sources, so any edit to a v4 .circom needs a re-run.
See [[mutation-harness-runs-in-a-tree-copy]], [[static-killers-mask-weak-negatives]],
[[test-titles-feed-mutation-patterns]], [[v4-gate-one-row-recipes]].
