# CI is circuits/ci.sh; c8 sees child processes, and pipeline-only scripts were at 0%

`circuits/ci.sh quick|full` is the only command devops calls. Exit codes: 0 pass, 1 a step failed,
2 usage, 3 prereq (circom 2.2.2 or npm ci). c8 picks up every spawned `node` child through the
inherited NODE_V8_COVERAGE, so CLI-driven scripts count. Under SKIP_SETUP=1, though,
`setup-manifest.js` and `ceremony-transcript.js` were at 0%, because only setup.sh/ceremony.sh call
them. `test/coverage-scripts.test.js` now drives them with synthetic logs and files (snarkjs hash =
4 lines of 4 8-hex words).
Per-file gate: lines/statements/functions 80, branches 75. Excluded: `perf/**` and `access-fixtures.js`
(it needs the same-run access_16 zkey). Reports and coverage go under build/, because circuits/.gitignore
has no `coverage/` entry. The CI mutation runs pass `--report $CI_OUT/...`: mutate.js takes the last
`--report`, so the committed reports/ are never rewritten.
`c8 report` re-gates the last run, so ci.sh reports test failures and coverage failures as separate
steps. See also [[mutation-sweep-adhoc]], [[ptau-dev-fallback]].
