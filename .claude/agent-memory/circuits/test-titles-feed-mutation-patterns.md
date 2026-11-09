# Test titles are matched by the mutation scripts' --grep / --forbid-killers regexes

`mutate:access` runs `--grep negatives` and forbids killers matching
`hook|public interface|source rules|constraints at --O2|AccessGate mains|positives|unlinkability`;
`mutate:toy` uses `--grep C-TOY-1` and forbids `hook|has exactly` (circuits/package.json). These are
substring regexes on mocha full titles, so renaming a describe/it in `test/access.test.js` or
`test/toy.test.js` can silently move a test into or out of the mutation run or the forbidden set.
Before renaming: check the new full title still contains (or still avoids) every pattern above.
G1-S1-CIRC-015 renamed "public interface (access.public_signals v1)" to "... v1.1)" — safe, the
`public interface` substring is kept. `reports/perf-proto-access-test.json` keeps the old titles
(historical snapshot, nothing reads it back). See [[static-killers-mask-weak-negatives]],
[[mutation-harness-runs-in-a-tree-copy]].
