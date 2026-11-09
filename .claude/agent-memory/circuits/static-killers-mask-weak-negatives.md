# Static tests steal mutation kills and hide weak negatives

Run over all of `test/access.test.js`, the harness reported AccessGate 59/59 killed, but most kills
went to "source rules: no `<--`…" (reads the source text) and "has exactly 9135 constraints at
--O2" (any `<==`→`<--` drops an R1CS row). With `--bail` the first failure wins, so those tests
masked whether any negative noticed the mutant. Fix: `mutate:access` runs `--grep negatives` and
`--forbid-killers 'hook|public interface|source rules|constraints at --O2|…'`; a kill only by a
forbidden title counts as survived. Forbid mode turns off mocha's bail and the reporter calls
`runner.abort()` at the first allowed failure. Hooks are forbidden because a failing `before`
proves completeness broke, not soundness. The toy has the same trap: its O2 count does not move
for `hasher.inputs[0] <-- secret` (linear rows are optimised away), so that mutant survived anyway.
Supersedes the manual loop in [[mutation-sweep-adhoc]]; see [[deleted-assert-vs-unconstrained-assign]].
