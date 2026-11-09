# At --O2 a merged signal is listed with index -1 in the .sym

circom 2.2.2 `--O2` keeps one representative per class of signals tied by `a === b`/`a <== b`;
every other name in the class gets witness index **-1** in the `.sym` (it does not share the
representative's index). In AccessGate(16) even `r8OnCurve.x`, `roleCheck.valueBits.out[0]`,
`leaf.out`, `tree.root` are -1, so witness tampering by name is impossible at O2.
Fix used in `test/access.test.js`: a second `--O0` build (`compile(..., { O: 0 })`, all signals
kept) and a union-find over pure-equality R1CS rows (A = B = 0, C = k·x − k·y) so a tamper writes
the whole alias class — that mimics O2 merging and splits automatically in a `<--` mutant.
Extends [[witness-tamper-for-mutants]]; counts in [[constraint-counts-o2]].
