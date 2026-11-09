# v3 witness tampers assert exactly ONE violated R1CS row

`circuits/test/v3.test.js` (G0-S1-CIRC-020) edits a valid `--O0` witness by name
(`NamedWitness` in `circuits/test/helpers.js`) and asserts `violatedRows()` returns exactly one
row that involves the target signal. One row means removing that source constraint (or `<==`→`<--`)
makes the edit acceptable, i.e. the test kills that mutant, with no mutation run needed to know it.

Recipes that got every v3 wiring link to one row:
- link `x <== main.y` where `main.y` is used nowhere else: tamper `main.y` alone.
- deeper link (`verifier.Ax <== Ax`): tamper the whole upstream copy chain (`main.Ax` +
  `main.signature.Ax`) and leave the downstream one honest.
- links carrying the commitment (`M`, `leaf`, hasher out): splice whole subtrees from a SECOND
  valid witness (other secret/salt, same issuer) with `copyFrom(prefix...)`.
- Merkle internals: recompute levels with her formula and splice honest Poseidon(2) sub-witnesses
  from a standalone harness (circom_tester `templateName: "Poseidon", templateParams: [2]`, O0);
  harness names `main.X` map 1:1 to `main.merkle.hashers[i].X`.
- `verifier.enabled <== 1`: set `enabled` and both `eqCheckX/Y.enabled` to 0.
Builds on [[witness-tamper-for-mutants]] and [[o2-sym-merged-signals]]; counts in [[v3-constraint-counts]].
