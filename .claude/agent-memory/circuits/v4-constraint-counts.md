# v4 constraint counts (non-linear + linear), circom 2.2.3

| depth | O0 | O1 | O2 |
|---|---|---|---|
| 8 | 10490+20801 | 10474+4231 | 7264+0 |
| 16 | 12458+25017 | 12442+6423 | 9208+0 |
| 20 | 13442+27125 | 13426+7519 | 10180+0 |

Asserted in `circuits/test/v4.test.js`. Each extra level costs ~243 at O2. At O1/O2
`main.employeeActive` has varIdx -1 (folded to constant 1 by the policy's `employeeActive === 1`):
"43 private inputs (42 belong to witness)" is expected, not a lost input. Public slots 1..12 are
nullifier, root, issuerAx, ... epoch at every level. Compile of the d16 main is ~3 s at O1.
See [[v4-gate-template-separate-file]], [[v3-constraint-counts]].
