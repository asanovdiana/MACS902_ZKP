# v3: the main-template booleans on deviceCompliant/employeeActive are equivalent mutants

`integrated_access_v3.circom` has `deviceCompliant * (deviceCompliant - 1) === 0` and the same for
`employeeActive`, but `FileShareAccess` already forces both to `=== 1` through the `<==` wiring.
Any value breaking the boolean also breaks the policy row, so removing the boolean admits no new
witness: semantically equivalent mutants. The suite has a documentation test asserting value 2
violates exactly TWO rows; the ad-hoc sweep (2026-11-08, 40 mutants: every `<==`→`<--` and `===`
deletion in v3 + her three components, `--grep negatives`) reports them KILLED only because that
row count drops to 1 — a change detector, not a semantic kill. The other 38 were killed by their
targeted test. Floor 1 review should accept the two as redundant (or P1 drops them).
See [[v3-one-violated-row-tamper]], [[static-killers-mask-weak-negatives]].
