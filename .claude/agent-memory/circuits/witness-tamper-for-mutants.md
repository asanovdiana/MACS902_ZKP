# Removed constraints are only caught by witness-level tamper tests

When a mutation turns `===`/`<==` into `<--`, the witness generator still computes the honest
value, so input-level negative tests (bad input → Assert Failed) often still "fail correctly" and
miss the mutant. To detect it: take a valid witness, overwrite the target signal (index from the
.sym file), and expect `checkConstraints` to throw. toy.test.js does this with `w[1]` (main.h).
Overwritten signals must exist in the build — check the .sym at the chosen -O level
([[constraint-counts-o2]]). SPEC.md §7 lists which negatives are witness-level.
