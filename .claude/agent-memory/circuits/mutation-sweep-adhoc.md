# Ad-hoc constraint-removal sweep (until G1-S1-CIRC-002 lands)

Mutating every `<==`→`<--` / commenting every `===` line in src/access.circom + src/lib (59
points) and running `mocha --spec test/access.test.js --grep negatives` per mutant takes ~10 min
with 4 in parallel (each mutant compiles O2 + O0). Gotchas: copy `scripts/` too — `.mocharc.json`
spec loads vectors.test.js, which requires `../scripts/gen-vectors`; mark runs with no "passing"
line as ERROR, or a crash reads as "0 failing". First sweep: all 24 C-row constraints killed, 21
**wiring** links (`comp.in <== x`) survived until the "component wiring" tests were added.
Unkillable by design: deleting circomlib-internal checks (BabyCheck, Num2Bits) is not a mutation
point; C4/C5 are implied by the EdDSA equation for inputs. See [[o2-sym-merged-signals]].
