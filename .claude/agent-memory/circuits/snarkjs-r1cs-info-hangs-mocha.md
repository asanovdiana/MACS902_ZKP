# snarkjs.r1cs.info keeps mocha alive

`snarkjs.r1cs.info(file)` builds the bn128 curve with worker threads and never terminates them, so
mocha finishes every test and then hangs forever (output piped through `tail` shows nothing). Use
`readR1cs(file, { loadConstraints: false, loadMap: false, getFieldFromPrime: p => new F1Field(p) })`
from `r1csfile` + `ffjavascript` (what circom_tester does) — it returns nOutputs / nPubInputs /
nConstraints without workers.
