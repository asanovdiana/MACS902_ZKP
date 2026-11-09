# snarkjs.groth16.verify is ~15-30 ms warm; the circuit is not the cause

Groth16 verify cost depends only on the number of public signals (12), not on constraints. On this
host warm `snarkjs.groth16.verify` takes ~16 ms median (more under load), over the 10 ms scope target.
About half is `multiExpAffine` for vk_x (12 points sent to the ffjavascript worker pool; the
round-trip dominates), the rest is 4 Miller loops + final exp, plus re-parsing the vkey every call.
`perf/proto/fast-verify.js` does the same checks in ~7 ms: parse once, main-thread `G1.timesScalar`
for vk_x, and e(alpha,beta)^-1 precomputed and passed as `pairingEq`'s optional odd last argument
(the target Gt value). `curve.millerLoop` takes `prepareG1/prepareG2` output, not affine points —
passing affine silently gives a wrong result. Use `buildBn128(true)` (single thread) in mocha
tests so no workers outlive them: [[snarkjs-workers-hang-mocha]].
