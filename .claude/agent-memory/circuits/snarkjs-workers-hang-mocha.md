# In-process snarkjs verify keeps mocha alive

`snarkjs.groth16.verify` builds the bn128 curve with ffjavascript worker threads and caches it on
`globalThis.curve_bn128`; the threads keep the Node process (and mocha, which has no `--exit` here)
running after the tests pass. `scripts/verify.js` exports `terminate()` to release them, and
`test/setup.test.js` calls it from a root-level `after` hook. A long-running service should NOT
terminate per request — the cached curve is what makes repeat verifies fast (toy: ~290 ms first,
~20 ms after). See also [[ptau-dev-fallback]].
