# verify() runs scripts/fast-verify.js; snarkjs point checks are weaker than they look

Since G1-S1-CIRC-011 `scripts/verify.js` uses `scripts/fast-verify.js` by default, with one
verifier cached per vkey content hash. `ZKGATE_VERIFY_IMPL=snarkjs` selects stock snarkjs instead.
`perf/proto/fast-verify.js` is now only a re-export.

What snarkjs 0.7.6 / ffjavascript 0.3.1 do NOT check, found while matching them:
- `G2.isValid` is only an on-curve test: no subgroup check, and the twist has order r·(2p−r).
- `isValid(O)` is true, and `fromObject([0,0,1])` *is* O (zeroAffine is all zeros).
- `F.fromObject` reduces mod q: `pi_a[0] + q` verifies as `pi_a[0]` (stock returns `true`).
verify() rejects all three in both paths. `(-A, -B, C)` still verifies (malleability, R8).

Implementation gotchas:
- `prepareG1`/`prepareG2` want JACOBIAN points (`G1.toJacobian`). Affine input gives a silently
  wrong pairing.
- For vk_x, call the wasm `g1m_multiexpAffine` directly on the main thread (via
  `tm.startSyncOp/allocBuff`): ~0.8 ms, against ~1.3 ms for 12 `timesScalar` calls.
- An all-single-thread design ran ~8.7 ms. Overlapping work brings it to ~4.9 ms median: queue
  the e(-A,B) Miller loop, the e(C, δ) Miller loop and the `[r]B` check (~0.9 ms) as
  `tm.queueAction` tasks while the main thread computes vk_x and e(vk_x, γ). A precomputed
  `preQ` buffer can be `ALLOCSET` into a worker.
- `buildBn128(false)` returns snarkjs's `globalThis.curve_bn128` and shares it.
- A non-G2 twist point for tests: x = (k, 1), y = sqrt(x³ + b'); a small k works.

See [[snarkjs-verify-overhead]], [[public-signal-leading-zeros-verify]] and
[[snarkjs-workers-hang-mocha]]. The red-phase mocha run hung after failing, because the old
verify.js workers stayed alive.
