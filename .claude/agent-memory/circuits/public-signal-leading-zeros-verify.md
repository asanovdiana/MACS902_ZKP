# Public signals with leading zeros used to verify — now rejected by verify.js

snarkjs 0.7.6 `groth16.verify` rejects values ≥ p (`publicInputsAreValid`), but it parses decimal
strings with `unstringifyBigInts`, so `"0123"` is 123: a raw snarkjs call accepts `"0"+n`.
Until G1-S1-CIRC-010 `scripts/verify.js` only checked `/^[0-9]{1,78}$/`, so `alice_wiki` with nonce
`"00"+n` or nullifier `"0"+n` verified (found 2026-11-02).

Fixed 2026-11-02 (G1-S1-CIRC-010): `verify()` requires `isCanonicalSignal` on every public signal
(`^(0|[1-9][0-9]*)$`, ≤ 77 digits, < p); `canonicalizeSignals(arr)` returns the canonical copy or
null. Contract is `access.public_signals v1.1`. Tests: `test/canonical.test.js`. `alice_wiki`
`min_clearance` (index 6) is `"0"` — use it for the zero case. Anyone calling snarkjs directly
(not via verify.js) still has the bug; the gateway must key on canonical values anyway (R7, R8).
Proof coordinates are still only `DEC`-checked: harmless, replay is never keyed on proof bytes.
Related: [[eddsa-verifier-gaps]] (another check the gateway must make).
