# access_16 fixtures are bound to one setup run; the circuit accepts any issuer key

`fixtures/access_16/*/proof.json` verify only under the committed `setup/access_16.verification_key.json`.
Re-running `npm run setup:access_16` (fresh randomness) makes a new vkey and silently breaks every
fixture; `scripts/access-fixtures.js` refuses to prove unless `build/access_16/access_16.zkey`
matches `zkey_sha256` in the manifest. The build dir is per worktree (gitignored), but since
G1-S1-CIRC-014 the matching pair is committed: `npm run artifacts:install` fills `build/access_16/`
on a fresh worktree; only a deliberate re-key re-runs setup (and then replaces zkey, wasm, vkey,
manifest and fixtures in one commit, see [[access16-proving-pair-is-committed]]). In-process
`snarkjs.groth16.fullProve(input, wasm, zkey)` avoids writing any input/witness file (floor 6).
Gateway-level attack fixtures are *valid* proofs: a forger can prove with its own issuer key and
the real root + path (only the pinned-key check stops it), so "wrong issuer is unprovable" holds
only under the pinned key. All Alice→Wiki fixtures share one nullifier (nonce-independent), so
gateway tests need fresh state per scenario. A secret-scan of committed JSON must skip short
values: empty-subtree siblings are `"0"`. Measured once: prove ~0.9–1.2 s, verify ~320 ms cold /
~21 ms warm, proof.json ~810 B (historical snarkjs verify; shipped verify() is ~5 ms warm, reports/perf-verify.md). See [[ptau-dev-fallback]], [[eddsa-verifier-gaps]],
[[snarkjs-workers-hang-mocha]].
