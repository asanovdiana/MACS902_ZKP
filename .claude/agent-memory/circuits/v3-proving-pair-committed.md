# integrated_access_v3 proving pair is committed (DEV keys, G0-S1-CIRC-022)

`circuits/setup/integrated_access_v3.{zkey,wasm,verification_key.json,manifest.json}` from one
setup run: 4935 constraints at --O2, public signals `[root]`, zkey sha256 8c1f5f58..., 3.0 MB zkey,
2.5 MB wasm. Tracked via `!` lines in `circuits/setup/.gitignore` (root `.gitignore` has `*.zkey`).
Re-running setup.sh re-keys: replace all four in one commit (`circuits/setup/ARTIFACTS.md`).
`circuits/test/setup.test.js` builds a TEST-ONLY v3 input in memory (circomlibjs, fixed seeds,
commitment at leaf index 1 so pathIndices = [1, 0]) and proves with the committed pair (~1 s).
See [[p2-setup-scripts-layout]], [[access-fixtures-are-tied-to-one-setup-run]].
