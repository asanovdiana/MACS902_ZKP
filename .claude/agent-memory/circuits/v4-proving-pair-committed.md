# integrated_access_v4 proving pair is committed (DEV keys, G1-S1-CIRC-037)

`circuits/setup/integrated_access_v4.{zkey,wasm,verification_key.json,manifest.json}` from one
`npm run setup:v4` run : 9208 constraints at --O2, pot15 DEV ptau, ~1 min wall.
zkey sha256 290ee43e... (6.1 MB), wasm ea5058ef... (4.2 MB), vkey c1dc6af4.... Manifest
`public_signals` came out in contract order straight from the .sym (no fix-up needed).
`.gitignore` has one `!` line per file; `setup_v4.test.js` asserts tracked/ignored both ways.
`circuits/fixtures/v4/` is bound to this key: a re-key (G2-S1-CIRC-040) must regenerate it in the
same commit. `client/src/prover.js` already resolves these names under `circuits/setup/`.
See [[v3-proving-pair-committed]], [[v4-fixtures-and-obligations]], [[perf-v4-numbers]].
