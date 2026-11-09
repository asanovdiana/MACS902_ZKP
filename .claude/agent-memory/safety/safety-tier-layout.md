# Safety tier layout and append-only mechanics

`npm test --prefix tests/safety` (node:test, ~35 s). F8.05 spawns the issuer crosscheck suite with
`issuer/node_modules/mocha --no-config`, because a CLI spec merges with `.mocharc.json` and would
run the whole issuer suite. IDs `F<floor>.<nn>` live in `test("...")` titles; `MANIFEST.json` must
stay a superset of HEAD's (F10.03): only append entries. mkdtemp dirs are already 0700, so to test
that code CREATES a dir with 0700, pass a not-yet-existing subdir. No Makefile exists (SR-17):
`make test` cannot run. See [[committed-wasm-is-a-fast-witness-oracle]].
