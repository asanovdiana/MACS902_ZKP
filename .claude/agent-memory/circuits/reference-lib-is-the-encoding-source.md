# circuits/lib is the reference encoder for identity and gateway

`circuits/lib` (G1-S1-CIRC-009) builds AccessGate inputs (`buildAccessInput`) and decodes
`access.public_signals v1.1` (`decodePublicSignals`); `test/lib.test.js` pins it to the vectors, every
`fixtures/access_16/*/public.json`, the setup manifest order and the --O2 witness calculator (build
dir `build/test/access_16_lib`, separate from access.test.js's). Any change to signal names, order
or ranges must update `lib/signals.js` / `lib/inputs.js` too, or that test fails.
Gotchas: `circomlibjs` is a devDependency, so a consumer outside `circuits/` needs it installed;
decode rejects non-canonical decimals (`"01"`) on purpose (nullifier-table aliasing).
Since G1-S1-CIRC-013 both generators (`scripts/gen-vectors.js`, `scripts/access-fixtures.js`)
build their inputs with the lib; `test/generators.test.js` checks the lib path reproduces the
committed vectors and every fixture `public.json`.
Related: [[public-signal-order-is-declaration-order]], [[vectors-workflow]].
