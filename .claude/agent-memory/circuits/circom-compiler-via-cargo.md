# circom compiler comes from cargo, not GitHub releases

In this sandbox GitHub release downloads are blocked (403) but crates.io and git clones of
github.com work, so `cargo install --git https://github.com/iden3/circom.git --tag v2.2.2 circom`
succeeds (~3 min build) and lands in `~/.cargo/bin/circom`. The npm `circom2` WASM fallback was not
needed and is not installed.

circom_tester shells out to plain `circom` on PATH (no option to pass a binary path), so
`circuits/test/setup.js` (mocha `require`) prepends `~/.cargo/bin` and fails fast if circom 2.x is
missing. See also [[constraint-counts-o2]].
