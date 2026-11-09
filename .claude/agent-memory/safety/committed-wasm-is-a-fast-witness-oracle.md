# The committed v4 wasm is a fast witness oracle

`snarkjs.wtns.calculate(input, "circuits/setup/integrated_access_v4.wasm", {type:"mem"})` runs the
shipped prover's circuit in ~0.2 s with no circom compile; a failed constraint throws "Assert
Failed". circom's wasm prints "ERROR: ..." through console.log/console.error, so silence both around
the call. `wtns.exportJson(mem)[1]` is the nullifier, `[1..12]` the 12 public signals in order.
Floor 2/3/8 safety tests use it (`tests/safety/helpers.js` witnessV4). Unknown input names throw
"Too many values for input signal X", which proves the v4 circuit has no `leaf`/`M` input.
See also [[test-only-issuer-key-is-derivable]].
