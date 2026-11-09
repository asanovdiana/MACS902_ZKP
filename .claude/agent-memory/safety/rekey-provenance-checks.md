# Checking a re-key independently (PSE ppot 0080)

The ptau lives outside the tree at `~/zkp-cache/ptau/ppot_0080_15.ptau` (37,842,066 B). The
manifests' transcript offsets (90185, 91706) are relative to section 7's data start (12,583,116),
not file offsets. Section 7 records 62 contributions, although the file is "contribution 0080".
`snarkjs zkey verify <r1cs> <ptau> <committed zkey>` (recompile the r1cs to a temp dir with
`~/.cargo/bin/circom ... --O2 -l node_modules -l .`; the output dir must exist) proves the key
descends from that phase 1. The worktree guard refuses `$VAR`-built commands: spell paths out.
F9.09/F9.10 lock the manifest side; the ptau checks stay manual. See [[committed-wasm-is-a-fast-witness-oracle]].
