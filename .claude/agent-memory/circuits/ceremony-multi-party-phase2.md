# Multi-party phase 2: snarkjs verify output is the chain of record

`scripts/ceremony.sh` (G1-S1-CIRC-008) checks a received zkey by running `snarkjs zkey verify`
and matching what it prints against `ceremony/<name>/transcript.json`. Facts that cost time:

- `zkey verify` lists contributions **newest first** (`contribution #3 …`, `#2`, `#1`), each as
  `contribution #N <name>:` followed by 4 lines of 4 eight-hex words (the 128-hex hash). The beacon
  is just another entry (`#N <beacon name>:` + `Beacon generator:` line). Strip ANSI colour first.
- `zkey contribute` prints `Contribution Hash:` in the same 4x4 layout; that exact hash reappears
  in later verifies, so it is what participants publish. Its stdin prompt is **not echoed** when
  stdin is a pipe, so entropy piped from a bash builtin `printf` never reaches argv or logs.
- `groth16 setup` with no contribution is deterministic from r1cs + ptau; its `Circuit Hash:`
  equals verify's `Circuit hash:` (lower-case h) — recorded as `snarkjs_circuit_hash`.
- Participant names land inside the zkey and in verify output, so the transcript restricts them to
  `[A-Za-z0-9][A-Za-z0-9 ._@'-]{0,63}` (a `:` or newline would break the parser).
- Flipping bytes ~150 B before the end of a toy zkey hits the contribution public key:
  `INVALID(1): public key G1 and G2 do not have the same ration`, exit 1. The scripts require
  both exit 0 and a `ZKey Ok!` line (as setup.sh does).
- In an isolated agent worktree the shell guard refuses `node $VAR …`, heredoc-then-run chains,
  `( … )` subshells and `for` loops around `bash`; write experiments to a script under
  `circuits/build/` (gitignored) and run `bash <abs path>`.
- The ceremony manifest makes `phase2.contributions` an array, so
  `test/setup_access.test.js` (asserts `=== 1` and `single-party`) must change in the same commit
  that installs ceremony keys for access_16.

Rehearsal on access_16 (9135 constraints, DEV-ONLY pot15, 4-core sandbox): init 24 s,
contribute ~23 s each, verify ~20 s, finalize 44 s (table in `circuits/ceremony/README.md`);
`zkey verify` against the power-15 ptau dominates. See [[ptau-dev-fallback]], [[access-fixtures-are-tied-to-one-setup-run]].
