# Measuring v3 in a fresh worktree

circom 2.2.3 is at `~/.cargo/bin/circom`. A worktree has no node_modules: run
`npm ci --ignore-scripts` at the worktree root first (v3 includes `../node_modules/circomlib`).
`circom circuits/integrated_access_v3.circom --r1cs --sym -o <scratch>` gives 8116 non-linear, 1529
linear, 1 public input, 17 private inputs, 0 outputs (matches p2-plan §1, 2026-11-08).
Related: [[zk-kit-pathindices-matches-v3]].
