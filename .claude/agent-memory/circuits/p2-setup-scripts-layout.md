# P2 setup scripts live in circuits/scripts and run from the repo root

Ported from the removed circuits prototype in G0-S1-CIRC-022. `setup-lib.sh` derives REPO_ROOT from its own
path; defaults: BUILD_DIR=`build/` (root, gitignored), SETUP_OUT=`circuits/setup/`,
PTAU_DIR=`~/zkp-cache/ptau` (outside the tree, shared by every worktree, so no 10-min dev ceremony
per worktree), NODE_MODULES=root `node_modules` (one npm package at the root now, not circuits/).
`require("snarkjs/package.json")` throws ERR_PACKAGE_PATH_NOT_EXPORTED: require the absolute path.
`artifacts.sh` takes the name as a mandatory 2nd argument (no default). verify.js is snarkjs-based
plus canonical-signal and coordinate < q checks; since G1-S1-CIRC-037 it runs the ported
`circuits/scripts/fast-verify.js` by default (see [[perf-v4-numbers]]).
See [[v3-proving-pair-committed]], [[ptau-dev-fallback]], [[public-signal-leading-zeros-verify]].
