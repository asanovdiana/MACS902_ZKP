# Hermez ptau is 403 here; the dev ceremony takes ~10 min at power 15

Both Hermez hosts (storage.googleapis.com/zkevm/ptau, hermez.s3-eu-west-1) return 403 through the
sandbox proxy, so `scripts/ptau.sh` falls back to a local `pot<NN>_DEV-ONLY_final.ptau`. Power 15
took ~10 min wall (22 min CPU); power 8 takes seconds, which is what `test/setup.test.js` uses.
The file is cached in `circuits/setup/ptau/` (gitignored, not shared between worktrees) and reused
while its blake2b matches the `.info.json` sidecar — do not delete it casually. A blake2b mismatch
on a *download* is fatal and never falls back to dev. snarkjs reads contribution entropy from its
stdin prompt when `-e` is absent, so the scripts pipe /dev/urandom there (no secret in argv).
See also [[snarkjs-workers-hang-mocha]].
