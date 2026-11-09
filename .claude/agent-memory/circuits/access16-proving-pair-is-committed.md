# access_16 zkey + wasm are committed in setup/ (since G1-S1-CIRC-014)

`setup/access_16.zkey` (6.0 MB) and `setup/access_16.wasm` (4.2 MB) are tracked via `!` exceptions
in `setup/.gitignore` (parent `circuits/.gitignore` also has `*.zkey`; the deeper negation wins).
A fresh worktree no longer needs to re-run setup: `npm run artifacts:install` (check, then copy to
`build/access_16/`) makes prove.sh / access-fixtures.js work. Re-keying = replace zkey, wasm, vkey,
manifest and fixtures in ONE commit (`setup/ARTIFACTS.md`); `test/artifacts.test.js` fails otherwise.
Gotcha: `git check-ignore -q` takes exactly ONE path (two paths -> exit 128, not 0/1), and on a
tracked file it reports "not ignored" regardless of rules: pass `--no-index` to test the rules.
Exporting the vkey from the zkey takes ~0.4 s; a full `artifacts.sh check` ~0.6 s.
See [[access-fixtures-are-tied-to-one-setup-run]], [[ceremony-multi-party-phase2]].
