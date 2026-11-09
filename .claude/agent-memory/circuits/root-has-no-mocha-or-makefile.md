# Root package.json has no mocha/c8 and there is no Makefile (at the time)

`npm ci` at the root installs circom_tester, circomlib(js), snarkjs and chai, but not mocha or c8,
and `make test` fails (no Makefile; devops owns it). For local runs: `npm install --no-save
mocha@10 c8@10` (leaves package.json and the lockfile alone), then
`npx mocha --no-config --exit <file>`. c8 writes `coverage/` at the root, which is not gitignored:
delete it. circom_tester needs `~/.cargo/bin` on PATH; `circuits/test/lib.test.js` prepends it.
Related: [[circom-compiler-via-cargo]].
