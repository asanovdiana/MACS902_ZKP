# verify.js worker threads hang a node:test file

`circuits/scripts/verify.js` (fast verifier) keeps worker threads alive; a test file that calls
`verifier.verify` without `verifier.terminate()` never exits and `npm test --prefix tests/safety`
hangs with no output. Files that verify have `after(() => verifier.terminate())`; F9.10 uses
`t.after` inside the test because floor09 had no verifier before. See [[safety-tier-layout]].
