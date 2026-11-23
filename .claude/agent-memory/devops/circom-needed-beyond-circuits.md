# circom is needed beyond the circuits suite

Native circom 2.2.3 is required by three suites, not one: root `npm test` (circuits), issuer's
`test/crosscheck.v4.test.js` (floor 8 cross-check compiles v3/v4 via circuits/test/helpers.js), and
tests/safety F8.05 (which runs that issuer suite). Without circom the issuer suite fails 4 hooks and
safety fails F8.05. So CI jobs `circuits`, `identity` and `safety` all use
`.github/actions/setup-circom`. client, client/attacks, `artifacts:check` and
`gen-vectors --check` do not need it. The v4 Docker demo uses the committed artefacts in
circuits/setup, not the native binary. See [[sandbox-npm-cache]].
