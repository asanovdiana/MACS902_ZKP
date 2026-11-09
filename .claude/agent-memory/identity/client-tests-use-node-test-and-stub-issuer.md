# client/ tests: node:test, an in-process stub issuer, and why not mocha

`client/` runs `node --test` (own package.json, `npm test --prefix client`) because the root
`.mocharc.json` merges its `circuits/test` spec into any mocha run and needs circom on PATH.
`client/test/helpers/stubIssuer.js` implements issuer.api v1 over real HTTP using `circuits/lib`
(sign, tree), with failure modes `foreign-issuer`, `bad-signature`, `altered-attributes`.
Coverage: `npm run coverage --prefix client` (c8 via npx; child-process CLI runs are counted).
snarkjs worker threads keep node alive: call `shutdown()` in an `after` hook and in the CLI.
v3 proving artefacts live in `circuits/setup/` as `<name>.wasm|.zkey|.verification_key.json`, not
under `_js/` as `profiles.v3.artefacts.wasm` suggests. See also [[v3-role-numbers-are-opaque]].
