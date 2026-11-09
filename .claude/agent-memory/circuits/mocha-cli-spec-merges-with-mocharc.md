# `mocha <file>` still runs the .mocharc spec glob

Mocha 10 merges a positional spec with `spec` from `.mocharc.json`, so `npx mocha test/x.test.js`
runs the whole `test/**/*.test.js` suite too (including any red peer tests). To run one file:
`npx mocha --no-config --require test/setup.js --timeout 600000 test/x.test.js`, or `--config`
with a file that omits `spec`. The mutation harness writes its own `.mutate-mocharc.json` for this
reason ([[mutation-harness-runs-in-a-tree-copy]]).
