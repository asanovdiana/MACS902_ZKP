# npm ci in the sandbox needs a writable cache

`npm ci` fails with EROFS on ~/.npm/_cacache inside the Claude sandbox. Pass
`--cache /tmp/claude-1000/npm-cache` inline (an `export` of env vars is refused by the worktree
guard) and allow registry.npmjs.org. Local npm 12 also blocks install scripts (esbuild,
blake-hash) by default; p3 typecheck/lint/test/build still pass without them. CI uses Node 22's
npm, which runs them. See [[circom-needed-beyond-circuits]].
