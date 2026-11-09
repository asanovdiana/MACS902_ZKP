# Cross-check suite harness (issuer/test/crosscheck.v4.test.js)

Drives the real issuer (`makeApp`) and the real client lib with no sockets: `IssuerClient({fetch})`
accepts a fetch built on `app.inject` (needs only `{status, text()}`). Circuit side uses
`compileV3(0)` / `compileCached("v4-d16-O0", ...)` from circuits/test/helpers (O0 keeps signal names,
see the circuits agent's o2-sym-merged-signals fact), `tester.calculateWitness(input, true)`; named
signals are `main.credentialCommitment`, `main.attr.attrHash`, `main.merkle.leaf`, `main.root`,
`main.nullifier`; public signals are `w[1..12]` (v4) / `w[1]` (v3). No v4 keys needed. The issuer
never returns the commitment, so "issuer side" means the stored leaf (`/admin/tree` level 0,
`/admin/leaves`, `/path`) plus the signature check. `mocha --grep` is needed to run one file (a CLI
spec merges with .mocharc). Related: [[v3-role-numbers-are-opaque]].
