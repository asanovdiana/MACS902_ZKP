# .gitignore blocks D7 and does not protect issuer keys (at the time)

Root `.gitignore` (P1's) ignores `*.zkey` and `tests/*.json`, so ADR 0009 (commit the v4 depth-16
zkey) needs an un-ignore rule for the artefact path. It does NOT ignore `issuer/keys/`, `.zkgate/`
or `*.credential.json`; floor 9 depends on adding them before G0-S1-IDEN-001. `.gitignore` is
unowned; raise to the Orchestrator rather than editing silently. Related:
[[zk-kit-pathindices-matches-v3]].
