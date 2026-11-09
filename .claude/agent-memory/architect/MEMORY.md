# architect — agent memory

One fact per file in this directory; one line here per fact, newest last. Link related facts with
`[[filename-without-extension]]`. Write a fact when something cost you time to discover and would
cost the next session the same: an endpoint quirk, a tool that lied, a constraint the code does not
state.

Do not record what the repository already says — structure, history, or anything in `CLAUDE.md`.

- [zk-kit pathIndices matches v3](zk-kit-pathindices-matches-v3.md) — verified from 1.1.0 source + scratch run; `siblings[i][0]` mapping; see [[gitignore-vs-d7-and-keys]].
- [.gitignore vs D7 and issuer keys](gitignore-vs-d7-and-keys.md) — `*.zkey` ignored, `issuer/keys/` not; floor 9 / ADR 0009 follow-ups.
- [Measuring v3 in a worktree](measuring-v3-in-a-worktree.md) — `npm ci` first; 8116 + 1529 constraints, 17 private inputs.
- [p2-plan revoke route inconsistency](p2-plan-revoke-route-inconsistency.md) — contract uses `/credentials/:leafIndex/revoke`; `GET /issuer` added.
