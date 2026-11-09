# Decisions

Durable decisions, newest last. Anything with a real trade-off gets an ADR in `docs/adr/`; this file
is the index plus the small rulings that do not warrant one.

## ADR index

| ADR | Title | Status |
|---|---|---|
| [0001](adr/0001-adopt-agentic-kit.md) | Adopt the agentic-kit orchestrator model | Accepted |
| [0002](adr/0002-adopt-p1-v3-circuit-as-base.md) | Adopt the team's P1 v3 circuit as the base; remove the circuits prototype (not included in this repository) | Accepted |
| [0003](adr/0003-node-runtime-for-issuer-and-registry.md) | D1: Node runtime for the issuer and the registry; gateway may stay FastAPI | Accepted |
| [0004](adr/0004-shared-encoder-in-circuits-lib.md) | D2: one shared encoder in `circuits/lib` with profiles v3/v4 | Accepted |
| [0005](adr/0005-commitment-with-salt-nullifier-from-secret.md) | D3: commitment = Poseidon(credentialSecret, credentialSalt); nullifier from credentialSecret | Accepted |
| [0006](adr/0006-v4-attribute-hash.md) | D4: v4 attrHash = Poseidon(7)(…, credentialCommitment) is the signed message and the leaf | Accepted |
| [0007](adr/0007-v4-public-signals-and-employee-active.md) | D5: v4 public-signal order (12 signals); `employeeActive` always required | Accepted |
| [0008](adr/0008-role-and-dept-enums.md) | D6: role and dept enums; v3 File Share values ignored | Accepted |
| [0009](adr/0009-commit-v4-proving-artefacts.md) | D7: commit v4 depth-16 proving artefacts, DEV keys until the ceremony | Accepted |

## Rulings

- 2026-11-08 (G0-S1-ARCH-010): the issuer API answers `400 forbidden_field` to any request body
  carrying `credentialSecret`, `credentialSalt`, `secret` or `salt`, instead of ignoring them, so a
  client bug that leaks the secret is loud (floor 6). Contract `issuer.api v1`.
- 2026-11-08 (G0-S1-ARCH-010): the registry's 30 s staleness window never re-admits a revoked
  leaf: a superseded root is acceptable only if no revocation happened after it
  (`issuer.api v1`, `GET /root/history`). Floor 3.
- 2026-11-08 (G1-S1-ARCH-011): the gateway takes `now`, `epoch`, `resourceId` and the policy from
  the challenge it issued with the nonce and requires the proof's public signals to equal them; the
  `now` skew bound is therefore the nonce TTL (120 s). Contract `access.public_signals v4`.
