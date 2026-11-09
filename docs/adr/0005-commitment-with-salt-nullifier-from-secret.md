# ADR 0005 — Keep `commitment = Poseidon(credentialSecret, credentialSalt)`; nullifier from `credentialSecret` (D3)

**Status** Accepted · **Date** 2026-11-08 · **Task** G0-S1-ARCH-010

## Context

The scope defines `secret_commitment = Poseidon(user secret)` (one input). P1's v3 computes
`credentialCommitment = Poseidon(2)(credentialSecret, credentialSalt)`. The prototype used
`Poseidon(1)(user_secret)`. The scope's nullifier is `Poseidon(user_secret, resource_id, epoch)`.

## Decision

- Keep v3's commitment unchanged in v3 and v4:
  `credentialCommitment = Poseidon(2)(credentialSecret, credentialSalt)`.
- Both values are generated client-side (31 bytes from a CSPRNG each, so < 2^248 < p) and never
  leave the client. The issuer receives only `credentialCommitment` (floor 6). This is the scope's
  `secret_commitment`, with a salt.
- v4 nullifier: `nullifier = Poseidon(3)(credentialSecret, resourceId, epoch)`. The salt is not an
  input to the nullifier.

## Consequences

- One extra private input relative to the scope; no constraint cost difference worth noting
  (Poseidon(2) vs Poseidon(1)).
- The salt makes the commitment hiding even if `credentialSecret` were reused across credentials;
  a user who re-enrols with the same secret but a new salt gets a fresh commitment but the **same**
  nullifiers. The client generates a fresh secret per credential (`credential.file v1`).
- P1's v3 input and any tests built on it keep working.
- Report text says "secret_commitment = Poseidon(secret, salt)" where the scope says
  Poseidon(secret).

## Alternatives considered

- **Scope's `Poseidon(1)(secret)`.** Rejected: changes P1's circuit for no security gain.
- **Nullifier over `(secret, salt, resourceId, epoch)`.** Rejected: Poseidon(4) for no benefit; the
  secret alone already carries the entropy.
