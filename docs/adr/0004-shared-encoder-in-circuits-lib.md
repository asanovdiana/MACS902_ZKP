# ADR 0004 — One shared encoder in `circuits/lib` (D2)

**Status** Accepted · **Date** 2026-11-08 · **Task** G0-S1-ARCH-010

## Context

Issuer, registry and client all compute values the circuit recomputes: the commitment, the signed
message, the Merkle leaf and root, the input JSON, and (v4) the nullifier and the public-signal
array. If each module computed them independently, any drift (input order, field reduction, a
different Poseidon, a different `pathIndices` convention) shows up only as "valid credential fails
to prove" (scope risk "Poseidon mismatch", floor 8). The prototype solved this with a reference
library next to the circuit; P1's v3 has only a one-off generator script.

## Decision

- A single CommonJS library at **`circuits/lib/`**, owned by `circuits` (written by P2, reviewed by
  P1), is the only place that encodes circuit-facing values:
  - field encoding (canonical decimal strings < p) and parsing;
  - `commitment`, signed message `M`, leaf, Merkle helpers matching the circuit's `pathIndices`;
  - the circuit input builder;
  - the public-signal codec;
  - the role/dept enums and demo policies (ADR 0008), and a local policy pre-check (v4);
  - **profiles** `v3` and `v4`: depth, message layout, public-signal order, artefact paths.
- `issuer/` and `client/` import it; they do not re-implement any of the above. The gateway
  (Python) consumes the contract `access.public_signals v4`, not the library.
- Reference vectors under `circuits/test/vectors/<profile>/` from fixed TEST-ONLY seeds; the lib
  reproduces them, and `identity`'s cross-check suite (G1-S1-IDEN-013) checks issuer, registry,
  client and circuit agree.

## Consequences

- `identity` depends on `circuits` for every encoding change; the contract entries in
  `docs/CONTRACTS.md` are the agreement, the lib is its implementation.
- Moving from v3 to v4 is a profile switch plus tests in `issuer/` and `client/`, not a rewrite.
- Module boundary details: `docs/design.md`, "Module boundaries".

## Alternatives considered

- **`issuer/lib` imported by the client.** Rejected: the encoding describes the circuit's
  interface, so it belongs to the circuit owner; the client would depend on the issuer's tree.
- **A separate `packages/encoder` workspace.** Rejected for now: one more unowned path and a
  workspace setup for one library.
