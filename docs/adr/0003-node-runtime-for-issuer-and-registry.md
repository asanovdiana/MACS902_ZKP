# ADR 0003 — Node runtime for the issuer and the registry (D1)

**Status** Accepted (team, 2026-11-08) · **Date** 2026-11-08 · **Task** G0-S1-ARCH-010

## Context

The scope's tech stack lists "Python FastAPI" for issuer + gateway, and
"`@zk-kit/incremental-merkle-tree` (Node) or a Poseidon tree in Python" for the registry, with the
condition that it "must use the same Poseidon parameters as the circuit". The issuer must sign with
EdDSA-Poseidon on BabyJubJub exactly as circomlib's `EdDSAPoseidonVerifier` checks it. The mature
implementations of both are `circomlibjs` (Poseidon, `eddsa.signPoseidon`) and
`@zk-kit/incremental-merkle-tree`, both JavaScript. A Python issuer would need a second
Poseidon/BabyJubJub implementation, which is the scope's "Poseidon mismatch" risk and floor 8.

## Decision

- `issuer/` (M1 issuer and M2 registry) is a **Node.js CommonJS** service, the module style P1
  uses in `scripts/generate_integrated_v3.js`. HTTP via a small framework (Fastify or Express,
  chosen by `identity`), exposing `issuer.api v1`.
- `client/` (M4) is Node.js CommonJS as well (the scope already says "CLI first (Node + snarkjs)").
- Poseidon, EdDSA and tree code come only from `circomlibjs` and
  `@zk-kit/incremental-merkle-tree`, through the shared encoder in `circuits/lib` (ADR 0004).
- The gateway (P3, `gateway/**`) may stay Python FastAPI. It never computes Poseidon; it only
  verifies Groth16 proofs and compares canonical integers (`access.public_signals v4`).

## Consequences

- Deviation from the scope's tech-stack row for the issuer, recorded here; the scope's reason
  ("fast to build; we know it") is outweighed by floor 8.
- Two runtimes in the demo (Node issuer/client, Python gateway). Packaging in `docker/` and
  `compose.yaml` is `devops`'s.
- `@zk-kit/incremental-merkle-tree` is not yet a dependency (root `package.json`); `identity`
  adds it, pinned (1.1.0 was checked against v3's `pathIndices` convention, see
  `credential v3`).

## Alternatives considered

- **Python issuer with a Python Poseidon/BabyJubJub.** Rejected: second implementation of the
  primitives; cross-check tests would be the only defence.
- **Python issuer calling a Node signing helper.** Rejected: two processes for one boundary, with
  no gain over a Node service.
