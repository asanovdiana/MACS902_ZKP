# ADR 0009 — Commit the v4 depth-16 proving artefacts (DEV keys until the ceremony) (D7)

**Status** Accepted · **Date** 2026-11-08 · **Task** G0-S1-ARCH-010

## Context

Proving needs the circuit `.wasm` and the Groth16 `.zkey`; verifying needs the verification key.
Regenerating them needs circom 2.2.3, a Powers of Tau file and a phase-2 setup: minutes of work and
a toolchain the demo machine may not have. The scope requires `make demo` to run offline from
Docker, and fixtures for the gateway must match the exact keys. The team's multi-party phase-2
ceremony is planned for G2 (G2-S1-CIRC-040).

## Decision

- Commit, for the v4 depth-16 main only: `.wasm`, `.zkey`, verification key and a manifest
  recording circuit source hash, circom version, ptau source and hash, zkey hash and the
  public-signal order (G1-S1-CIRC-037).
- Until the ceremony these are **DEV-ONLY** keys (single contributor, toxic waste not provably
  destroyed); the manifest and the README say so. G2-S1-CIRC-040 replaces them and regenerates the
  fixtures in one commit.
- v3 (G0) artefacts and the depth 8/20 benchmark mains are build outputs, not committed.
- Fixtures (valid and attack proofs) are tied to the committed zkey and regenerated with it.

## Consequences

- A clone can prove and verify without a setup run; the gateway tests against fixed fixtures.
- Repository size grows by the depth-16 zkey (tens of MB); `devops` decides on Git LFS if needed.
- Floor 9 is unaffected: a zkey is public material, not a credential or issuer key. Anyone with
  the DEV zkey's toxic waste could forge proofs, which is why it is labelled and replaced.

## Alternatives considered

- **Generate at `make demo` time.** Rejected: slow, needs the toolchain in the image, and the
  fixtures would not match.
- **Download from a release.** Rejected for now: the demo must run offline.
