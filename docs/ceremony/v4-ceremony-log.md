# Phase-2 ceremony log — `integrated_access_v4`

Procedure: [`circuits/ceremony/README.md`](../../circuits/ceremony/README.md).

## Honest scope: a simulated multi-party ceremony

This ceremony was run on **one machine, under one operator**, with each participant role (P1, P2,
P3) played by a **separate AI agent process** that generated its own randomness (64 bytes of
`/dev/urandom` plus snarkjs's own, per `ceremony.sh contribute`) and passed the zkey on as a file.
It exercises the complete multi-party procedure (separate contributions, hash attestations,
verification at every hand-off, a beacon announced in advance) and produces keys whose transcript
verifies.

It does **not** give the trust guarantee of a real multi-party ceremony: that guarantee needs at least
one contributor who is an independent person on their own machine. Whoever controlled this machine
could in principle have kept every contribution's randomness. The keys therefore stay
**DEMO-ONLY — not for production**. For any real use, re-run the ceremony with the team members each
contributing on their own machine.

## 1. Announcement (made before any contribution)

- **Date:** 2026-11-23, about 16:34 UTC.
- **Beacon:** drand mainnet (chain hash `8990e7a9aaed2ffe…`, period 30 s), **round 6667474**,
  expected at about 2026-11-23 17:34 UTC: the `randomness` field of
  `https://api.drand.sh/public/6667474`. Fixed now, so nobody can choose it after seeing the
  contributions.
- **Phase 1:** PSE Perpetual Powers of Tau, contribution 0080, power 15 (`ppot_0080_15.ptau`,
  blake2b-512 `a6dd3adc…7f24`, verified against the pin in `circuits/scripts/ptau.sh`).
- **Toolchain:** circom 2.2.3, snarkjs 0.7.6 (root `package-lock.json`).
- **Order:** P1 (coordinator: init, contribute, finalize, install) → P2 → P3 → P1 finalizes.

## 2. Contributions

<!-- Each participant appends their contribution hash here before passing the zkey on. -->
