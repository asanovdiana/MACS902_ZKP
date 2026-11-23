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
- **#1 P1 circuits - simulated by agent on same machine** — contribution hash `b94c7befc2143dac2ee41c774716c8e2d641ba7beac2f23df96b826dfa9070e3b68897b4b96da046b5a0feaec0b631535f74026f6ec2d0a00bf5ea0232f81ccf`, zkey sha256 `64e08294b5240c37e109134363c518592f6124d917eb0e69be7faefbb5d72efb` (from transcript.json), 2026-11-23T16:36:02Z
- **#2 P2 identity - simulated by agent on same machine** — contribution hash `65c1a72c1dac225ba16a973dabb762d32b32176ab6a2c520875acbccaa0c3f4a6ffbc6d5eddd1368f12e0e1b3e05e6eb91e2566ddacb4b8ad30d25e899a807cc`, zkey sha256 `711ce556cb9e57bdfb8d4fd406ae79363a913b730b6404ec71003e73228314ac` (from transcript.json), 2026-11-23T16:37:35Z; verified #1 before contributing
- **#3 P3 gateway - simulated by agent on same machine** — contribution hash `6ae8dc38bc675c88796e62e566b353dab2911b76fd199726902d8e444981ce29bf6d0ac43e92e8178f5a24997b4ae259314d832c18cf6788dd1ccc9f1938c7c9`, zkey sha256 `58f37d60da398d894bc71d48d0d7f6cd8aae94025db59b55a3ae373d7af0c624` (from transcript.json), 2026-11-23T16:39:01Z; verified #1–#2 before contributing

## 3. Beacon and finalize

- **Beacon:** drand mainnet (chain hash `8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce`), **round 6667474** (2026-11-23 17:34:00 UTC), as announced in §1. Randomness `9c26abbf0594815ac1e143bc5c586518f1ddf2264411ebd7af4a8d17d6d022d2`, re-fetched by P1 from `https://api.drand.sh/public/6667474` and checked as sha256 of the round's signature. Applied with 2^10 iterations.
- **Before finalize:** P1 verified `integrated_access_v4_0003.zkey` (ZKey Ok against the r1cs + PSE ptau). The chain #1 P1, #2 P2, #3 P3 matches the three hashes in §2 exactly.
- **Beacon contribution hash:** `88c9928e5ad06a82d07a01679633a7607aef64eb2ec3128a653e567396ce1e27d9c47c49208f46178c457ca51778884faaf6a2c372338391b1100575c01151d4`
- **Final zkey** `integrated_access_v4_final.zkey` sha256 `73f527f371539c34b4507f6f2c395fd9be2f0c2df53fd5af9df2caa8749d85e3`
- **Verification key** `integrated_access_v4.verification_key.json` sha256 `c5490c184298b14dd5cc8882a351e68b1e5983d54e10fa5c68acb3c7927ae059`
- **Manifest `status`:** `DEMO-ONLY` (3 contributors + public beacon + public phase 1). This is a simulated, same-machine ceremony; see the scope note above.
- Finalized 2026-11-23T17:35:21Z by P1.

## 4. Final checks

- P2 identity: OK — final zkey `73f527f371539c34b4507f6f2c395fd9be2f0c2df53fd5af9df2caa8749d85e3` verified, own entry #2 present, beacon matches round 6667474, 2026-11-23T17:36:55Z
- P3 gateway: OK — final zkey `73f527f371539c34b4507f6f2c395fd9be2f0c2df53fd5af9df2caa8749d85e3` verified, own entry #3 present, beacon matches round 6667474, 2026-11-23T17:36:57Z
