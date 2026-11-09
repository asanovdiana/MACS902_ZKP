# circomlib EdDSAPoseidonVerifier does not check points are on-curve

circomlib 2.0.5 `EdDSAPoseidonVerifier` checks S < l and 8·A ≠ 0, but not that R8 or A lie on
BabyJubJub. SPEC.md adds `BabyCheck` on R8 (C4) and on the issuer key (C5). `enabled` must be the
constant 1 — with `enabled = 0` every check is skipped. The issuer key is a public input that the
gateway must pin; a self-signed credential verifies fine in-circuit under the forger's key
(eddsa.json `forged` vector demonstrates it).
