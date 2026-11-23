# v4 Groth16 fixtures (TEST-ONLY)

Real proofs of `circuits/integrated_access_v4.circom` (depth 16) under the committed
**DEMO-ONLY** key `circuits/setup/integrated_access_v4.verification_key.json` (phase 1 PSE
Perpetual Powers of Tau 0080; multi-party phase 2, 3 contributors + the public drand beacon, round
6667474). The three contributions were **simulated** by separate agents on one machine under one
operator, so the multi-party trust guarantee does **not** hold: not for production
(`docs/ceremony/v4-ceremony-log.md`, `circuits/setup/README.md`). Re-keyed in G2-S1-CIRC-040a and
again in G2-S1-FINAL-001 (ceremony install), which regenerated every proof here. For `gateway` (verifier + obligations 1-8 of
`access.public_signals v4` in `docs/CONTRACTS.md`), `identity` (client contract), `qa`, `safety`
and the Attack Lab. Built from the TEST-ONLY vectors `circuits/test/vectors/v4/credentials.json`
by `npm run prove:fixtures:v4` (`circuits/scripts/access-fixtures.js`). **Never use outside tests.**

| File | What |
|---|---|
| `verification_key.json` | copy of `circuits/setup/integrated_access_v4.verification_key.json` (sha256 `c5490c18...` = manifest) |
| `fixtures.json` | machine-readable index: `context` (pinned issuer, roots before/after revocation, gateway clock, epoch, nonce TTL, resource policies) and per fixture `kind`, `expect`, `persona`, `resource` (what it proves), `presented_to` (what the request asks for), `nonce`, `gateway_state`, `gateway_obligations`, `floor`, `description` |
| `<name>/proof.json` | snarkjs Groth16 proof (~806 B JSON; 256 B as raw points) |
| `<name>/public.json` | 12 canonical decimal strings in `access.public_signals v4` order: `nullifier, root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch` |

No private input is committed (floor 6): every witness is built in memory by
`snarkjs.groth16.fullProve`; there is no `input.json`. `circuits/test/fixtures_v4.test.js` enforces
the file allow-list and scans every file for every persona's secret, salt, commitment, attrHash,
signature and Merkle siblings.

**Every fixture verifies** (`verify()` returns `true`, gateway obligation 1). Verification is only
the cryptographic half: the attack fixtures are valid proofs that the gateway must still deny on
the obligation named below.

## Scenario context (`fixtures.json` -> `context`)

| Key | Value |
|---|---|
| `pinned_issuer` | the vectors' TEST-ONLY issuer key (`Ax 1561...7649`, `Ay 2091...5376`); the gateway's configured key |
| `root_before_revocation` | tree with Alice (leaf 0), Bob (1), Carol (2): `9711...0430` (= vectors `tree.root`) |
| `root_after_bob_revoked` | same tree after `delete(1)`: `6411...6342` |
| `gateway_now` | `1794128400` (2026-11-08T09:00:00Z, the vectors' clock) |
| `epoch` | `2990214` = `floor(gateway_now / 600)` |
| `nonce_ttl_seconds` | `120` (obligation 5 skew bound) |

Each fixture's `gateway_state` (`current_root`, `now`, `epoch`) is the state the gateway must be in
for the expected decision; for everything except `stale_root_bob_wiki` it is
`root_before_revocation` / `gateway_now` / `epoch`. Treat each fixture's `nonce` as issued by the
gateway with a challenge `{nonce, resourceId, epoch, now, policy}` equal to its public signals
(obligation 5), except where the attack says otherwise. **Use fresh nonce and nullifier state per
scenario**: the nullifier is `Poseidon(3)(credentialSecret, resourceId, epoch)`, independent of
nonce, `now`'s seconds within the epoch and issuer key, so every Alice -> Wiki fixture in epoch
`2990214` (alice_wiki, forged_issuer, same_epoch_a/b, wrong_service) shares one nullifier, and
`bob_wiki` and `stale_root_bob_wiki` share another.

## Valid: the gateway must accept (all obligations pass)

| Fixture | Persona -> resource (`resourceId`) | Policy `(roleMask, deptMask, minClearance, requireDevice)` | Note |
|---|---|---|---|
| `alice_wiki` | Alice (engineer, engineering, c2) -> Wiki (1) | `(15, 15, 0, 1)` | nonce = vector nonce 0; `public.json` = `circuits/test/vectors/v4/input.alice.wiki.json` `expectedPublicSignals` |
| `alice_file_share` | Alice -> File Share (2) | `(3, 15, 2, 0)` | nullifier differs from `alice_wiki` (unlinkable across services, floor 5) |
| `carol_admin_panel` | Carol (admin, it, c3) -> Admin Panel (3) | `(2, 15, 3, 1)` | |
| `carol_wiki` | Carol -> Wiki (1) | `(15, 15, 0, 1)` | |
| `bob_wiki` | Bob (contractor, operations, c1) -> Wiki (1) | `(15, 15, 0, 1)` | before Bob is revoked |

## Attacks: valid proofs the gateway must deny

| Fixture | Attack | Gateway obligation that denies it | Floor |
|---|---|---|---|
| *replay* (reuse `alice_wiki`) | present `alice_wiki` a second time | obligation 6: `nonce` single-use and unexpired (marked used on admission) | 4 |
| `stale_root_bob_wiki` | Bob -> Wiki proved against `root_before_revocation`; Bob has since been revoked, `gateway_state.current_root` = `root_after_bob_revoked` | obligation 3: `root` is current (the superseded root never re-admits a revoked leaf). Bob cannot prove against the new root at all. The valid fixtures are also stale once the root moves: set the gateway's root per scenario. | 3 |
| `forged_issuer_alice_wiki` | Alice's attrHash self-signed by the TEST-ONLY forger key (vectors `forged`), real root and path | obligation 2: `issuerAx/issuerAy` = `context.pinned_issuer`. The circuit accepts any key it is given; this pin is the only defence. | 2 |
| `stale_now_alice_wiki` | Alice -> Wiki with `now` 90 days before `gateway_now` (`1786352400`) and its own `epoch` `2977254`; the credential was unexpired then | obligation 5: `now`/`epoch` must equal the challenge stored with the nonce (skew bound 120 s). Otherwise an old `now` revives an expired credential. | 2 |
| `same_epoch_a` then `same_epoch_b` | Alice -> Wiki twice in one epoch with two different fresh nonces: **equal nullifiers** | obligation 7: `(nullifier, epoch)` at most once. Accept `same_epoch_a` (`expect: accept`), deny `same_epoch_b` (`present_after: ["same_epoch_a"]`) as rate-limited. | 5 |
| `wrong_service_alice_wiki_as_admin` | a valid Alice -> Wiki proof presented on a request for Admin Panel (`presented_to: admin_panel`) | obligation 4: policy fields and `resourceId` equal the requested service's (`resourceId` 1 != 3, `roleMask` 15 != 2, `minClearance` 0 != 3) | 2 |

Not fixtures:

- **Forged signature under the pinned key**: no proof exists (witness generation fails in the
  in-circuit EdDSA verifier; `circuits/test/v4.test.js`). Its gateway-level form is
  `forged_issuer_alice_wiki`.
- **Tampered public signal** (any of the 12 changed after proving): `verify()` returns `false`
  (`circuits/test/setup_v4.test.js` tests each one). Make it in a test by editing one element of a
  `public.json`.
- **Non-canonical spelling** (`"0" + nonce`, `nonce + p`, whitespace, hex): `verify()` returns
  `false` though stock snarkjs accepts leading zeros. Key replay state on the canonical `nonce` and
  rate-limit state on the canonical `(nullifier, epoch)`, never on proof bytes: `(-A, -B, C)` is a
  second valid encoding of the same proof.

## Gateway notes

- `require("circuits/scripts/verify.js").verify(vkey, publicSignals, proof)` -> `true | false`,
  never throws. Default implementation: `circuits/scripts/fast-verify.js` (one verifier cached per
  vkey content; keep the process long-lived and call `terminate()` only at shutdown).
  `ZKGATE_VERIFY_IMPL=snarkjs` selects stock snarkjs with the same input rules and point checks.
  Numbers: `circuits/reports/perf-v4.md`.
- Stricter than stock snarkjs on proofs: `false` for coordinates >= q or with leading zeros, a point
  at infinity, or a `pi_b` outside G2. Every committed `proof.json` and every `fullProve` output
  passes.
- The gateway (Python, P3) implements obligations 2-8 from the contract. `circuits/lib`
  `decodePublicSignals("v4", arr)` is the reference parser.

## Regenerate

```sh
npm run prove:fixtures:v4   # proves with circuits/setup/integrated_access_v4.{wasm,zkey}
```

The script refuses (exit 2, nothing written) unless the committed zkey, wasm and vkey hash to
`circuits/setup/integrated_access_v4.manifest.json`. Proofs are randomised, so every run rewrites
all `proof.json` files; `public.json` and `fixtures.json` are deterministic. When the keys change
(G2-S1-CIRC-040 ceremony), regenerate in the same commit as the new zkey, wasm, vkey and manifest
(`circuits/setup/ARTIFACTS.md`).
