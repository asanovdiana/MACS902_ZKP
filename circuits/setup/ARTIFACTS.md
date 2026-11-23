# Committed proving artefacts (decision D7)

The proving key and witness generator that match a committed verification key are **committed**,
so a fresh clone can prove without re-running the trusted setup (which would make a new key that
nothing pinned verifies under).

## `integrated_access_v3` (G0-S1-CIRC-022; re-keyed G2-S1-CIRC-040a, DEMO-ONLY)

| File | Size | sha256 (= manifest field) |
|---|---|---|
| `circuits/setup/integrated_access_v3.zkey` | 3,119,484 B (3.0 MiB) | `63ad81765d29341d29d4003cba088ce72bf957161ebacf3a098a43aa4b76993e` (`zkey_sha256`) |
| `circuits/setup/integrated_access_v3.wasm` | 2,595,113 B (2.5 MiB) | `8946d02cf67032ab08a85433d1b9f386ad16dbc94b7a8890603925f936055913` (`wasm_sha256`) |
| `circuits/setup/integrated_access_v3.verification_key.json` | 2,929 B | `de0917988611f85d3700cfe8419e8ffc578738c3079d9c062b98f6ddf869b5ae` (`verification_key_sha256`) |
| `circuits/setup/integrated_access_v3.manifest.json` | 2,505 B | (provenance; holds the three hashes above) |

All four come from one `setup.sh` run; the zkey and wasm were copied byte for byte from that run's
`build/integrated_access_v3/`. The manifest's `status` is `DEV-ONLY` and its `status_detail` is
`DEMO-ONLY (single-party phase 2) ...`. The wasm is byte-identical to the previous commit (same
circuit); the zkey and vkey are new. v3 has no committed proof fixtures.

## `integrated_access_v4` (G1-S1-CIRC-037, ADR 0009; re-keyed G2-S1-CIRC-040a; ceremony keys G2-S1-FINAL-001, DEMO-ONLY)

The product key: depth 16, 9208 constraints at `--O2`, 12 public signals in
`access.public_signals v4` order. First committed with a DEV-ONLY phase 1 (G1-S1-CIRC-037); re-keyed on
PSE ppot 0080 in G2-S1-CIRC-040a, in one commit with its fixtures. Re-keyed again in
G2-S1-FINAL-001 from the **simulated** 3-party phase-2 ceremony (`npm run ceremony:install --
integrated_access_v4`, same commit as the regenerated fixtures). The r1cs (`r1cs_sha256`
`652dae08...`) and the wasm are byte-identical to G2-S1-CIRC-040a; the zkey (the ceremony's
`integrated_access_v4_final.zkey`), vkey and manifest are new.

**Simulated, not a real multi-party ceremony.** The three contributions were made by separate AI
agent processes on **one machine under one operator**, closed by the public drand mainnet beacon
round 6667474 announced in advance. Whoever controlled that machine could in principle have kept
every contribution's randomness, so the multi-party trust guarantee does **not** hold: the key is
**DEMO-ONLY, not for production**. Record: [`docs/ceremony/v4-ceremony-log.md`](../../docs/ceremony/v4-ceremony-log.md);
transcript `circuits/ceremony/integrated_access_v4/transcript.json` (sha256 = manifest
`phase2.transcript_sha256`).

| File | Size | sha256 (= manifest field) |
|---|---|---|
| `circuits/setup/integrated_access_v4.zkey` | 6,111,048 B (5.8 MiB) | `73f527f371539c34b4507f6f2c395fd9be2f0c2df53fd5af9df2caa8749d85e3` (`zkey_sha256`) |
| `circuits/setup/integrated_access_v4.wasm` | 4,161,091 B (4.0 MiB) | `b6651dd53459fe72ae8bc4483385868500d55012a7f5f5418fee8dc8af49770b` (`wasm_sha256`) |
| `circuits/setup/integrated_access_v4.verification_key.json` | 4,937 B | `c5490c184298b14dd5cc8882a351e68b1e5983d54e10fa5c68acb3c7927ae059` (`verification_key_sha256`) |
| `circuits/setup/integrated_access_v4.manifest.json` | 4,553 B | (provenance; holds the three hashes above, `public_signals`, the 3 contributors, the drand beacon and the transcript sha256) |

Bound to this key, regenerated with it: `circuits/fixtures/v4/` (`npm run prove:fixtures:v4`;
`fixtures.json` records `zkey_sha256` and `verification_key_sha256`; the script refuses to prove
with a pair whose hashes differ from the manifest).

## DEMO-ONLY keys

Since G2-S1-CIRC-040a, phase 1 of both keys is **PSE Perpetual Powers of Tau, contribution 0080,
prepared for phase 2** (`ppot_0080_15.ptau`, manifest `ptau.source` = `pse-ppot-0080`, blake2b-512
`a6dd3adc...7f24` pinned on first download; provenance in [`README.md`](README.md) *Phase 1*). The
Hermez files the keys were meant to use are no longer downloadable; before this re-key, phase 1
was the local `pot15_DEV-ONLY_final.ptau`.

**v3** phase 2 is still **single-party** (one urandom contribution + a local beacon;
[`README.md`](README.md), *Limitations*): **whoever ran setup could forge proofs**. Its manifest keeps
`status: "DEV-ONLY"` and says `status_detail: "DEMO-ONLY (single-party phase 2) ..."`.

**v4** phase 2 is the simulated 3-party ceremony above: manifest `status: "DEMO-ONLY"`, 3
contributors in `phase2.contributors`, public beacon. Because all three contributions ran on one
machine under one operator, that is no stronger in practice than a single party: **whoever ran the
machine could forge proofs**.

Both keys: tests and demos only, **not for production**; for any real use re-run the ceremony with
independent people each contributing on their own machine. `tests/safety` F9.12 checks that each
manifest's status matches its provenance.
Committing the zkey does not weaken them further: a Groth16 proving key is public by design; the
secret is the toxic waste, which is in no file.

## How the client uses the pair

In-process, with no input or witness file on disk (floor: private inputs never leave the client):

```js
const snarkjs = require("snarkjs");
const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  input,                                               // built in memory by the client
  "circuits/setup/integrated_access_v3.wasm",
  "circuits/setup/integrated_access_v3.zkey",
);
// publicSignals = [root]  (manifest.public_signals)
```

v4 is the same with `integrated_access_v4.{wasm,zkey}` and an input from `circuits/lib`
`buildInputV4` (client) — `publicSignals` is the 12-element `access.public_signals v4` array.
`client/src/prover.js` already resolves these names (`zk.profiles.v4.artefacts.name`) under
`circuits/setup/`.

Self-check or gateway side: `require("circuits/scripts/verify.js").verify(vkey, publicSignals, proof)`
with `vkey` = `circuits/setup/integrated_access_v3.verification_key.json`.

Docker images can `COPY` the pair from the build context; no setup step in the image.

Shell tools:

```sh
circuits/scripts/artifacts.sh check   <name>   # sha256 vs manifest + exported vkey == committed vkey
circuits/scripts/artifacts.sh install <name>   # check, then copy to build/<name>/
npm run artifacts:check            # both pairs (v3, v4); artifacts:check:v3 / artifacts:check:v4 for one
npm run artifacts:install          # both; artifacts:install:v3 / artifacts:install:v4 for one
```

`check` exits 1 on any mismatch and never modifies anything; `install` copies nothing if `check`
fails. `install` produces the layout `setup.sh` leaves, which `prove.sh` reads.

## Re-keying

All in **one commit** (`<name>` = `integrated_access_v3` or `integrated_access_v4`).

### Multi-party (the way to replace a DEMO-ONLY key)

Run the phase-2 ceremony in [`circuits/ceremony/README.md`](../ceremony/README.md): each teammate
contributes on their own machine (`circuits/scripts/ceremony.sh init | contribute | verify |
finalize`, `npm run ceremony:*`), closed by a beacon announced in advance. Then, in one commit:

1. `circuits/scripts/ceremony.sh install <name>` (`npm run ceremony:install -- <name>`): hash
   checks, then copies `circuits/setup/<name>.{zkey,wasm,verification_key.json,manifest.json}` and
   `build/<name>/`, then runs `artifacts.sh check <name>`. Copies nothing if a hash check fails.
2. Steps 4-6 below (sizes/hashes here, `npm run prove:fixtures:v4`, tests, one `git commit --only`),
   adding `circuits/ceremony/<name>/{transcript.json,<name>.verification_key.json,<name>.manifest.json}`.
   The ceremony manifest is no longer single-party: `tests/safety` F9.06 and the single-party
   assertions in `circuits/test/setup*.test.js` / `fixtures_v4.test.js` change with it (README,
   "Tests that change with the install"); `safety` signs off before the commit.

### Single-party (rehearsals, a changed circuit before its ceremony)

1. `PTAU_SOURCE=pse circuits/scripts/setup.sh circuits/<name>.circom <name>` (`npm run setup:v3` /
   `setup:v4`, which set `PTAU_SOURCE=pse`; writes `build/<name>/*` and `circuits/setup/<name>.{verification_key,manifest}.json`).
2. `cp build/<name>/<name>.zkey build/<name>/<name>.wasm circuits/setup/`
3. `circuits/scripts/artifacts.sh check <name>`: must pass.
4. Update the sizes and hashes in this file; regenerate the committed proof fixtures for this key
   (v4: `npm run prove:fixtures:v4`, which rewrites `circuits/fixtures/v4/`).
5. Run the tests (`circuits/test/setup.test.js`, `setup_v4.test.js`, `fixtures_v4.test.js`,
   `fast_verify.test.js` and the rest of the suite).
6. `git add` the zkey, wasm, vkey, manifest, this file and any fixtures, then
   `git commit --only <same paths>`.

## The rule

**Never commit a zkey without its matching vkey and manifest in the same commit** (and never a new
vkey without its zkey/wasm). A mismatched pair means every proof the client makes is rejected.
`circuits/test/setup.test.js` fails on any mismatch: hashes vs the manifest, the vkey exported from
the zkey vs the committed vkey, and a fresh TEST-ONLY proof verified under the committed vkey.

Only the pairs named in `circuits/setup/.gitignore` (`!integrated_access_v3.{zkey,wasm}`,
`!integrated_access_v4.{zkey,wasm}`, one line each) are exempt; every other `*.zkey` stays ignored
(root `.gitignore` and `circuits/setup/.gitignore`) and every other `*.wasm` under
`circuits/setup/` too (`setup_v4.test.js` checks both directions). `circuits/.gitattributes` marks `*.zkey` /
`*.wasm` binary (no text diff). Check a rule with `git check-ignore --no-index -v <one path>`.
