# circuits

M3, the access circuit of ZK Access Gate, and everything around it: the Circom sources, the shared
encoder that issuer and client import, the trusted-setup scripts, the committed **DEMO-ONLY** proving
artefacts, Groth16 proof fixtures for the gateway, the circuit tests and the floor-1 mutation
harness. Owner: the `circuits` role. Overview of the whole repository: [`../README.md`](../README.md).

Two circuits live here side by side:

- **v3** (`integrated_access_v3.circom`): P1's circuit, imported from `feature/p1-circuits-hamsa`
  and **kept unchanged** as the base ([ADR 0002](../docs/adr/0002-adopt-p1-v3-circuit-as-base.md)).
  It has known gaps and is a pipeline baseline only.
- **v4** (`integrated_access_v4.circom`): the scope's statement. It reuses her components where it
  can and adds six new ones beside them; it never edits her files.

The authoritative interface is [`docs/CONTRACTS.md`](../docs/CONTRACTS.md): `credential v3`,
`access.public_signals v3`, `credential v4`, `access.public_signals v4` (signal order and gateway
obligations 1-8). The report chapter [`docs/report/circuit.md`](../docs/report/circuit.md) explains
the design in prose.

## Layout

| Path | What |
|---|---|
| `integrated_access_v3.circom` | P1's main `IntegratedAccessGate()`; public signal `[root]` only |
| `integrated_access_v4.circom` | **the product main**: `IntegratedAccessGateV4(16)`, 12 public signals |
| `integrated_access_v4_d8.circom`, `integrated_access_v4_d20.circom` | depth 8 / 20 mains for the M8 depth sweep; benchmark only, not keyed, not served |
| [`components/`](components/) | templates: her v3 components (below) and the v4 gate + six v4 components |
| [`lib/`](lib/) | the shared encoder (ADR 0004): Poseidon, EdDSA, Merkle tree, enums, policies, input builders, public-signal codec. Imported by `issuer/` and `client/`. [`lib/README.md`](lib/README.md) |
| [`scripts/`](scripts/) | setup, prove, verify, artefact check, fixture generation, vectors, perf, mutation harness (table under *npm scripts*) |
| [`setup/`](setup/) | committed DEMO-ONLY artefacts (PSE ppot 0080 phase 1, single-party phase 2) per circuit: `<name>.{zkey,wasm,verification_key.json,manifest.json}` for `integrated_access_v3` and `integrated_access_v4`. [`setup/README.md`](setup/README.md), [`setup/ARTIFACTS.md`](setup/ARTIFACTS.md) |
| [`fixtures/v4/`](fixtures/v4/) | 11 real v4 proofs (5 valid, 6 attack scenarios) + `fixtures.json` + a copy of the v4 vkey, for gateway, client, qa, safety and the Attack Lab. TEST-ONLY. [`fixtures/v4/README.md`](fixtures/v4/README.md) |
| [`reports/`](reports/) | generated, committed: [`mutation-v4.md`](reports/mutation-v4.md) (+ `.json`), [`perf-v4.md`](reports/perf-v4.md) (+ `.json`) |
| `test/*.test.js` | the mocha suites (one per component, v3, v4, lib, setup v3/v4, fixtures, fast verifier, mutation harness) |
| `test/helpers.js`, `test/setup.js`, `test/fixtures.js` | cached circom_tester builds, R1CS info, `NamedWitness` editor; mocha bootstrap (PATH + circom 2.2.3 check); TEST-ONLY v3 inputs built in memory |
| `test/circuits/` | TEST-ONLY mains that instantiate one component each (policy, attribute hash, challenge binding, expiry, signature points, signed attributes, her `IssuerSignatureCheck`, `MerkleMembershipN` at depth 2/4/16, her depth-2 `MerkleMembership` as reference) |
| `test/vectors/{v3,v4}/` | TEST-ONLY vectors (`credentials.json`, `poseidon.json`, `input.alice.json` / `input.alice.wiki.json`) written by `node circuits/scripts/gen-vectors.js`; never hand-edited |
| `test/fixtures/mutate/` | toy circuits and specs for the harness's own tests (never run by `npm test` directly) |
| `.gitattributes` | `*.zkey`, `*.wasm`, `*.ptau` binary |

Build output goes to `build/` at the repository root (gitignored): `build/test/<name>/` for test
builds, `build/<name>/` for setup and `prove.sh`.

## v3: P1's circuit (kept unchanged)

Her files have not changed since the import; new behaviour goes into new files.

| File | What |
|---|---|
| `integrated_access_v3.circom` | `IntegratedAccessGate()`: commitment `Poseidon(2)(secret, salt)`, issuer signature, depth-2 membership, File Share policy; public `[root]` |
| `components/access_policy.circom` | `FileShareAccess`: `role ∈ {2,3}`, `clearance ∈ {2,3}`, `deviceCompliant = 1`, `employeeActive = 1` (numbers opaque, see [`lib/README.md`](lib/README.md) *The v3 File Share quirk*) |
| `components/eddsa_verifier.circom` | `IssuerSignatureCheck`: circomlib `EdDSAPoseidonVerifier` over `M`, `enabled = 1`. **Reused unchanged by v4.** |
| `components/merkle_membership.circom` | `MerkleMembership`: depth-2 Poseidon(2) tree; `pathIndices[i] = 1` means the running node is the right child; indices boolean-constrained |
| `components/integrated_access.circom` | Removed obsolete two-line fragment during P1 cleanup; it was not used by circuit builds or tests. |

Constraint counts (circom 2.2.3, circomlib 2.0.5; asserted by `test/v3.test.js`):

| level | non-linear | linear |
|---|---|---|
| `--O0` | 8133 | 15456 |
| `--O1` (circom default) | 8116 | 1529 |
| `--O2` (setup level) | **4935** | 0 |

R1CS: 1 public input (`root`), 0 outputs, 17 private inputs.

**Known gaps** (full list G-1 … G-10 in [`docs/plan/p2-plan.md`](../docs/plan/p2-plan.md) §1; v4
closes G-1 … G-8):

- G-1: attributes are not in the signed message or the leaf, so a holder can claim any role.
- G-2: the issuer key `Ax, Ay` is a private input, so a self-signed credential verifies.
- G-3 policy hard-coded to File Share; G-4 no expiry; G-5 depth 2; G-6 no nonce, resource,
  epoch or nullifier (a v3 proof is replayable); G-7 no `dept`; G-8 no attribute range checks.
- G-9 the broken fragment above; G-10 a random issuer key per generator run (P1's
  `scripts/generate_integrated_v3.js`, not used by the tests).

`test/v3.test.js` pins what v3 does: layout, counts, positives, input-level negatives, and one
witness-level tamper per constraint and per `<==` link (each violates **exactly one** R1CS row).
G-1 and G-2 are tests titled `GAP G-n (v3 only, closed in v4 ...)` that assert the **insecure**
behaviour and pass on purpose; the closing negatives live in `test/v4.test.js`. The main template's
two booleanity checks on `deviceCompliant` / `employeeActive` are equivalent mutants (implied by
`FileShareAccess`'s `=== 1`); a documentation test makes their removal visible.

## v4: the access circuit

Statement: the prover knows a secret, salt, attributes, issuer signature and Merkle path such that
the attribute hash is signed by the **public** issuer key, is a leaf of the tree with the **public**
root, satisfies the **public** policy, has not expired at the public `now`, and the nullifier is
`Poseidon(3)(secret, resourceId, epoch)`. Contracts `credential v4`, `access.public_signals v4`;
ADR [0005](../docs/adr/0005-commitment-with-salt-nullifier-from-secret.md),
[0006](../docs/adr/0006-v4-attribute-hash.md),
[0007](../docs/adr/0007-v4-public-signals-and-employee-active.md),
[0008](../docs/adr/0008-role-and-dept-enums.md),
[0009](../docs/adr/0009-commit-v4-proving-artefacts.md).

| File | What |
|---|---|
| `integrated_access_v4.circom` | `component main {public [...]} = IntegratedAccessGateV4(16)`; the only v4 main that is keyed |
| `integrated_access_v4_d8.circom`, `_d20.circom` | the same at depth 8 / 20, benchmark only |
| `components/integrated_access_v4_gate.circom` | template `IntegratedAccessGateV4(depth)`: wiring only (no `<--`, no `===`). A separate file because circom refuses to include a file that declares `component main`. |
| `components/attribute_hash.circom` | `AttributeHash`: `attrHash = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry, commitment)`, used as both signed `M` and leaf; role/dept/clearance 2-bit, flags boolean (closes G-1, G-7) |
| `components/issuer_key.circom` | `SignaturePointsOnCurve`: issuer key and R8 on BabyJubJub (`BabyCheck`); with the key public, closes G-2 |
| `components/merkle_membership_n.circom` | `MerkleMembershipN(depth)`: her `MerkleMembership` body with the depth as a parameter; `MerkleMembershipN(2)` compiles to her R1CS (closes G-5) |
| `components/access_policy_v4.circom` | `AccessPolicyV4`: role/dept mask bits, `clearance >= minClearance`, device if required, `employeeActive === 1` (closes G-3, G-8) |
| `components/expiry.circom` | `ExpiryCheck`: both sides 64-bit range-checked, `now < expiry` strictly (closes G-4) |
| `components/challenge_binding.circom` | `ChallengeBinding`: `nullifier = Poseidon(3)(secret, resourceId, epoch)`, `nonceSquared <== nonce * nonce` (closes G-6) |
| `components/eddsa_verifier.circom` | her `IssuerSignatureCheck`, unchanged, wired with `Ax, Ay = issuerAx, issuerAy` and `M = attrHash` |

**Signals** (names as compiled; `lib` `buildInputV4` emits the inputs in this order):

- private (43): `credentialSecret, credentialSalt, role, dept, clearance, deviceCompliant,
  employeeActive, expiry, R8x, R8y, S, pathElements[16], pathIndices[16]`. No `M`, `leaf`, `Ax` or
  `Ay` input.
- public signals in `access.public_signals v4` order (snarkjs: output first, then public inputs in
  **declaration** order; `test/v4.test.js` asserts it from the `.sym` file, witness slot = public
  slot + 1):

  | slot | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
  |---|---|---|---|---|---|---|---|---|---|---|---|---|
  | name | `nullifier` | `root` | `issuerAx` | `issuerAy` | `roleMask` | `deptMask` | `minClearance` | `requireDevice` | `now` | `nonce` | `resourceId` | `epoch` |

**Constraint counts** (non-linear + linear; circom 2.2.3, circomlib 2.0.5; asserted by
`test/v4.test.js`; R1CS 11 public inputs, 1 output, 43 private inputs):

| depth | `--O0` | `--O1` (default) | `--O2` (setup level) |
|---|---|---|---|
| 8 | 10490 + 20801 | 10474 + 4231 | 7264 + 0 |
| **16** | 12458 + 25017 | 12442 + 6423 | **9208 + 0** |
| 20 | 13442 + 27125 | 13426 + 7519 | 10180 + 0 |

At `--O1`/`--O2` `main.employeeActive` is folded to the constant 1 (the policy's
`employeeActive === 1`), so the R1CS has 42 private wires for 43 private inputs.

**What `test/v4.test.js` checks**: layout and counts above; positives at O1 and O2 (the Alice ->
Wiki vector with exactly its expected public signals, the 9 persona x policy verdicts of the
contract, a stable nullifier under a fresh nonce, unlinkable nullifiers across resources and
epochs); lib parity at O0 (commitment, `attrHash`, root, nullifier equal `circuits/lib`);
input-level negatives (each of the 7 `attrHash` inputs tampered under the original signature,
self-signed under the pinned key, off-curve key/R8, revoked, wrong/stale root, expired incl.
`now == expiry`, each policy denial, out-of-range fields); each of the 12 public signals changed
after witness generation; and one witness-level tamper per `<==` line of the gate, each violating
exactly one R1CS row. The per-component suites (`attribute_hash`, `issuer_key`, `merkle_depth`,
`policy_v4`, `expiry`, `challenge_binding`) do the same for each component.

## Toolchain

| | |
|---|---|
| circom | **2.2.3** exactly (`pragma circom 2.2.3`; does not compile on 2.2.2). `cargo install --git https://github.com/iden3/circom.git --tag v2.2.3 circom`; it lands in `~/.cargo/bin`. |
| npm | `npm ci` at the **repository root**. The root `package.json` is the circuits' npm project (circomlib 2.0.5, circom_tester, snarkjs 0.7.6, circomlibjs 0.1.7, `@zk-kit/incremental-merkle-tree` 1.1.0, mocha); the circuits include `../node_modules/circomlib/...` by relative path. |
| tests | mocha + circom_tester; config in the root `.mocharc.json` (spec `circuits/test/**/*.test.js`, require `circuits/test/setup.js`, timeout 600 s) |

`circuits/test/setup.js` prepends `~/.cargo/bin` to `PATH` and aborts with an install hint if
`circom --version` is not 2.2.3: the constraint counts the suites assert hold only for that
compiler. The shell scripts in `scripts/` put `~/.cargo/bin` on `PATH` themselves. circom is needed
only to compile circuits and run circuit tests; proving and verifying use the committed artefacts.

## npm scripts

All from the repository root.

| Script | What |
|---|---|
| `npm test` | mocha over `circuits/test/**/*.test.js` (the circuits tier; `test:all` adds issuer, client, Attack Lab and safety) |
| `npm run setup:v3`, `npm run setup:v4` | `scripts/setup.sh` for the v3 / v4 main: compile at `--O2`, phase 1, phase 2, verify, export vkey, manifest. **Re-keys**: new zkey and vkey every run; follow [`setup/ARTIFACTS.md`](setup/ARTIFACTS.md) *Re-keying* |
| `npm run artifacts:check` (`:v3`, `:v4`) | committed zkey/wasm/vkey hashes equal the manifest and the vkey exported from the zkey equals the committed vkey; never modifies anything |
| `npm run artifacts:install` (`:v3`, `:v4`) | `check`, then copy the pair to `build/<name>/` for `prove.sh` |
| `npm run prove:fixtures:v4` | `scripts/access-fixtures.js`: regenerate `fixtures/v4/` from the committed v4 pair (refuses if hashes differ from the manifest); `-- --out <dir>` writes elsewhere |
| `npm run perf:v4` | `scripts/perf-v4.js`: prove/verify timings into `reports/perf-v4.{md,json}`; `-- --prove-runs N --verify-runs N --warmup N --out-dir <dir>` |
| `npm run mutate:v4` | floor-1 mutation sweep over the v4 main, gate and the components it includes -> `reports/mutation-v4.{md,json}` (long; see [`scripts/MUTATION.md`](scripts/MUTATION.md)) |
| `npm run audit:arrows` | every `<--`/`-->` in project circuits (mains, components, test mains) is followed by an `===` in its template |

Script entry points without an npm alias: `scripts/prove.sh <name> <input.json> <outdir>`,
`scripts/verify.sh <name|vkey.json> <proof.json> <public.json>` (exit 0 valid, 1 invalid),
`scripts/artifacts.sh check|install <name>`, `node circuits/scripts/gen-vectors.js [--check]`.

## How to test

```sh
npm ci                     # at the repo root
npm test                   # every circuits suite; first run compiles into build/test/ (minutes)
SKIP_SETUP=1 npm test      # skips setup.test.js and setup_v4.test.js (Groth16 proving)
npx mocha --no-config --require circuits/test/setup.js --timeout 600000 circuits/test/v4.test.js
```

Use `--no-config` for a single file: with the root `.mocharc.json` loaded, mocha merges its spec
glob with the file you name and runs everything. Test builds are cached in `build/test/<name>/`
and recompiled only when sources, circomlib, compiler version or options change (`stamp.txt`);
delete `build/test/` to force a rebuild. `node circuits/scripts/gen-vectors.js --check` exits 0
only when the committed vectors are current.

## Floor 1 evidence

Floor 1: every constraint has a negative test that fails when it is removed, and every `<--` is
followed by an `===` that checks it.

- **Mutation sweep**: [`reports/mutation-v4.md`](reports/mutation-v4.md) records **102 mutants, 102
  killed, 0 survived**, 0 compile errors, 0 equivalent, 0 timeouts, 0 errors (baseline: 350 tests
  pass), over the v4 main, the gate and seven components (the six v4 components plus her
  `eddsa_verifier.circom`). Each kill names the test that earned it; static tests (layout, counts)
  are forbidden as killers. `test/mutate.test.js` fails if the committed report is stale or records
  a survivor. Method: [`scripts/MUTATION.md`](scripts/MUTATION.md).
- **Arrow audit**: `npm run audit:arrows` prints `arrow audit: 26 file(s), 0 <--/--> statement(s),
  0 violation(s)`: no project circuit uses `<--` at all. Independently confirmed in
  [`docs/security/review-G1-P2.md`](../docs/security/review-G1-P2.md) (F1.05, F1.06).
- **v3** is not mutated; `test/v3.test.js` carries one exactly-one-row tamper test per constraint
  and `<==` link of her circuit and components.

## How identity and gateway consume it

- **Encoder.** `issuer/` and `client/` `require` [`lib/`](lib/README.md) for every
  circuit-facing value (commitment, `attrHash`, signature, tree, input builder, public-signal
  codec); they do not re-implement any of it (ADR 0004, floor 8). The vectors in
  `test/vectors/*/poseidon.json` pin the Poseidon parameters for the cross-check.
- **Proving.** The client proves in-process with `snarkjs.groth16.fullProve(input,
  "circuits/setup/integrated_access_v4.wasm", "circuits/setup/integrated_access_v4.zkey")`, the
  input built in memory by `buildInputV4`; no input or witness file is written (floor 6).
- **Verifying.** `require("circuits/scripts/verify.js").verify(vkey, publicSignals, proof)` returns
  `true`/`false` and never throws. Default implementation: the fast verifier
  `scripts/fast-verify.js` (one verifier cached per vkey; median 5.61 ms warm in
  [`reports/perf-v4.md`](reports/perf-v4.md)). `ZKGATE_VERIFY_IMPL=snarkjs` selects stock snarkjs
  with the same canonical-input rules and point checks (median 15.48 ms, an escape hatch only).
  Call `terminate()` only at shutdown. Verification is the cryptographic half (gateway obligation
  1); the gateway must still enforce obligations 2-8 of `access.public_signals v4`.
- **Committed artefacts.** `setup/integrated_access_v{3,4}.{zkey,wasm,verification_key.json,manifest.json}`
  are committed so a fresh clone proves and verifies without re-running setup (ADR 0009); hashes
  and sizes in [`setup/ARTIFACTS.md`](setup/ARTIFACTS.md).
- **Fixtures.** [`fixtures/v4/`](fixtures/v4/README.md): valid and attack proofs under the
  committed v4 key, each with the gateway state and obligation that decides it.

## DEMO-ONLY keys and the ceremony

Both committed keys are **DEMO-ONLY (single-party phase 2)**; their manifests keep
`status: "DEV-ONLY"` as the machine-checked label. Since G2-S1-CIRC-040a phase 1 is the public
PSE Perpetual Powers of Tau, contribution 0080, prepared for phase 2 (`ppot_0080_15.ptau`; the
Hermez files are no longer downloadable; provenance in [`setup/README.md`](setup/README.md)
*Phase 1*). Phase 2 still has a single contributor, so **whoever ran setup could forge proofs**.
Fine for tests and the demo, never for real use (finding SR-06). The multi-party phase 2 is
G2-S1-CIRC-040; when it lands the zkey, wasm, vkey, manifest and `fixtures/v4/` are replaced in one
commit ([`setup/README.md`](setup/README.md) *Limitations*,
[`setup/ARTIFACTS.md`](setup/ARTIFACTS.md) *Re-keying*).

## Further reading

| Doc | What |
|---|---|
| [`lib/README.md`](lib/README.md) | shared encoder API, profiles, input signal names, error codes, floor notes, vectors |
| [`setup/README.md`](setup/README.md) | trusted setup: phase 1 (PSE ppot 0080; Hermez gone; dev fallback), phase 2, prove/verify scripts, v3 and v4 keys |
| [`setup/ARTIFACTS.md`](setup/ARTIFACTS.md) | committed proving pairs, sizes and hashes, re-keying, the commit rule |
| [`fixtures/v4/README.md`](fixtures/v4/README.md) | v4 proof fixtures and the gateway obligation each one exercises |
| [`scripts/MUTATION.md`](scripts/MUTATION.md) | mutation harness and arrow audit |
| [`reports/mutation-v4.md`](reports/mutation-v4.md) | generated floor-1 mutation report |
| [`reports/perf-v4.md`](reports/perf-v4.md) | generated prove/verify performance report |
| [`docs/CONTRACTS.md`](../docs/CONTRACTS.md) | interface contracts (authoritative) |
| [`docs/report/circuit.md`](../docs/report/circuit.md) | report chapter: the access circuit |
| [`docs/plan/p2-plan.md`](../docs/plan/p2-plan.md) | P2 plan, v3 gap list (§1) |
