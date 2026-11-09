# circuits/lib — the shared encoder

The only place that encodes circuit-facing values (ADR 0004). `issuer/` and `client/` import it;
they do not re-implement any of it. The authoritative spec is `docs/CONTRACTS.md` (Common rules,
`credential v3`, `access.public_signals v3`, `credential v4`, `access.public_signals v4`); this
library is its implementation. Tasks: G0-S1-CIRC-021 (profile `v3`), G1-S1-CIRC-038 (profile `v4`).

CommonJS. Depends only on `circomlibjs` 0.1.7 and `@zk-kit/incremental-merkle-tree` 1.1.0 (pinned
exactly). No I/O, no network, no key storage: the issuer passes its private key in per call.

```js
const zk = require("../circuits/lib"); // path relative to your module
```

## API

Every field value the library returns is a **canonical decimal string** (`^(0|[1-9][0-9]*)$`,
`< p`). Inputs accept canonical decimal strings, `bigint` and safe non-negative integer `Number`s;
anything else (leading zeros, hex, signs, whitespace, `>= p`) throws. Nothing is reduced mod p.

| Area | Export | Notes |
|---|---|---|
| field | `P`, `L`, `TWO64` | BN254 scalar field, BabyJubJub subgroup order, 2^64 |
| | `isCanonical(s)`, `parseField(name, v, {stringsOnly})` → bigint, `formatField(v)` → string | |
| | `AccessInputError` (`.code`, `.message`, sometimes `.reasons`), `CODES` | codes below |
| crypto (async) | `poseidon([..])` | circomlibjs Poseidon(n), 1 ≤ n ≤ 16 |
| | `commitment(secret, salt)` | Poseidon(2) (ADR 0005) |
| | `attrHash(attributes, commitment)` | v4: Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry, commitment) |
| | `nullifier(secret, resourceId, epoch)` | v4: Poseidon(3) |
| | `publicKey(prv)` → `{Ax, Ay}`, `sign(prv, msg)` → `{R8x, R8y, S}` | `prv` = 32 raw bytes; issuer only |
| | `verifySignature(msg, {R8x,R8y,S}, {Ax,Ay})` → boolean | throws on malformed values (`S ≥ l`) |
| enums | `ROLES`, `DEPTS` | D6: engineer 0, admin 1, contractor 2, finance 3 / engineering 0, it 1, operations 2, finance 3 |
| | `policies.{wiki,file_share,admin_panel}` | `{name, label, resourceId, roleMask, deptMask, minClearance, requireDevice}` per contract |
| | `epochOf(unixSeconds)` | `floor(t / 600)` |
| pre-checks | `checkPolicyLocally(attrs, policy, now)` → `{ok, reasons: [{code, message}]}` | v4; policy = name or object |
| | `checkFileShareV3(attrs)` → same shape | v3 `FileShareAccess` |
| profiles | `profiles.v3`, `profiles.v4`, `getProfile(nameOrProfile)` | see below |
| tree | `createTree(profile)` (async) | zk-kit `IncrementalMerkleTree(h, depth, 0n, 2)` |
| | `proofFor(tree, index)` → `{leafIndex, leaf, root, pathElements, pathIndices}` | strings; `pathIndices` `"0"`/`"1"` |
| | `merkleRoot(leaf, pathElements, pathIndices)` (async) | the circuit's recomputation |
| inputs (client) | `buildInputV3(args, {precheck})`, `buildInputV4(args, {precheck})`, `buildInput(profile, args, opts)` | async; validate and fail fast |
| | `expectedPublicSignals(profile, input)` | the array a proof over `input` will carry |
| signals | `PUBLIC_SIGNALS.v3` = `["root"]`, `PUBLIC_SIGNALS.v4` (12) | |
| | `decodePublicSignals(profile, arr)` → `{name: string}`, `encodePublicSignals(profile, obj)` → array | decode is strings-only, exact length, ranged |

### Profiles

| | `v3` | `v4` |
|---|---|---|
| `depth` | 2 | 16 |
| `attributes` | `role, clearance, deviceCompliant, employeeActive` | `role, dept, clearance, deviceCompliant, employeeActive, expiry` |
| `message(cred)` / `leaf(cred)` (async, `cred = {commitment, attributes}`) | `commitment` | `attrHash(attributes, commitment)` |
| `publicSignals` | `["root"]` | `nullifier, root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch` |
| `artefacts` | `integrated_access_v3` (`.wasm` under `_js/`, `.zkey`, `.vkey.json`) | `integrated_access_v4` |

Artefact entries are file names only; their directory is fixed by G0-S1-CIRC-022 (v3) and
G1-S1-CIRC-037 (v4).

### Circuit input signal names

**v3** (`circuits/integrated_access_v3.circom`, exactly P1's names): `credentialSecret,
credentialSalt, role, clearance, deviceCompliant, employeeActive, Ax, Ay, R8x, R8y, S, M, leaf,
pathElements[2], pathIndices[2], root`. `M = leaf = commitment`.

**v4** (`credential v4`; the v4 circuit, G1-S1-CIRC-031…036, must declare these names):

- private: `credentialSecret, credentialSalt, role, dept, clearance, deviceCompliant,
  employeeActive, expiry, R8x, R8y, S, pathElements[16], pathIndices[16]`
- public, in this declaration order: `root, issuerAx, issuerAy, roleMask, deptMask, minClearance,
  requireDevice, now, nonce, resourceId, epoch`
- output: `nullifier`. `M` and `leaf` are not inputs (computed in-circuit as `attrHash`).

`buildInputV4` returns the keys in exactly that order.

### Builder arguments

```js
await zk.buildInputV4({
  credentialSecret, credentialSalt,     // from the credential file's `secrets`
  commitment,                           // optional; checked against Poseidon(2)(secret, salt)
  attributes,                           // issuer.api v1 attributes (role/dept may be D6 labels)
  signature: { R8x, R8y, S },
  issuer: { Ax, Ay },
  merkleProof,                          // GET /path/:leafIndex body, proofFor() or zk-kit createProof()
  policy: "wiki",                       // or {roleMask, deptMask, minClearance, requireDevice, resourceId?}
  challenge: { nonce, resourceId, epoch, now }, // exactly as the gateway issued it
});
```

`buildInputV3` takes the same arguments without `policy` and `challenge`. Order of checks:
strict schema and encodings → (with `precheck`, default on) v3 `FileShareAccess` / v4 epoch,
resource, expiry, `employeeActive`, policy → secret↔commitment → issuer signature over the
profile's message → path leaf → root recompute. `{precheck: false}` skips only the semantic
pre-checks, for negative tests that need an input the circuit must reject.

`buildInputV4` does not know which issuer key the gateway pins: a self-signed credential builds
(and would prove) with the forger's key in `issuerAx/issuerAy`. The client checks the issuer key
when it stores the credential (`credential.file v1`); the gateway pins it (obligation 2).

### Error codes (`AccessInputError.code`)

`INVALID_VALUE`, `OUT_OF_RANGE`, `MISSING_FIELD`, `UNKNOWN_FIELD`, `BAD_LENGTH`, `DEPTH_MISMATCH`,
`INVALID_PATH_INDEX`, `INVALID_KEY`, `UNKNOWN_PROFILE`, `PROFILE_MISMATCH`, `SECRET_MISMATCH`,
`LEAF_MISMATCH`, `BAD_SIGNATURE`, `ROOT_MISMATCH`, `POLICY_NOT_SATISFIED` (with `.reasons`),
`CREDENTIAL_EXPIRED`, `EMPLOYEE_INACTIVE`, `EPOCH_MISMATCH`, `RESOURCE_MISMATCH`.
Pre-check reason codes: `ROLE_NOT_ALLOWED`, `DEPT_NOT_ALLOWED`, `CLEARANCE_TOO_LOW`,
`DEVICE_NOT_COMPLIANT`, `EMPLOYEE_INACTIVE`, `CREDENTIAL_EXPIRED`.
Messages never echo input values.

## Usage

**Issuer** (signs, keeps the registry):

```js
const profile = zk.profiles.v4;                      // fixed at start (issuer.api v1)
const tree = await zk.createTree(profile);
const M = await profile.message({ commitment, attributes });
const signature = await zk.sign(prv, M);             // prv: 32 bytes from issuer/keys/, never stored here
tree.insert(BigInt(await profile.leaf({ commitment, attributes })));
const leafIndex = tree.leaves.length - 1;
// GET /path/:i -> zk.proofFor(tree, i), pathIndices mapped to JSON integers with Number()
// revoke       -> tree.delete(i)  (leaf <- 0; indices are never reused)
```

**Client** (builds the witness input):

```js
const v = zk.checkPolicyLocally(cred.attributes, "file_share", challenge.now);
if (!v.ok) showReasons(v.reasons);                   // local UI only
const input = await zk.buildInputV4({ ...cred.secrets, commitment: cred.commitment,
  attributes: cred.attributes, signature: cred.signature, issuer: cred.issuer,
  merkleProof: await fetchPath(cred.leafIndex), policy: "file_share", challenge });
// snarkjs.groth16.fullProve(input, wasm, zkey); send only {proof, publicSignals}
```

**Gateway** (Python) implements `access.public_signals v4` from the contract, not this library;
`decodePublicSignals` is the reference for its canonical-decimal parser.

## Floor notes

- **Floor 6.** `credentialSecret` and `credentialSalt` exist only on the client; the issuer
  receives `commitment` and the attributes. The input object `buildInput*` returns contains every
  private input and must never leave the client; only `{proof, publicSignals}` goes to the gateway.
- **Floor 8.** One Poseidon (circomlibjs 0.1.7) for circuit tests, issuer and client; the vectors
  pin it (`circuits/test/vectors/*/poseidon.json`) and identity's cross-check uses them.
- **Floor 9.** The library never holds or stores a key. Vectors derive TEST-ONLY keys from public
  labels and record only the label.
- **Floor 7.** `checkPolicyLocally` messages contain the user's attributes: show them locally,
  never log them on a server.

## The v3 File Share quirk

P1's v3 `FileShareAccess` hard-codes `role ∈ {2,3}` and `clearance ∈ {2,3}`. Those numbers are
**opaque** (ADR 0008): they do not follow D6, where 2 is contractor and an engineer is 0. A v3
credential that should prove therefore uses role 2 (or 3) and clearance 2 (or 3) regardless of the
person's real role. In the vectors, v3 Alice is that File Share TEST credential (role 2,
clearance 2); Bob (2/1) and Carol (1/3) carry their D6 numbers and v3 rejects them. v3 attributes
are also **unsigned** (not in `M` or the leaf), so v3 is a pipeline baseline only; v4 fixes it.

## Vectors

`circuits/test/vectors/{v3,v4}/*.json`, written by `node circuits/scripts/gen-vectors.js`;
`--check` exits 0 only when they are up to date. Never hand-edit them. Fixed clock
2026-11-08T09:00:00Z, expiry 2099-01-01.
