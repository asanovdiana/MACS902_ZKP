# Contracts

Every interface crossing a role boundary is recorded here **before** it is implemented: shape,
version, and what changed.

## Current

One `###` heading per contract.

<!--
### orders.create v1

```json
{ "order_id": "uuid", "total_cents": "int" }
```

Consumers: `backend`, `worker`.
-->

**Who implements what.**

| Contract | Implemented in | By tasks |
|---|---|---|
| `credential v3`, `access.public_signals v3` | **G0** (describes P1's imported circuit as it is) | G0-S1-CIRC-020/021/022, G0-S1-IDEN-001/002/003 |
| `issuer.api v1` | **G0** (profile `v3`), carried to `v4` in G1 | G0-S1-IDEN-001/002/004, G1-S1-IDEN-010/011 |
| `issuer.admin v1`, `issuer.api v1.1` | **G2** | G2-S1-IDEN-020 |
| `issuer.api v2`, `issuer.admin v1.1` | **G1 follow-up (SR-03/04/09/10)** | G1-S1-IDEN-014 |
| `credential.file v1` | **G0** (profile `v3`), carried to `v4` in G1 | G0-S1-IDEN-001/003, G1-S1-IDEN-012 |
| `credential v4`, `access.public_signals v4` | **G1** (agreed before any v4 code) | G1-S1-CIRC-030…038, G1-S1-IDEN-010…013 |

**Common rules (every contract below).**

- **Field.** BN254 scalar field, circom's default prime
  `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
- **Canonical decimal.** Every field element crossing a boundary (JSON, files, HTTP, public
  signals) is a string matching `^(0|[1-9][0-9]*)$` whose value is `< p`: ASCII digits only, no
  sign, no whitespace, no `0x`, no leading zero except `"0"` itself. Producers emit only this form;
  consumers reject anything else (they do not reduce mod p: the circom witness calculator would
  silently reduce `p + x` to `x`). Small enumerations (`role`, `pathIndices`, …) are JSON integers
  in `issuer.api v1` and `credential.file v1` and decimal strings in circuit input JSON.
- **Poseidon.** circomlib 2.0.5 `Poseidon(n)` in-circuit and circomlibjs 0.1.7 `buildPoseidon()`
  off-circuit, read as `F.toObject(poseidon([...]))`. No other implementation anywhere (floor 8).
  Shorthand `Poseidon(n)(a, b, …)` means that function over n inputs in that order.
- **EdDSA.** EdDSA-Poseidon on BabyJubJub: off-circuit circomlibjs `buildEddsa()`,
  `eddsa.prv2pub(prv)`, `eddsa.signPoseidon(prv, F.e(M))`; in-circuit circomlib
  `EdDSAPoseidonVerifier` with `enabled = 1`. The issuer private key `prv` is 32 random bytes,
  kept under `issuer/keys/` (gitignored, mode 0600, floor 9) and never leaves the issuer.
  Encoding: `Ax = F.toObject(pub[0])`, `Ay = F.toObject(pub[1])`, `R8x = F.toObject(sig.R8[0])`,
  `R8y = F.toObject(sig.R8[1])`, `S = sig.S` (integer < BabyJubJub subgroup order
  `l = 2736030358979909402780800718157159386076813972158567259200215660948447373041`; the
  circomlib verifier checks `S < l`). All five as canonical decimal strings.
- **Merkle tree.** Binary, `node = Poseidon(2)(left, right)`, zero leaf `0`, empty subtree at level
  `k+1` = `Poseidon(2)(z_k, z_k)`. `pathIndices[i] ∈ {0,1}`, level 0 = leaf level;
  `pathIndices[i] = 1` means **the current node is the right child** (so
  `parent = Poseidon(2)(pathElements[i], current)`), `0` means left
  (`parent = Poseidon(2)(current, pathElements[i])`). `pathIndices[i] = (leafIndex >> i) & 1`.
  Registry = `@zk-kit/incremental-merkle-tree` `new IncrementalMerkleTree(h, depth, 0n, 2)` with
  `h = (xs) => F.toObject(poseidon(xs))`. **Verified 2026-11-08** against zk-kit 1.1.0 source
  (`createProof`: `pathIndices[level] = index % arity`) and by a scratch run: for leaves
  `[11, c, 33, 44]` at depth 2, `createProof(1)` returns `pathIndices [1,0]`, siblings
  `[[11],[Poseidon(2)(33,44)]]`, and the zk-kit root equals the v3 circuit's computation.
  Mapping: `pathElements[i] = proof.siblings[i][0]`. Revocation = `tree.delete(i)` (leaf ← `0`);
  leaf indices are never reused. G0-S1-IDEN-002 pins zk-kit 1.1.0 and keeps a test that asserts
  this convention.
- **Floor 6.** `credentialSecret` and `credentialSalt` are generated on the client and never sent
  anywhere. The issuer receives `credentialCommitment` and the admin-assigned attributes; the
  gateway receives only a proof and public signals. The signature, Merkle path and attributes are
  never sent to the gateway.

### credential v3

What P1's `circuits/integrated_access_v3.circom` (template `IntegratedAccessGate()`, circom
2.2.3) consumes, exactly. Circuit input JSON (one object, all values canonical decimal strings):

```json
{
  "credentialSecret": "field; client CSPRNG, 31 bytes (< 2^248)",
  "credentialSalt":   "field; client CSPRNG, 31 bytes (< 2^248)",
  "role":             "v3 opaque integer; FileShareAccess requires 2 or 3",
  "clearance":        "integer; FileShareAccess requires 2 or 3",
  "deviceCompliant":  "0 | 1; FileShareAccess requires 1",
  "employeeActive":   "0 | 1; FileShareAccess requires 1",
  "Ax": "issuer public key x", "Ay": "issuer public key y",
  "R8x": "signature R8 x", "R8y": "signature R8 y", "S": "signature scalar < l",
  "M":    "= credentialCommitment (constraint M === credentialCommitment)",
  "leaf": "= credentialCommitment (constraint leaf === credentialCommitment)",
  "pathElements": ["sibling level 0", "sibling level 1"],
  "pathIndices":  ["0 | 1", "0 | 1"],
  "root": "public: Merkle root"
}
```

- `credentialCommitment = Poseidon(2)(credentialSecret, credentialSalt)` (intermediate signal, not
  an input; ADR 0005).
- Signature: `eddsa.signPoseidon(prv, F.e(credentialCommitment))`, i.e. signed message
  **`M = credentialCommitment`**. Verified by `IssuerSignatureCheck` →
  `EdDSAPoseidonVerifier(enabled = 1)`.
- Leaf = `credentialCommitment`. Tree per Common rules, **depth 2** (4 leaves), checked by
  `MerkleMembership()`; `pathIndices` are boolean-constrained in-circuit.
- Policy `FileShareAccess`: `deviceCompliant === 1`, `employeeActive === 1`,
  `(role-2)(role-3) === 0`, `(clearance-2)(clearance-3) === 0`; the main also boolean-constrains
  `deviceCompliant` and `employeeActive`. Role numbers are opaque in v3 (ADR 0008: D6 names apply
  from v4).
- Size: 8116 non-linear + 1529 linear constraints (`--O1`), 1 public input, 17 private inputs, no
  outputs (re-measured 2026-11-08).
- **Known gaps, stated plainly.** (1) `role, clearance, deviceCompliant, employeeActive` are
  **unsigned claims**: they are in neither `M` nor the leaf, so a holder of any valid credential can
  prove with any values that pass `FileShareAccess` (floor 2, tampered attribute: **not met**).
  (2) `Ax, Ay` are **private**: a self-signed credential produces a valid proof; nothing pins the
  issuer (floor 2, forged signature: **not met** at the proof level). (3) No expiry, nonce,
  resource binding or nullifier (floors 2 expired, 4, 5: **not met**). (4) R8 and A are not
  checked on-curve (circomlib verifier gap). v4 closes all four.
- The issuer key is stable (one key in `issuer/keys/`, generated once); P1's generator's
  random-key-per-run is a test convenience only.

Consumers: `circuits` (circuit, `circuits/lib` v3 profile, vectors), `identity` (issuer signs `M`,
registry stores leaves, client builds the input via `circuits/lib`).

### access.public_signals v3

```json
["root"]
```

| # | Name | Range | Who checks |
|---|---|---|---|
| 0 | `root` | field, canonical decimal | verifier compares to the registry's current root (`issuer.api v1`, staleness rule) |

- No outputs; one public input. Groth16 proof from snarkjs `groth16.fullProve`; verification key
  from G0-S1-CIRC-022 (build output, not committed).
- Because `[root]` is the only public signal, a v3 proof binds no issuer, policy, time, challenge
  or service: it can be replayed indefinitely and used for any resource. **v3 is a G0 pipeline
  baseline (issue → register → prove → verify, revoke → fail). The gateway must not admit on v3
  proofs.**

Consumers: `identity` (client produces it), `circuits` (prove/verify scripts), `qa` (G0 e2e).

### credential v4

Target of G1 (ADR 0006, 0008). v4 main `circuits/integrated_access_v4.circom`, depth 16.

```json
{
  "attributes": {
    "role":            "0..3 (0 engineer, 1 admin, 2 contractor, 3 finance)",
    "dept":            "0..3 (0 engineering, 1 it, 2 operations, 3 finance)",
    "clearance":       "0..3",
    "deviceCompliant": "0 | 1",
    "employeeActive":  "0 | 1 (must be 1 to prove; ADR 0007)",
    "expiry":          "unix seconds UTC, 0 <= expiry < 2^64 (issuer API: <= 2^53 - 1)"
  },
  "credentialCommitment": "Poseidon(2)(credentialSecret, credentialSalt)",
  "attrHash": "Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry, credentialCommitment)",
  "M":    "= attrHash (signed message)",
  "leaf": "= attrHash (Merkle leaf)",
  "signature": { "R8x": "field", "R8y": "field", "S": "< l" },
  "issuer":    { "Ax": "field (public input issuerAx)", "Ay": "field (public input issuerAy)" },
  "tree": "Common rules, depth 16 (65,536 leaves); 8 and 20 only for benchmarks"
}
```

Circuit inputs (v4):

| Kind | Signals |
|---|---|
| private | `credentialSecret, credentialSalt, role, dept, clearance, deviceCompliant, employeeActive, expiry, R8x, R8y, S, pathElements[16], pathIndices[16]` |
| public | the 11 inputs of `access.public_signals v4` (`root`, `issuerAx`, `issuerAy`, policy, `now`, `nonce`, `resourceId`, `epoch`) |
| output | `nullifier` |

- `M` and `leaf` are **not inputs** in v4; the circuit computes `attrHash` and uses it as both.
- In-circuit range checks: `role, dept, clearance` via `Num2Bits(2)`; `deviceCompliant`,
  `employeeActive` boolean; `expiry` and `now` via `Num2Bits(64)`; every comparator input is
  range-checked to the comparator's width first.
- `employeeActive === 1`; `expiry > now` strictly (`expiry == now` is expired).
- `R8` and the issuer key are checked on-curve (`BabyCheck`); `enabled = 1` is a constant.
- Signature: `eddsa.signPoseidon(prv, F.e(attrHash))`. The issuer key is public and pinned by the
  gateway, so a self-signed credential cannot satisfy the gateway.
- Enums: ADR 0008. One table in `circuits/lib`, imported by issuer and client.

Consumers: `circuits` (v4 components and main, `circuits/lib` v4 profile, vectors, fixtures),
`identity` (issuer signs `attrHash`, registry stores it, client builds inputs), `gateway`
(pins `issuerAx/issuerAy`), `safety` (floor 2 tests).

### access.public_signals v4

Ordered snarkjs `publicSignals` of the v4 depth-16 proof (ADR 0007). Output first, then public
inputs in template declaration order; the v4 main declares them in this order and a test asserts it
from the `.sym` file.

```json
["nullifier", "root", "issuerAx", "issuerAy", "roleMask", "deptMask", "minClearance",
 "requireDevice", "now", "nonce", "resourceId", "epoch"]
```

| # | Name | Kind | Range | Gateway must check |
|---|---|---|---|---|
| 0 | `nullifier` | output | field; `Poseidon(3)(credentialSecret, resourceId, epoch)` | `(nullifier, epoch)` not admitted before (rate limit 1 per epoch) |
| 1 | `root` | input | field | current registry root, or acceptable under the staleness rule (`issuer.api v1`) |
| 2 | `issuerAx` | input | field | equals the pinned issuer key (configuration, not fetched per request) |
| 3 | `issuerAy` | input | field | equals the pinned issuer key |
| 4 | `roleMask` | input | 0..15, bit i allows role i | equals the requested resource's policy |
| 5 | `deptMask` | input | 0..15, bit i allows dept i | equals the requested resource's policy |
| 6 | `minClearance` | input | 0..3 | equals the requested resource's policy |
| 7 | `requireDevice` | input | 0 \| 1 | equals the requested resource's policy |
| 8 | `now` | input | unix seconds, < 2^64 | equals the `now` the gateway put in this nonce's challenge |
| 9 | `nonce` | input | field; gateway issues 128 random bits | issued by this gateway, unexpired (TTL 120 s), unused; marked used on admission |
| 10 | `resourceId` | input | 1 wiki, 2 file share, 3 admin panel | equals the requested resource and the challenge |
| 11 | `epoch` | input | `floor(unixSeconds / 600)` | equals `floor(now / 600)` and the challenge's epoch |

**Encoding.** Every element is canonical decimal (Common rules). The gateway rejects a payload with
any non-canonical element **before** verifying, and keys all state on the canonical integer value:
replay state on `nonce`, rate-limit state on `(nullifier, epoch)`, never on proof bytes or a proof
hash (Groth16 proofs are re-randomisable).

**Gateway obligations** (all required; the circuit alone does not deliver floors 2–5):

1. Groth16 verify against the committed v4 verification key (ADR 0009).
2. Pin `issuerAx, issuerAy` to the configured issuer key (floor 2, forged signature).
3. `root` is current: the gateway's view of the registry root is at most **30 s** old (the scope's
   staleness window); a superseded root is accepted only per the `GET /root/history` rule, which
   never re-admits a revoked leaf (floor 3).
4. Policy fields and `resourceId` equal the configuration of the service actually requested
   (floor 2, unsatisfied policy).
5. `now` freshness: the gateway issues `{nonce, resourceId, epoch, now, policy}` as one challenge
   and stores it with the nonce; the proof's `now`, `epoch`, `resourceId` and policy must equal the
   stored values. Skew bound = nonce TTL = **120 s** (an old `now` would otherwise revive an expired
   credential; floor 2).
6. `nonce` single-use and unexpired (floor 4).
7. `(nullifier, epoch)` admitted at most once; a second proof is denied as rate-limited (floor 5).
   A session cookie (10 minutes, scope M5) covers further requests in the epoch.
8. Logs and state hold only public signals and decisions, never identity attributes (floor 7). The
   policy fields are the service's, not the user's.

**Circuit obligation.** Every public input appears in at least one constraint (`nonce` via
`nonceSquared <== nonce * nonce`), so changing any public signal fails verify; CIRC-037 tests each.

**Unlinkability.** Same user, different `resourceId` or `epoch` → unrelated nullifiers (floor 5).
`root`, `issuerAx/Ay` and policy fields are shared by every user of a service.

**Demo policies and resources** (enums per ADR 0008):

| Resource | `resourceId` | `roleMask` | `deptMask` | `minClearance` | `requireDevice` |
|---|---|---|---|---|---|
| Wiki | 1 | `15` (0b1111, any role) | `15` | `0` | `1` |
| File Share | 2 | `3` (0b0011, engineer \| admin) | `15` | `2` | `0` |
| Admin Panel | 3 | `2` (0b0010, admin) | `15` | `3` | `1` |

`epoch = floor(unixSeconds / 600)`: 10-minute sessions (scope, Core concepts).

Consumers: `identity` (client produces it, local pre-check uses the policy table), `gateway`
(verifies and enforces obligations 1–8), `circuits` (main, codec, `verify.js`, fixtures), `qa`,
`safety`, `frontend` (Gateway Live View shows these signals).

### issuer.api v1

HTTP/JSON API of the Node issuer + registry service (ADR 0003). One process serves one profile,
fixed at start (`v3` in G0, `v4` from G1); every credential and root response names it. Bodies are
`application/json`; field elements are canonical decimal strings; times are unix seconds (JSON
integers).

```text
GET  /issuer                         200 {profile, depth, issuer:{Ax, Ay}}
POST /credentials                    201 {credential:{profile, attributes, signature:{R8x,R8y,S}, issuer:{Ax,Ay}, leafIndex}}
     body {commitment, attributes}
POST /credentials/:leafIndex/revoke  200 {root}
GET  /root                           200 {root, updatedAt, profile, depth}
GET  /root/history?since=<unix s>    200 {now, current, roots:[{root, validFrom, supersededAt|null, supersededBy:"insert"|"revoke"|null}]}
GET  /path/:leafIndex                200 {profile, leafIndex, leaf, root, pathElements:[depth], pathIndices:[depth]}

error (any route)                    {error:{code, message}}
```

Profile-dependent fields:

| Field | `v3` | `v4` |
|---|---|---|
| `attributes` | `{role, clearance, deviceCompliant, employeeActive}` integers: role, clearance 0..3; booleans 0/1 | `{role, dept, clearance, deviceCompliant, employeeActive, expiry}`; enums per ADR 0008; `expiry` integer, `now < expiry ≤ 2^53 − 1` |
| signed message | `credentialCommitment` | `attrHash` (`credential v4`) |
| leaf | `credentialCommitment` | `attrHash` |
| `depth` / path length | 2 | 16 |

Semantics:

- `POST /credentials`: the issuer validates (strict schema, unknown keys rejected), signs the
  profile's message with its persistent key, inserts the leaf at the next index, returns the
  credential. The caller is the enrolment/admin path (scope M1: the admin assigns attributes); the
  issuer does not enforce any service policy. v3 attributes are returned but **unsigned**
  (`credential v3` gap). **Superseded by `issuer.api v2` for `POST /credentials`** (the body below
  is the open-enrolment form, kept only behind `ISSUER_INSECURE_DEV=1`, v3 profile).
- **Floor 6.** The issuer never receives `credentialSecret` or `credentialSalt`: a body carrying
  any key named `credentialSecret`, `credentialSalt`, `secret` or `salt` (at any depth) is rejected
  with `400 forbidden_field` and the value is not logged.
- `POST /credentials/:leafIndex/revoke`: sets the leaf to `0` (`tree.delete`), returns the new
  root. Not reversible; indices are not reused.
- `GET /root`: `updatedAt` = time of the last insert or revoke.
- `GET /root/history?since=t`: every root that was current at some time `≥ t`, oldest first
  (retained ≥ 10 minutes). **Staleness rule (30 s window):** a verifier accepts proof root `r`
  iff `r == current`, or `r` is in the history with `gatewayNow − supersededAt ≤ 30` **and** every
  transition from `r` up to `current` has `supersededBy = "insert"`. A root superseded by (or
  before) a revocation is never accepted once the verifier has seen the revocation, so enrolments
  do not break in-flight proofs, and revocations take effect within the verifier's refresh period
  (≤ 30 s, or immediately on a per-request fetch).
- `GET /path/:leafIndex`: path against the current root, `pathIndices` as JSON integers 0/1 per
  Common rules. Revoked leaf → `410 revoked`. Privacy note: the registry sees which `leafIndex`
  asks and when; the client caches the path and refreshes it on root change, not per gateway
  request (scope privacy table: the issuer is not the gateway, but the timing is still a leak to
  state in the threat model).

Errors (`message` never echoes request values):

| Status | `code` | When |
|---|---|---|
| 400 | `invalid_json` | body not JSON |
| 400 | `forbidden_field` | secret or salt key present (floor 6) |
| 400 | `invalid_commitment` | not canonical decimal, `≥ p`, or `0` |
| 400 | `invalid_attributes` | missing, extra, wrong-profile or out-of-range attribute; v4 `expiry ≤ now` |
| 400 | `invalid_leaf_index` | not a non-negative integer |
| 400 | `invalid_since` | `since` not a non-negative integer |
| 404 | `unknown_leaf` | index ≥ number of issued leaves |
| 409 | `duplicate_commitment` | commitment already issued (v3: would be a duplicate leaf) |
| 409 | `already_revoked` | revoke on a revoked leaf |
| 409 | `tree_full` | `2^depth` leaves issued (v3: 4) |
| 410 | `revoked` | `GET /path` for a revoked leaf |
| 500 | `internal` | anything else; no details |

Observability: structured JSON logs with route, status, `leafIndex`, latency; counters for issued,
revoked, errors by code; never the commitment, attributes, signature, or any key material.

Consumers: `identity` (client calls it; issuer implements it), `gateway` (`/root`,
`/root/history`, `/issuer` for bootstrapping only), `frontend` (Admin Console, via G2 Admin API),
`qa`, `safety`.

### issuer.admin v1

Admin surface of the issuer service for the Admin Console (`frontend`), task G2-S1-IDEN-020. Same
process, same conventions as `issuer.api v1` (JSON, canonical decimal field elements, unix-second
integers, `{error:{code,message}}`). It adds three read routes and one stream, and authenticates the
revoke route.

```text
GET  /admin/leaves?from=<n>&limit=<n>   200 {profile, depth, total, from, leaves:[{leafIndex, status:"issued"|"revoked", leaf, issuedAt, revokedAt|null}]}
GET  /admin/tree                        200 {profile, depth, root, leafCount, zeros:[depth+1], levels:[{level, nodes:[hash...]}]}
GET  /admin/events                      200 text/event-stream (Server-Sent Events)
POST /credentials/:leafIndex/revoke     200 {root}          (issuer.api v1; now bearer-protected, see Auth)
```

**`/admin/leaves`.** Issued leaves in index order; `from` default 0, `limit` default 1000, max 5000
(`400 invalid_query` otherwise). `total` = leaves issued so far (revoked included; indices are never
reused). `leaf` is the canonical-decimal leaf hash as it sits in the tree: the credential's leaf
while `issued`, `"0"` once `revoked`. Unissued positions are not listed (they are the empty leaf
`"0"` by definition). Fields kept to what the console draws: index, status, hash, two timestamps.
**Never present:** attributes, commitment, signature, secret, salt, key material. (The issuer side
may know identities, but the console draws a tree and a table of indices; it needs no attribute, and
v4 attributes are not retained by the issuer at all. A person-to-index mapping, if the console wants
names, is the console's own demo data.)

**`/admin/tree`, path-compressed shape.** Level 0 = leaves, level `depth` = root. For each level only
the nodes that have at least one issued leaf below them are returned, as a dense array from
position 0: `levels[l].nodes` has `ceil(leafCount / 2^l)` entries (level `depth` has exactly one,
the root; an empty tree has `leafCount 0`, `nodes: []` at levels below `depth`, and `root == zeros[depth]`). Any node not
listed is the empty-subtree hash `zeros[l]` (`zeros[0] = "0"`, `zeros[l+1] = Poseidon(2)(zeros[l],
zeros[l])`). Parent of position `i` at level `l` is position `floor(i/2)` at level `l+1`. A revoked
leaf appears as `"0"` at level 0 and the hashes above it are recomputed. Size is at most `2 * leafCount`
entries plus the `depth+1` zeros. Invariant: `root` equals `GET /root`'s `root` taken in the same
instant (both are served from one in-memory tree; the response is a consistent snapshot).

**`/admin/events` (SSE).** `Content-Type: text/event-stream`, `Cache-Control: no-cache`. Frames:

```text
event: hello
data: {"profile":"v4","root":"...","seq":12}

id: 13
event: root-changed
data: {"seq":13,"root":"...","prevRoot":"...","kind":"insert"|"revoke","leafIndex":3,"at":1800000000}

: hb
```

- `hello` is sent first on every connection (current root and the last event sequence number `seq`).
- `root-changed` is sent after the change is persisted, exactly once per insert or revoke, in
  order; `prevRoot` of event `n+1` equals `root` of event `n`. `at` = the registry's change time
  (same clock as `updatedAt`). `seq` is a per-process counter starting at 1 (resets on restart).
- **Reconnect.** The server keeps the last 256 events in memory. A client that reconnects with
  `Last-Event-ID: <seq>` receives, after `hello`, every retained event with a larger `seq`, then the
  live stream. If `<seq>` is older than the buffer, or larger than the current `seq` (the issuer
  restarted), only `hello` is sent: the client re-reads `/admin/tree` or `/admin/leaves`. The client
  should always do that on `hello` whose `root` differs from what it holds.
- Heartbeat: a comment line `: hb` every 15 s (configurable) so proxies keep the stream open.
- Event payloads carry no commitment, attribute or identity.

**Auth.** If the environment variable `ISSUER_ADMIN_TOKEN` is set (non-empty), every `/admin/*` route
and `POST /credentials/:leafIndex/revoke` require `Authorization: Bearer <token>` (constant-time
compare); otherwise `401 unauthorized` with `WWW-Authenticate: Bearer`. The token is read from the
environment only, is never logged, echoed, or put in a URL (so a browser `EventSource`, which cannot
set headers, cannot be used directly: use `fetch` streaming, or a server-side proxy that adds the
header; the `ui` server is the natural place). Since `issuer.api v2` the issuer refuses to start without a token unless `ISSUER_INSECURE_DEV=1`; in that dev mode the admin surface is open: the demo
binds the issuer to localhost / the compose network and states this in `issuer/README.md`. `POST
/credentials`, `GET /root*`, `GET /path/*`, `GET /issuer` and `GET /metrics` stay unauthenticated
(clients and the gateway use them). There is no CORS handling; the console reaches the issuer through
its own server.

Errors added: `401 unauthorized`; `400 invalid_query` (`/admin/leaves` `from`/`limit`).

Observability: `GET /metrics` (an addition of `issuer.api v1.1`, below) gains `sseClients` (gauge) and
`sseEvents` (counter of frames sent); each SSE connect and disconnect is one structured log line
with the client count; auth failures count as error code `unauthorized`. No token, no attribute.

Consumers: `frontend` (Admin Console: leaves table, tree drawing with revoked leaf greyed, live
root), `qa`, `safety` (floor 7: no attributes in admin responses or logs).

### issuer.api v1.1

Backward-compatible additions to `issuer.api v1`, all already implemented in G0/G1 and listed in
`issuer/README.md`, recorded here so consumers can rely on them:

- `GET /metrics` -> `200 {profile, leaves, issued, revoked, rootChanges, errors:{code:n},
  requests:{"METHOD route":{count, latencyMsSum, latencyMsMax}}, sseClients, sseEvents}`. No
  commitment, attribute or key material.
- Unknown route -> `404 {error:{code:"not_found"}}`.
- Strictness already in force: attribute values are JSON integers; an unknown top-level key in the
  `POST /credentials` body is `400 invalid_attributes`.
- `POST /credentials/:leafIndex/revoke` is bearer-protected when `ISSUER_ADMIN_TOKEN` is set
  (`issuer.admin v1`).

### issuer.api v2

Task G1-S1-IDEN-014, closing safety finding SR-03 (open enrolment: whoever reached the issuer chose
their own attributes, a revoked user re-enrolled, one person held N credentials) and SR-04. Only
`POST /credentials` changes; every other `issuer.api v1` / `v1.1` route is as before.

```text
POST /credentials   201 {credential:{profile, attributes, signature:{R8x,R8y,S}, issuer:{Ax,Ay}, leafIndex}}
     body {commitment, enrolmentCode}
```

- **The admin assigns the attributes, the user supplies the commitment.** The admin creates an
  enrolment (`issuer.admin v1.1`) for an employee with the attributes (v4: including `expiry`) and
  receives a one-time `code`, which the admin hands to the employee out of band. The user's client
  generates secret and salt locally and submits `{commitment, enrolmentCode}`. The issuer signs the
  **admin-assigned** attributes of that enrolment and returns them in the credential. The client has
  no way to choose or alter an attribute.
- A body carrying `attributes` (any value) is `400 attributes_not_accepted`; the `forbidden_field`
  rule for `secret`/`salt` (floor 6) is unchanged and is checked first; other unknown keys are
  `400 invalid_request`.
- **Code.** 24 CSPRNG bytes, base64url (32 characters, 192 bits). Shown once, in the response that
  creates the enrolment. The issuer stores only `sha256(code)`. Single use: consumed by the
  successful issue. Lifetime `ttlSeconds` from creation (default 3600, `ISSUER_ENROLMENT_TTL_SECONDS`;
  admin may request 60..604800). Redeeming checks, in order: well-formed and known, not used, not
  expired, v4 `expiry` still in the future, commitment not already issued, registry not full; the
  code is consumed only when the leaf has been inserted.
- **At most one live credential per employee.** `employeeId` is compared case-insensitively. An
  enrolment for an employee who has a **pending** (unredeemed, unexpired) enrolment, or a redeemed
  enrolment whose leaf is not revoked, is refused (`409 enrolment_pending` /
  `409 employee_has_credential`). Chosen policy: **no implicit re-enrolment**. To replace a
  credential the admin revokes the old leaf (`POST /credentials/:leafIndex/revoke`, unchanged) and
  then creates a new enrolment; to replace an unredeemed code the admin cancels it first. A revoked
  employee therefore cannot get a new credential without a fresh, deliberate admin enrolment; the
  user alone can do nothing with a used or cancelled code.
- **Open enrolment is removed for `v4`.** For `v3` (baseline only) the v1 body
  `{commitment, attributes}` is accepted **only** when the issuer runs with `ISSUER_INSECURE_DEV=1`.
  Otherwise `v3` also requires a code.
- **Fail closed (SR-04).** The issuer refuses to start without `ISSUER_ADMIN_TOKEN` unless
  `ISSUER_INSECURE_DEV=1`, in which case it logs a warning at startup and the admin surface is open.
  (Applies to both profiles: without the token nobody could create an enrolment.)
- **Key directory (SR-10).** The directory holding `issuer.key` is created `0700`; an existing
  directory that is accessible by group or other is refused at start.
- **Identity stays issuer-side.** `employeeId` and the pending attributes are held only by the issuer
  (`enrolments.json` in the data directory, `0600`; the attributes are erased at redemption, the
  `employeeId` -> `leafIndex` link is kept so that liveness and revocation work). They are never
  logged, never in a metric, never in `/admin/leaves`, `/admin/tree`, `/admin/events`, `/root*`,
  `/path/*`, and never reach the gateway. The issuer still never receives secret, salt or any private
  input (floor 6): it sees the commitment, as before.

Errors added to the `issuer.api v1` table:

| Status | `code` | When |
|---|---|---|
| 400 | `attributes_not_accepted` | body carries `attributes` (outside insecure-dev v3) |
| 400 | `invalid_request` | unknown top-level key |
| 403 | `invalid_enrolment_code` | `enrolmentCode` absent, malformed, unknown or cancelled |
| 409 | `enrolment_used` | the code was already redeemed |
| 410 | `enrolment_expired` | code past its lifetime, or the assigned v4 `expiry` has passed |

`invalid_attributes` no longer arises on `POST /credentials` (the attributes were validated when the
admin created the enrolment), except in insecure-dev v3.

Observability: `GET /metrics` gains `enrolmentsCreated`, `enrolmentsRedeemed` (counters) and
`enrolmentsPending` (gauge); failures count under the error codes above. Logs carry route, status,
latency and code only: never the code, the employeeId, a commitment or an attribute.

Consumers: `identity` (client `zkgate request --code`, seed script, Attack Lab world), `frontend`
(User Portal asks for the code and calls the client library), `devops` (set `ISSUER_ADMIN_TOKEN`,
or `ISSUER_INSECURE_DEV=1` for local use), `qa`, `safety` (todo F2.14, F3.10).

### issuer.admin v1.1

Additions to `issuer.admin v1` (same auth: `Authorization: Bearer <ISSUER_ADMIN_TOKEN>` on every
route below, `401 unauthorized` otherwise), task G1-S1-IDEN-014.

```text
POST   /admin/enrolments              201 {enrolmentId, code, expiresAt}
       body {employeeId, attributes, ttlSeconds?}
GET    /admin/enrolments?from=&limit= 200 {total, from, enrolments:[{enrolmentId, employeeId, status, createdAt, expiresAt, redeemedAt|null, leafIndex|null}]}
DELETE /admin/enrolments/:enrolmentId 200 {enrolmentId, status:"cancelled"}
```

- `employeeId`: 1..128 characters of `[A-Za-z0-9._@+-]`, starting with a letter or digit. `attributes`:
  exactly the profile's attributes, validated as in `issuer.api v1` (v4 `expiry > now`).
  `ttlSeconds`: integer 60..604800, default 3600.
- `status`: `pending`, `redeemed`, `cancelled`, or `expired` (a pending enrolment past
  `expiresAt`). For a `redeemed` enrolment `leafIndex` names its leaf; whether that leaf is revoked
  is read from `/admin/leaves`.
- **Why the listing shows `employeeId`.** The console must show which employee holds which leaf
  index in order to revoke the right one, and the issuer already knows the identity (the admin typed
  it). The listing never carries attributes, the code, the code hash or a commitment, and is behind
  the token. `/admin/leaves`, `/admin/tree` and `/admin/events` are unchanged and remain identity-free.
- The `code` is returned once and cannot be retrieved later; a lost code is cancelled and re-issued.
- Errors: `400 invalid_employee_id`, `400 invalid_attributes`, `400 invalid_ttl`, `404
  unknown_enrolment`, `409 enrolment_pending`, `409 employee_has_credential`,
  `409 enrolment_not_pending` (cancel of a redeemed/cancelled enrolment), `400 invalid_query`.
- `issuer.admin v1` statement "v4 attributes are not retained by the issuer at all" is refined: they
  are retained only for a **pending** enrolment and erased when it is redeemed or cancelled.

Consumers: `frontend` (Admin Console: enrol an employee, show the one-time code, list/cancel
enrolments), `identity` (seed script, Attack Lab), `qa`, `safety`.

### credential.file v1

Client-side credential file written by `client/` (wallet). Never sent anywhere, never committed.

```json
{
  "format": "zk-access-gate/credential",
  "version": 1,
  "profile": "v3 | v4",
  "issuerUrl": "http://…",
  "status": "pending | issued",
  "secrets": {
    "credentialSecret": "canonical decimal, 31 CSPRNG bytes",
    "credentialSalt":   "canonical decimal, 31 CSPRNG bytes"
  },
  "commitment": "Poseidon(2)(credentialSecret, credentialSalt)",
  "attributes": "issuer.api v1 attributes for the profile (as returned by the issuer)",
  "issuer":     { "Ax": "…", "Ay": "…" },
  "signature":  { "R8x": "…", "R8y": "…", "S": "…" },
  "leafIndex":  "integer",
  "createdAt":  "unix seconds",
  "issuedAt":   "unix seconds"
}
```

- `keygen` writes `status: "pending"` with `secrets` and `commitment` only; `request` sends
  **only** `{commitment, enrolmentCode}` to `POST /credentials` (`issuer.api v2`; v1 sent
  `{commitment, attributes}`) and fills in `attributes` (the **admin-assigned** ones), `issuer`,
  `signature`, `leafIndex`, `status: "issued"`.
- On receipt the client verifies the signature over the profile's message (v3: commitment; v4:
  `attrHash`) of the returned attributes under `issuer`, checks `issuer` equals the key it expects, and checks
  `GET /path/:leafIndex` returns its own leaf; otherwise it refuses to store the credential.
- Storage: `${ZKGATE_HOME:-~/.zkgate}/credentials/<name>.json`, file mode **0600**, directory
  0700, written atomically (temp file + rename); outside the repository by default. `.gitignore` must cover
  `.zkgate/`, `*.credential.json` and `issuer/keys/` before G0-S1-IDEN-001 lands (today it covers
  none of them; floor 9). The client refuses to read a file with group/other
  permissions.
- The Merkle path is not stored (fetched from `GET /path/:leafIndex`, cached in memory).
- `secrets` is never serialised into any request, log or error (floor 6). One fresh secret and salt
  per credential (ADR 0005).

Consumers: `identity` (client CLI and library), `frontend` (User Portal through the client
library, never by reading the file directly).

## Superseded

The entries below described the removed circuits prototype (not included in this repository). They are
kept as the reference design for the planned `v4` contracts and are **not** implemented by the P1 v3
circuit.

### credential.leaf v1 (superseded)

Attribute encoding, leaf hash and issuer signature of a credential. Full rationale in
`circuits/SPEC.md` §2–3; reference values in `circuits/test/vectors/credentials.json` and
`circuits/test/vectors/eddsa.json` (TEST-ONLY).

```json
{
  "attributes": {
    "role": "0..3 (0 engineer, 1 admin, 2 contractor, 3 finance)",
    "dept": "0..3 (0 engineering, 1 it, 2 operations, 3 finance)",
    "clearance": "0..3",
    "device_compliant": "0 | 1",
    "expiry": "unix seconds UTC, 0 <= expiry < 2^64",
    "secret_commitment": "field element = Poseidon(1)(user_secret)"
  },
  "attr_hash": "field element = Poseidon(6)(role, dept, clearance, device_compliant, expiry, secret_commitment)",
  "signature": { "R8x": "field element", "R8y": "field element", "S": "integer < BabyJubJub subgroup order" },
  "issuer": { "Ax": "field element", "Ay": "field element" },
  "leaf_index": "int, position in the registry tree"
}
```

- Every field element is a decimal string, BN254 scalar field (circom default prime).
- Poseidon = circomlibjs `buildPoseidon` / circomlib `Poseidon(n)` (x^5, 8 full rounds, circomlib
  partial-round table). Use this one implementation everywhere (floor 8).
- Signature = EdDSA-Poseidon on BabyJubJub: circomlibjs `eddsa.signPoseidon(prv, F.e(attr_hash))`,
  verified in-circuit by circomlib `EdDSAPoseidonVerifier`. The signed message is `attr_hash`.
- Merkle leaf = `attr_hash`. Registry tree = `@zk-kit/incremental-merkle-tree`
  `(Poseidon(2), depth 16, zeroValue 0, arity 2)`; revocation = delete (leaf → 0).
- `user_secret` is a random field element generated client-side and never sent to the issuer; the
  issuer receives only `secret_commitment` (floor 6).
- Cross-check: issuer and client must reproduce `circuits/test/vectors/*.json` bit-for-bit.

Consumers: `identity` (issuer signs and inserts leaves; client builds witnesses), `gateway`
(knows the issuer public key and registry root semantics).

### access.public_signals v1.1 (superseded)

Ordered `publicSignals` array of an `AccessGate(16)` Groth16 proof (snarkjs puts outputs first).
Every element is a decimal-string field element. Full spec in `circuits/SPEC.md` §5; sample in
`circuits/test/vectors/access_input.alice.wiki.json`.

**Encoding (normative, v1.1).** Every element is a **canonical decimal** string: ASCII digits
only, no sign, no whitespace, no leading zero except `"0"` itself, value < p (BN254 scalar field,
`21888242871839275222246405745257275088548364400416034343698204186575808495617`). Regex
`^(0|[1-9][0-9]*)$` plus the range check. The verifier (`circuits/scripts/verify.js` `verify()`)
returns false for any other spelling; helpers `isCanonicalSignal` / `canonicalizeSignals` are
exported from the same module. The gateway keys replay state on the canonical `nonce` and
rate-limit state on the canonical `(nullifier, epoch)`, never on proof bytes (Groth16 proofs are
re-randomisable). Every v1 producer (snarkjs `fullProve`) already emits canonical strings, so v1
payloads that verified still verify.

| # | Name | Range | Gateway must check |
|---|---|---|---|
| 0 | `nullifier` | field; `Poseidon(3)(user_secret, resource_id, epoch)` | not seen before in this epoch (rate limit) |
| 1 | `merkle_root` | field | equals the issuer's current root (staleness window documented) |
| 2 | `issuer_Ax` | field | equals the pinned issuer key |
| 3 | `issuer_Ay` | field | equals the pinned issuer key |
| 4 | `role_mask` | 0..15, bit i = role i allowed | equals the resource's policy |
| 5 | `dept_mask` | 0..15, bit i = dept i allowed | equals the resource's policy |
| 6 | `min_clearance` | 0..3 | equals the resource's policy |
| 7 | `require_device` | 0/1 | equals the resource's policy |
| 8 | `now` | unix seconds, < 2^64 | within tolerance of the gateway clock |
| 9 | `nonce` | field (gateway issues ≤ 128 random bits) | issued by this gateway, fresh, unused |
| 10 | `resource_id` | field | the resource being requested |
| 11 | `epoch` | field, gateway-defined window index | the current epoch |

Private witness inputs (never leave the client): `role`, `dept`, `clearance`, `device_compliant`,
`expiry`, `user_secret`, `sig_R8x`, `sig_R8y`, `sig_S`, `pathElements[16]`, `pathIndices[16]`.

Demo policies `(role_mask, dept_mask, min_clearance, require_device)`: Wiki `(15, 15, 0, 1)`,
File Share `(3, 15, 2, 0)`, Admin Panel `(2, 15, 3, 1)`.

Consumers: `identity` (client prover produces it), `gateway` (verifier checks it).

## Change log

The `Contract` column holds the name from that contract's `###` heading in Current.

| Date | Contract | Version | Change | Task |
|---|---|---|---|---|
| 2026-11-02 | credential.leaf v1 | 1 | Initial: attribute encoding, attr_hash = Poseidon(6), EdDSA-Poseidon over attr_hash, zk-kit Poseidon tree leaf | G0-S1-CIRC-006 |
| 2026-11-02 | access.public_signals v1 | 1 | Initial: 12 ordered public signals of AccessGate(16) and gateway-side checks | G0-S1-CIRC-006 |
| 2026-11-02 | access.public_signals v1.1 | 1.1 | Normative canonical-decimal encoding (no sign, no leading zeros except "0", < p); verifier rejects non-canonical signals; replay / rate-limit keys are canonical values, never proof bytes | G1-S1-CIRC-010 |
| 2026-11-08 | credential.leaf v1, access.public_signals v1.1 | — | Superseded: prototype removed in favour of the team's P1 v3 circuit; v3 contracts to be recorded by G0-S1-ARCH-010 | — |
| 2026-11-08 | credential v3 | 3 | Initial: describes P1's imported v3 exactly (commitment = Poseidon(2)(secret, salt), EdDSA-Poseidon over M = commitment, leaf = commitment, depth-2 tree, pathIndices 1 = right child, zk-kit 1.1.0 convention verified); attributes unsigned and issuer key private recorded as gaps | G0-S1-ARCH-010 |
| 2026-11-08 | access.public_signals v3 | 3 | Initial: `[root]`; not an admission path for the gateway | G0-S1-ARCH-010 |
| 2026-11-08 | issuer.api v1 | 1 | Initial: /issuer, /credentials, /credentials/:leafIndex/revoke, /root, /root/history (30 s staleness rule, never re-admits revoked), /path/:leafIndex; error codes; forbidden_field for secret/salt (floor 6) | G0-S1-ARCH-010 |
| 2026-11-08 | credential.file v1 | 1 | Initial: client credential file, secrets local only, mode 0600 | G0-S1-ARCH-010 |
| 2026-11-08 | credential v4 | 4 | Initial: attrHash = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry, commitment) = M = leaf; ranges; issuer key public; depth 16; D6 enums | G1-S1-ARCH-011 |
| 2026-11-08 | access.public_signals v4 | 4 | Initial: 12 ordered signals (prototype order, camelCase), canonical decimal, nullifier = Poseidon(3)(secret, resourceId, epoch), gateway obligations 1–8, demo policies, resourceIds 1–3, epoch = floor(t/600) | G1-S1-ARCH-011 |
| 2026-11-08 | issuer.admin v1 | 1 | Initial: GET /admin/leaves, GET /admin/tree (path-compressed levels + zeros), GET /admin/events (SSE root-changed, hello, heartbeat, Last-Event-ID replay), bearer token ISSUER_ADMIN_TOKEN for /admin/* and revoke; no attributes in any response | G2-S1-IDEN-020 |
| 2026-11-08 | issuer.api v1.1 | 1.1 | Records existing additions (GET /metrics, 404 not_found, strict body keys) plus 401 unauthorized on revoke when ISSUER_ADMIN_TOKEN is set and sseClients/sseEvents metrics | G2-S1-IDEN-020 |
| 2026-11-08 | issuer.api v2 | 2 | `POST /credentials` takes `{commitment, enrolmentCode}`; the admin assigns attributes via an enrolment; single-use hashed code with TTL; one live credential per employee (no implicit re-enrolment, revoke first); open enrolment removed for v4 and kept for v3 only behind `ISSUER_INSECURE_DEV=1`; issuer refuses to start without `ISSUER_ADMIN_TOKEN` unless insecure-dev (SR-04); key directory 0700 enforced (SR-10); new errors `attributes_not_accepted`, `invalid_request`, `invalid_enrolment_code`, `enrolment_used`, `enrolment_expired` | G1-S1-IDEN-014 |
| 2026-11-08 | issuer.admin v1.1 | 1.1 | `POST/GET /admin/enrolments`, `DELETE /admin/enrolments/:id`; employeeId held issuer-side and listed only behind the token; pending attributes erased at redemption | G1-S1-IDEN-014 |
| 2026-11-08 | credential.file v1 | 1 | Clarified (no format change): `request` sends `{commitment, enrolmentCode}`; stored attributes are the admin-assigned ones | G1-S1-IDEN-014 |
