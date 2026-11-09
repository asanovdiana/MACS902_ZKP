# Report chapter: identity (issuer, registry, client prover)

Audience: the course and demo panel. Plain explanation first, then technical detail. Numbers come
from committed files or from test runs named in the text.

## 1. The idea in plain words

Think of a company ID office. The employee walks in, the office decides which attributes they get
(role, department, clearance, device compliance, expiry), signs them, and writes the credential
into a public logbook of valid credentials. The employee keeps a private secret that the office
never sees. Later, the employee proves at a door that they hold a signed, still-valid entry that
fits the door's rule, without showing the entry.

Three pieces of our system play these parts:

| Part | Scope item | Code | What it does |
|---|---|---|---|
| Issuer | M1 | `issuer/` | assigns and signs attributes, keeps the signing key |
| Registry | M2 | `issuer/src/registry.js` | Merkle tree of valid credentials; revoking removes an entry |
| Client prover | M4 | `client/` | keeps the secret, builds the proof on the user's machine |

All three share one encoder, `circuits/lib` (ADR 0004), so they cannot disagree on how values are
turned into circuit inputs. Runtime: Node (ADR 0003), because EdDSA-Poseidon and the Poseidon tree
only exist reliably in `circomlibjs` and `@zk-kit`.

## 2. Issuer

### 2.1 Key handling

- The signing key is 32 random bytes, hex-encoded in `ISSUER_KEY_DIR/issuer.key`, generated once
  with a temp file and `link()` so an existing key is never overwritten, mode 0600.
- Start-up refuses a key file with group/other permissions or a malformed one, and the error never
  prints the content. The key survives restarts; losing it invalidates every issued credential.
- Only the public key is exposed (`GET /issuer`). The signer keeps the private key in a closure.
- The key directory is gitignored, and tests use temporary directories (floor 9: no issuer private
  key in the tree). Source: [`issuer/README.md`](../../issuer/README.md) "Keys".

### 2.2 Signing, profiles v3 and v4

| | `v3` (P1 baseline) | `v4` (product) |
|---|---|---|
| tree depth / leaves | 2 / 4 | 16 / 65 536 |
| attributes | role, clearance, deviceCompliant, employeeActive | role, dept, clearance, deviceCompliant, employeeActive, expiry |
| signed message and leaf | `commitment` | `attrHash(attributes, commitment)` |

In v3 the attributes are not signed at all (gap G-1, see the circuit chapter). In v4 the issuer
signs `attrHash = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry,
commitment)` (ADR 0006) with EdDSA-Poseidon on BabyJubJub, and inserts the same value as the
Merkle leaf. Role and dept use the enums of ADR 0008; expiry must satisfy `now < expiry <= 2^53-1`.
One process runs one profile, named in every response.

What the issuer sees: `{commitment, attributes}` only, where `commitment = Poseidon(secret, salt)`
(ADR 0005). A request body containing `credentialSecret`, `credentialSalt`, `secret` or `salt` at
any depth is rejected with `400 forbidden_field` and the value is not logged (floor 6).

### 2.3 API

Contract: [`docs/CONTRACTS.md`](../CONTRACTS.md) `issuer.api v1` (v1.1 adds `/metrics`).

| Route | Purpose |
|---|---|
| `GET /issuer` | profile and public key |
| `POST /credentials` | `{commitment, attributes}` returns the signed credential and its `leafIndex` |
| `POST /credentials/:leafIndex/revoke` | sets the leaf to zero, returns the new root |
| `GET /root`, `GET /root/history?since=` | current root; recent roots for the staleness rule |
| `GET /path/:leafIndex` | Merkle path against the current root; `410 revoked` after revocation |
| `GET /metrics` | counters and latency per route |

Logs are one JSON line per request (route template, method, status, latency, leaf index, error
code). Never the commitment, attributes, signature, body or key material.

### 2.4 Admin API and live events (`issuer.admin v1`)

For the Admin Console. `GET /admin/leaves` (status issued/revoked per leaf; a revoked leaf shows
`"0"`; no attributes, no commitments), `GET /admin/tree` (the non-empty nodes per level so the UI
can draw the tree) and `GET /admin/events` (Server-Sent Events: `hello`, then `root-changed` with
`kind` insert or revoke; reconnect with `Last-Event-ID` replays up to 256 buffered events).
Revoke and `/admin/*` require a bearer token when `ISSUER_ADMIN_TOKEN` is set (compared in constant
time, never logged or accepted in a URL). With no token the admin surface is open; the demo runs it
on localhost or the compose network only. `POST /credentials` stays unauthenticated because clients
enrol through it. The persona script `issuer/scripts/seed-personas.js` enrols Alice (engineer,
engineering, clearance 2), Bob (contractor, operations, 1) and Carol (admin, it, 3) through the
client library.

## 3. Registry and revocation (M2)

- The registry is a `@zk-kit/incremental-merkle-tree` with Poseidon(2), depth 16 in v4, zero leaf
  value, rebuilt from stored leaves at start and compared with the stored root (a mismatch aborts
  the start). State is written atomically (mode 0600) and holds no secret, salt, attribute or
  signature; v4 attributes exist only inside the leaf hash. If persisting fails, the registry halts
  rather than serve a state it cannot recover.
- **Revoke = set the leaf to zero.** The root changes. Indices are never reused and a revoked
  commitment cannot be re-issued. A proof made against the old root still verifies
  cryptographically but carries a superseded root, which the gateway must reject.
- **30 s staleness rule** (`docs/CONTRACTS.md`, ruling in [`docs/decisions.md`](../decisions.md)): a
  verifier accepts a proof root `r` iff `r` is the current root, or `r` was superseded at most 30 s
  ago and every step from `r` to the current root was an insert. A root superseded by a revocation
  is never accepted once the verifier has seen the revocation, so the window cannot re-admit a
  revoked user. The issuer keeps superseded roots for 15 minutes (contract minimum: 10) and exports
  `isRootAcceptable` in `issuer/src/registry.js` as the reference implementation.
- G0 evidence ([plan](../plan/README.md), "Gate evidence"): revoking leaf 0 changed the root, the
  client then refused with `revoked (HTTP 410)`, and the old proof carried the superseded root.

## 4. Client prover (M4)

`client/`: library plus the `zkgate` CLI (`keygen`, `request`, `status`, `prove`).

- **Wallet.** `credentialSecret` and `credentialSalt` are generated locally (31 CSPRNG bytes each).
  The credential file lives in `$ZKGATE_HOME/credentials/<name>.json`, mode 0600 in a 0700
  directory, written by temp file and rename; `load` refuses a file readable by group or other.
  `keygen` refuses to overwrite, because a lost secret orphans the issued leaf.
- **Issuer pinning.** Before storing a credential the client checks that the issuer key equals the
  expected one (explicit `--issuer-key`, else the pin stored for that issuer URL, else trust on first
  use then pin), that returned attributes equal the requested ones, that the signature verifies over
  the profile's message and that the registry path starts at its own leaf.
- **Local policy pre-check.** `checkPolicyLocally` (from `circuits/lib`) tells the user, before any
  proving, which rule fails (`ROLE_NOT_ALLOWED`, `CLEARANCE_TOO_LOW`, `CREDENTIAL_EXPIRED`, ...).
  This saves proving time and explains the refusal. The reasons contain the user's own attributes,
  so they are shown locally and never logged server-side (floor 7).
- **In-memory proving.** The circuit input is built in memory and handed to
  `snarkjs.groth16.fullProve`; it is never written to disk (floor 6). Only `{proof, publicSignals}`
  may leave the machine. Output of the CLI holds identifiers and hashes only.
- **Fast verification.** Every proof is verified locally with `circuits/scripts/verify.js` before it
  is returned. That verifier is the fast implementation (about 5.6 ms warm, against about 14 ms for
  stock snarkjs; [`circuits/reports/perf-v4.md`](../../circuits/reports/perf-v4.md)) and also rejects
  non-canonical encodings that stock snarkjs accepts.
- **Path fetch.** The path is fetched once per registry root, not per gateway request.
- **Status.** v4 proving works end to end (G1-S1-IDEN-012): against the real issuer and the
  committed v4 keys, Alice→Wiki, Alice→File Share, Carol→Admin Panel, Carol→Wiki and Bob→Wiki
  prove and verify (about 1 s per proof including local verification), while the three
  denied combinations are refused locally before proving; see
  [`client/README.md`](../../client/README.md). The
  gateway endpoints the client calls (`/challenge`, `/access`) are the client's assumptions until
  the gateway exists.

## 5. Floor evidence

| Floor | Claim | Evidence |
|---|---|---|
| 6 | Private inputs never leave the client; the issuer sees only the commitment | issuer rejects `forbidden_field`; client request body is an allow-list `{commitment, attributes}`; registry file and logs hold no secrets; a G0 end-to-end run found 0 secret or attribute matches in the issuer log ([plan](../plan/README.md)) |
| 8 | Circuit, issuer and client use identical Poseidon parameters | the cross-check suite `issuer/test/crosscheck.v4.test.js` drives the real issuer, the real client library and the compiled v3 (depth 2) and v4 (depth 16) circuits (witness only); one run of `npm test --prefix issuer` printed `total checked values: 263`. Commitment, `attrHash`, leaf, root, nullifier and the public signals agree, before and after a revoke |
| 9 | No issuer private key or plaintext credential in the tree | key under gitignored `issuer/keys`, mode 0600, refused otherwise; wallet files are gitignored; test vectors derive TEST-ONLY keys from public labels |
| 3 | Revoked credential denied against the current root | issuer side: revoke zeroes the leaf, `410` on `/path`; the denial itself is the gateway's obligation 3 |

The 263 figure comes from running the suite for this chapter; it is printed by the suite, it is not
stored in a file. Safety review of floors 3, 6, 8 and 9 was requested at the time of the tasks
(plan rows) and is not recorded here as given.

## 6. Known limitations

- **Credentials are transferable.** Nothing binds a credential to a person or device: whoever copies
  the credential file (it holds the secret and salt) can prove as that user. Wallet file modes and
  device attestation (scope N4) reduce but do not remove this. This is a property of the design, not
  of a bug, and there is no repository document that states it, so it is listed here as our own
  assessment.
- **`/path` access-pattern leak.** `GET /path/:leafIndex` tells the issuer which leaf asks and when
  (`docs/CONTRACTS.md` privacy note). Caching per root reduces it; it is not removed. A private
  information retrieval scheme or fetching a whole level would be needed.
- **TOFU.** The issuer key is pinned on first contact. A hostile issuer on first contact is only
  caught if the user passes `--issuer-key` or an `expectedIssuer`.
- **DEV keys.** Single-party DEV-ONLY proving keys (circuit chapter, section 4); an issuer that
  also knows the trusted-setup secret could forge.
- **Open admin surface without a token.** Acceptable on localhost for the demo only.
- **Issuer learns attributes.** By the scope's model the issuer assigns them, so it sees them at
  enrolment; it never sees the secret.
- **One issuer, no key rotation.** Rotation would change the pinned key at the gateway and every
  client.
