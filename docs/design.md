# ZK Access Gate — Design

Zero-trust gateway that admits employees to internal services on a Groth16 proof that their issuer-signed credential is valid, unrevoked and satisfies the resource policy, without the gateway learning who they are.

## Inherited documentation

These files are **authoritative** and are not restated or rewritten here. Read them directly:

- `docs/project-scope.md`
- `docs/technology-explained.md`

This file records design that those documents do not cover, and decisions taken after them.

## Module boundaries

Each role in `docs/strategy.md` §2 owns a boundary. The interfaces between them are recorded
in `docs/CONTRACTS.md`.

### architect

Interface contract, ADRs, module boundaries, public-input order.

_Design notes: to be written by `architect` as the boundary takes shape._

### circuits

M3 access circuit, circuit tests (circom_tester), trusted setup, constraint optimisation.

**Boundary (architect, G0-S1-ARCH-010; ADR 0002, 0004).**

| Path | Contents | Public surface |
|---|---|---|
| `circuits/integrated_access_v3.circom`, `circuits/components/*.circom` | P1's v3 (base, not rewritten in place) and P2's new components beside it | contracts `credential v3`, `access.public_signals v3` |
| `circuits/integrated_access_v4.circom` | v4 main, depth 16 (8/20 mains for benchmarks only) | `credential v4`, `access.public_signals v4` |
| `circuits/lib/` | **the only encoder** (CommonJS): field encoding and canonical-decimal parse/emit; `commitment`; v4 `attrHash`; Merkle helpers with v3's `pathIndices` semantics and the zk-kit mapping; circuit input builder; public-signal codec; enums and demo policies; v4 local policy pre-check; profiles | `profiles.v3`, `profiles.v4`, each `{name, depth, message(cred), leaf(cred), publicSignals, artefacts:{wasm, zkey, vkey}}` |
| `circuits/test/`, `circuits/test/vectors/<profile>/` | circuit tests, TEST-ONLY reference vectors | vectors are the cross-check source for `identity` |
| v4 artefacts (path chosen by CIRC-037) | committed depth-16 `.wasm`, `.zkey`, vkey, manifest, fixtures (ADR 0009) | consumed by `client/` (prove) and `gateway/` (verify) |

Rules: `circuits/lib` has no I/O beyond reading artefact paths, no network, no key storage; it never
holds an issuer private key (signing takes the key as an argument from `issuer/`). It depends only
on `circomlibjs`, `@zk-kit/incremental-merkle-tree` (helpers) and `snarkjs` (codec/prove wrappers).

_Design notes: to be written by `circuits` as the boundary takes shape._

### identity

M1 issuer, M2 Merkle registry + revocation, M4 client prover.

**Boundary (architect, G0-S1-ARCH-010; ADR 0003, 0004, 0005).** Node CommonJS, one profile per
process, every circuit-facing value computed through `circuits/lib`.

| Module | Responsibility | Must not |
|---|---|---|
| `issuer/` signing | load or create the persistent issuer key (`issuer/keys/`, gitignored, 0600); sign the profile's message (`credential v3`: commitment; `v4`: `attrHash`); validate attributes against the profile and enums | hold or log `credentialSecret`/`credentialSalt`; expose the private key; compute Poseidon outside `circuits/lib` |
| `issuer/` registry | `@zk-kit/incremental-merkle-tree` at profile depth; insert on issue; revoke = leaf `0`; root history with insert/revoke cause (30 s staleness rule) | reuse leaf indices; drop history inside the retention window |
| `issuer/` HTTP | `issuer.api v1`: strict schemas, `forbidden_field`, error codes, structured logs, counters | log commitments, attributes, signatures, keys |
| `client/` wallet | keygen (secret + salt, CSPRNG), `credential.file v1` read/write (0600, atomic), verify an issued credential before storing it | send `secrets` anywhere; read world-readable credential files |
| `client/` challenge client (v4) | fetch `{nonce, resourceId, epoch, now, policy}` from the gateway; submit proof + public signals | invent `now`/`epoch` locally |
| `client/` prover | fetch `/path`, build input via `circuits/lib`, local policy pre-check with reason (v4), snarkjs `groth16.fullProve` with the profile's artefacts | send the witness, path or attributes off the machine |
| `client/` CLI | `keygen`, `request`, `prove`, `submit` over the library; the UI (`ui/`) calls the same library API | contain logic the library lacks |

_Design notes: to be written by `identity` as the boundary takes shape._

### gateway

M5 verifier gateway (reverse proxy, nonce, root, nullifier, sessions) and the three demo services.

_Design notes: to be written by `gateway` as the boundary takes shape._

### frontend

M6 demo UI: User Portal, Gateway Live View, SSO vs ZK split screen, Admin Console, Attack Lab.

_Design notes: to be written by `frontend` as the boundary takes shape._

### devops

Docker Compose, make demo, CI, M7 Keycloak baseline.

_Design notes: to be written by `devops` as the boundary takes shape._

### qa

Integration and e2e tiers, M8 benchmarks (median/p95 over 100 runs).

_Design notes: to be written by `qa` as the boundary takes shape._

### safety

Floors, threat model, security test suite and Attack Lab cases.

_Design notes: to be written by `safety` as the boundary takes shape._

## Data flows (P2 lane)

Recorded by `architect` (G0-S1-ARCH-010). Contracts named in brackets.

```
enrolment   client.keygen ─(local: secret, salt → commitment)
            client.request ── {commitment, attributes} ──▶ issuer  POST /credentials   [issuer.api v1]
                           ◀── {credential: attributes, signature, issuer, leafIndex, profile}
            client verifies signature + path, writes credential file           [credential.file v1]

revocation  admin ── POST /credentials/:i/revoke ──▶ registry (leaf i ← 0, new root, history "revoke")
            gateway ── GET /root, /root/history (≤ 30 s) ──▶ registry

access (v4) client ── GET challenge ──▶ gateway: {nonce, resourceId, epoch, now, policy}
            client ── GET /path/:i (cached per root) ──▶ registry
            client: circuits/lib input builder → snarkjs prove (local)          [credential v4]
            client ── {proof, publicSignals[12]} ──▶ gateway                    [access.public_signals v4]
            gateway: canonical check → verify → issuer pin → root rule → challenge match
                     → nonce single-use → (nullifier, epoch) → session → service
```

What leaves the user's machine: the commitment and attributes to the issuer at enrolment; the leaf
index to the registry when fetching a path; the proof and 12 public signals to the gateway. Never
`credentialSecret`, `credentialSalt`, the signature or the Merkle path towards the gateway, and
never the secret or salt to anyone (floor 6). In G0 the access flow is v3 (`[root]`) and ends at
verify; there is no gateway admission on v3.
