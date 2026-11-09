# client — wallet, issuer client, prover, CLI (M4)

Node (CommonJS, >= 20). Imports the shared encoder `circuits/lib` (ADR 0004) and never
re-implements encoding or crypto. Proves with the committed `circuits/setup/integrated_access_v{3,4}.{wasm,zkey}`
and verifies every proof with `circuits/scripts/verify.js` before returning it.

## Install and test

```sh
npm ci                       # at the repo root (snarkjs, circomlibjs, zk-kit)
npm test --prefix client     # node:test, no extra dependencies
npm run coverage --prefix client   # c8 via npx; fails below 80 % lines
```

## CLI

```sh
export ZKGATE_HOME=$HOME/.zkgate          # wallet directory (default ~/.zkgate)
zkgate keygen  --name alice --issuer http://localhost:8001
zkgate request --name alice --issuer-key Ax:Ay --code CODE     # CODE: one-time, from your administrator
zkgate status  [--name alice]                                  # shows the admin-assigned attributes
zkgate prove   --name alice --out ./proof                    # v3: proof.json + public.json
zkgate prove   --name alice --gateway http://gw --resource file_share [--submit]   # v4
zkgate prove   --name alice --challenge challenge.json       # v4 with a saved challenge
```

Exit codes: 0 ok, 1 error (one line on stderr, plus policy reasons), 2 usage. Output holds
identifiers and hashes only (commitment, leaf index, issuer-key fingerprint); never the secret, salt,
signature, path or circuit input. `prove` without `--out` prints `{proof, publicSignals}` on stdout.

**Enrolment.** The administrator creates an enrolment for you with your attributes and gives you a
one-time `CODE` (also accepted as `ZKGATE_ENROLMENT_CODE`). You cannot choose or change attributes
(`--role` and friends are refused); `request` sends only `{commitment, enrolmentCode}` and stores the
credential the issuer signed for the admin-assigned attributes. A used, expired or unknown code is
refused with the issuer's error code (`enrolment_used`, `enrolment_expired`, `invalid_enrolment_code`).
A revoked employee gets a new code from the admin; there is no self-service re-enrolment.

**Pinning the issuer key.** `--issuer-key Ax:Ay` (decimal public-key coordinates, from your
administrator or `GET /issuer` over a trusted channel) sets the expected issuer key at `request` time.
Use it on first contact: without it the client trusts the key the issuer advertises the first time and
pins it in `$ZKGATE_HOME/pins.json` (trust on first use). If `pins.json` exists but cannot be read or
parsed, the client **fails closed** (`PINS_CORRUPT`, nothing is sent, the code is not spent) instead of
silently re-pinning: fix or delete the file, or pass `--issuer-key`.

## Library API (`require("client/src")`)

| Export | Use |
|---|---|
| `Wallet({home})` | `keygen({name, profile, issuerUrl})`, `load`, `save`, `list`, `summary`, `getPin`/`setPin`, `Wallet.defaultHome(env)` |
| `IssuerClient({baseUrl, fetch?, timeoutMs?})` | `getIssuer`, `getRoot`, `requestCredential({commitment, enrolmentCode})`, `getPath(leafIndex)` (cached per root) |
| `requestCredential({wallet, name, issuer, enrolmentCode, expectedIssuer?})` | redeem the admin's code and verify before storing; `wallet.summary(name, {withAttributes: true})` includes the assigned attributes |
| `prove({credential, issuer, challenge?, artefactDir?})` | `{profile, proof, publicSignals}`; `prepareV3`/`prepareV4` build the input only |
| `parseChallenge`, `fetchChallenge({gatewayUrl, resource})`, `submitProof(...)` | v4 gateway challenge |
| `shutdown()` | release snarkjs worker threads (CLI exit, test teardown; not per request) |
| `ClientError` | `.code` (stable), `.message`, `.status?`, `.reasons?` |

Policy refusal: `ClientError` with `code` `POLICY_NOT_SATISFIED` (or `CREDENTIAL_EXPIRED`,
`EMPLOYEE_INACTIVE`) and `.reasons = [{code, message}]` (`ROLE_NOT_ALLOWED`, `CLEARANCE_TOO_LOW`, ...).
Reasons contain the user's own attributes: show them locally, never log them server-side (floor 7).
Revoked credential: code `revoked` (HTTP 410 from `GET /path`).

## Wallet layout (`credential.file v1`)

```text
$ZKGATE_HOME/credentials/<name>.json   0600, directory 0700, atomic temp-file + rename
$ZKGATE_HOME/pins.json                 0600, issuer key per issuer URL (public values)
```

`load` refuses a file readable by group or other. `keygen` refuses to overwrite (a lost secret
orphans the issued leaf). The default directory `.zkgate/` and `*.credential.json` are gitignored.

## Security notes

- **Floor 6.** `credentialSecret` and `credentialSalt` are generated locally (31 CSPRNG bytes) and only
  ever read by the in-process prover. `IssuerClient.requestCredential` builds its body from an
  allow-list `{commitment, enrolmentCode}`; extra properties (secrets, attributes) are dropped, a
  malformed code is an error before any network call. The circuit input is built in memory, passed to `snarkjs.groth16.fullProve`, and never written.
- **Issuer key check.** Before a credential is stored the client checks: the issuer key equals the
  expected key (explicit `expectedIssuer` > stored pin for that URL > trust on first use of the key
  from `GET /issuer`, then pinned; a corrupt pin file fails closed); the returned attributes are the
  profile's exact set; the signature verifies over the profile's message and those attributes; the registry path starts at the client's own leaf. TOFU
  protects against a credential signed by a key other than the advertised one; for a hostile issuer on
  first contact, pass `--issuer-key` or an `expectedIssuer`.
- **Path privacy.** The path is fetched once per registry root (the root fetch carries no leaf index).
- **DEV keys.** The committed v3 proving key is a single-party DEV key (see `circuits/setup/ARTIFACTS.md`).

## v4 proving (G1-S1-IDEN-012)

Flow for the UI or any caller (all exports from `require("client/src")`):

```js
const { Wallet, IssuerClient, fetchChallenge, prove, submitProof, shutdown } = require("client/src");
const wallet = new Wallet({ home });                    // credential.file v1, profile "v4"
const issuer = new IssuerClient({ baseUrl: issuerUrl });
const challenge = await fetchChallenge({ gatewayUrl, resource: "file_share" });  // parsed + validated
const { proof, publicSignals } = await prove({ credential: wallet.load("alice"), issuer, challenge });
await submitProof({ gatewayUrl, resource: "file_share", nonce: challenge.nonce, proof, publicSignals });
await shutdown();                                       // once, at process / test end
```

- `prove` order: (1) `parseChallenge` (nonce canonical decimal string, `epoch == floor(now/600)`,
  masks in range); (2) local policy check at `challenge.now` (no network, no artefacts); (3) fetch the
  Merkle path (`410 revoked` -> `ClientError.code "revoked"`); (4) `fullProve` with the committed
  `integrated_access_v4.{wasm,zkey}`; (5) `publicSignals` must equal `expectedPublicSignals`
  (`PROOF_INVALID` otherwise); (6) `verify.js` fast path against the committed verification key.
- Public signals (12, `access.public_signals v4` order): `nullifier, root, issuerAx, issuerAy,
  roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch`.
- Error codes (`ClientError.code`): `CHALLENGE_REQUIRED`, `INVALID_CHALLENGE`, `POLICY_NOT_SATISFIED`
  (reasons `ROLE_NOT_ALLOWED`, `DEPT_NOT_ALLOWED`, `CLEARANCE_TOO_LOW`, `DEVICE_NOT_COMPLIANT`),
  `CREDENTIAL_EXPIRED`, `EMPLOYEE_INACTIVE`, `revoked`, `ARTEFACTS_MISSING`, `PROVE_FAILED`,
  `PROOF_INVALID`. Local refusals generate no proof and send nothing to the gateway.
- Nullifier = Poseidon(secret, resourceId, epoch): stable across nonces for one resource and epoch,
  different across resources (unlinkable), different per user.
- Timings (dev container, 1 thread, depth 16, warm): `prove` about 1.0 s per proof (first call 1.3 s:
  wasm load + path fetch); local verify is included in that figure. Artefacts: zkey 6.1 MB.
- `shutdown()` terminates the snarkjs worker threads; call it once at the end (the CLI does).
- `--challenge FILE` takes the JSON object returned by `GET /challenge` (see assumptions below).

## Tests

`node --test`, 79 tests; `npm run coverage --prefix client` reports about 96 % lines (floor 80 %).
`test/e2e.v4.test.js` runs the real issuer (`issuer/src/server.js`, temp key and data dirs) and a
challenge stub (`test/helpers/challengeStub.js`, contract-shaped, not the gateway) with real proofs:
Alice to Wiki and File Share, Carol to Admin Panel and Wiki, Bob to Wiki admitted; Bob to File Share
and Admin Panel and Alice to Admin Panel refused locally; revoked, expired and bad-epoch cases;
nullifier stability. `test/cli.v4.test.js` drives the CLI as a child process.

## Status

- v3 (G0-S1-IDEN-003): keygen -> request -> prove -> verify, tested end to end against a stub issuer.
- v4 (G1-S1-IDEN-012): complete end to end against the real issuer and a challenge stub.

## Assumptions for the gateway (P3), to confirm

The gateway does not exist yet; the client side is written against the contract with these guesses
(`src/challenge.js`):

- `GET {gateway}/challenge?resource=<wiki|file_share|admin_panel>` -> `{nonce, resourceId, epoch, now, policy:{roleMask, deptMask, minClearance, requireDevice}}`;
  `nonce` a canonical decimal string (128 random bits, never a JSON number); `epoch == floor(now/600)`
  or the client rejects the challenge.
- `POST {gateway}/access` `{resource, nonce, proof, publicSignals}` -> 2xx admitted; 4xx `{error:{code}}`.
- The client proves exactly the challenge it was given, with `policy` from the challenge (the local
  check uses it; the gateway still enforces its own).
