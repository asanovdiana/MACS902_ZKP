# issuer — M1 issuer + M2 registry (`issuer.api v1`)

Node.js (CommonJS) service, Fastify. Tasks: G0-S1-IDEN-001/002/004 (profile `v3`),
G1-S1-IDEN-010/011 (profile `v4`). The API and its error codes are specified in
`docs/CONTRACTS.md` (`issuer.api v1`, `credential v3`, `credential v4`); this file only says how to
run it. All Poseidon, EdDSA and Merkle-tree work is `circuits/lib` (ADR 0004), required as
`../../circuits/lib`; nothing is re-implemented here. It resolves `circomlibjs` and
`@zk-kit/incremental-merkle-tree` from the repository-root `node_modules` (`npm ci` at the root),
and `fastify` from `issuer/node_modules` (`npm ci --prefix issuer`).

## Run

```sh
npm ci                      # repository root (circuits/lib dependencies)
npm ci --prefix issuer
ISSUER_PROFILE=v4 npm start --prefix issuer     # listens on 127.0.0.1:8100
npm test --prefix issuer                         # suite
npm run coverage --prefix issuer                 # c8, fails below 80 % lines
```

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `ISSUER_PROFILE` | `v3` | `v3` or `v4`; one profile per process, named in every response |
| `ISSUER_KEY_DIR` | `issuer/keys` | directory of the private key (gitignored, mode 0700) |
| `ISSUER_DATA_DIR` | `issuer/data` | registry state (gitignored via `issuer/.gitignore`) |
| `ISSUER_HOST` / `ISSUER_PORT` | `127.0.0.1` / `8100` | bind address |
| `ISSUER_ADMIN_TOKEN` | **required** | bearer token for `/admin/*` and revoke. The issuer **refuses to start** without it unless `ISSUER_INSECURE_DEV=1` (SR-04) |
| `ISSUER_INSECURE_DEV` | unset | `1` = local development only: no token needed (admin surface open), a loud warning at start, and v3 may use the legacy open enrolment. Any other value: off. Never set it on a shared network |
| `ISSUER_ENROLMENT_TTL_SECONDS` | `3600` | default lifetime of an enrolment code (60..604800) |
| `ISSUER_SSE_HEARTBEAT_SECONDS` | `15` | SSE heartbeat comment interval |
| `ISSUER_LOG_LEVEL` | `info` | pino level |

Tests set `ISSUER_KEY_DIR`/`ISSUER_DATA_DIR` to temp directories (via `config` overrides); they never
touch the real key directory.

`docker`/`compose` users: set `ISSUER_ADMIN_TOKEN` (a random secret) for the issuer, and give the same
value to whoever runs `seed-personas.js` or the Admin Console server; do not set `ISSUER_INSECURE_DEV`.

## API

All routes, bodies and errors: `docs/CONTRACTS.md` `issuer.api v1` and `v2` (enrolment), `issuer.admin v1.1`. Summary:
`GET /issuer`, `POST /credentials`, `POST /credentials/:leafIndex/revoke`, `GET /root`,
`GET /root/history?since=`, `GET /path/:leafIndex` (`410 revoked` after revocation).
Additions recorded as `issuer.api v1.1`: **`GET /metrics`** returns
`{profile, leaves, issued, revoked, rootChanges, sseClients, sseEvents, errors:{code:n}, requests:{"METHOD route":{count, latencyMsSum, latencyMsMax}}}`.
Unknown routes answer `404 not_found`.

Implementation notes on points the contract leaves open:

- Attribute values are JSON integers only (no D6 labels, no strings or booleans).
- An unknown top-level key in the `POST /credentials` body is `400 invalid_request`; an `attributes` key is `400 attributes_not_accepted` (the admin assigns them).
- Check order: JSON, `forbidden_field`, `commitment`, `attributes`/unknown keys, enrolment code (`invalid_enrolment_code`, `enrolment_used`, `enrolment_expired`), then `duplicate_commitment` /
  `tree_full`. A revoked commitment stays "issued" (it cannot be re-issued). A refused redemption never consumes the code.
- Forbidden keys (`credentialSecret`, `credentialSalt`, `secret`, `salt`) are matched at any depth,
  ignoring case, `_` and `-`.
- `GET /root/history`: entries are kept for 15 minutes after being superseded (contract: at least
  10); the current root is always present. `src/registry.js` exports `isRootAcceptable(history,
  root, gatewayNow, window)`, a reference implementation of the staleness rule.

## Admin API (`issuer.admin v1`, G2-S1-IDEN-020)

For the Admin Console; full spec in `docs/CONTRACTS.md`.

| Route | Returns |
|---|---|
| `GET /admin/leaves?from=&limit=` | `{profile, depth, total, from, leaves:[{leafIndex, status:"issued"\|"revoked", leaf, issuedAt, revokedAt}]}`; a revoked leaf shows `leaf: "0"`. No attributes, no commitments. |
| `GET /admin/tree` | `{profile, depth, root, leafCount, zeros[depth+1], levels:[{level, nodes[]}]}`: per level only the `ceil(leafCount/2^level)` non-empty nodes; any other node is `zeros[level]`. `root` equals `GET /root`. |
| `GET /admin/events` | Server-Sent Events: `hello {profile, root, seq}`, then `root-changed {seq, root, prevRoot, kind:"insert"\|"revoke", leafIndex, at}` (`id:` = `seq`), plus `: hb` heartbeats. Reconnect with `Last-Event-ID` replays missed events from a 256-event buffer. |
| `POST /credentials/:leafIndex/revoke` | unchanged, but bearer-protected when a token is set |

**Token.** With `ISSUER_ADMIN_TOKEN` set, `/admin/*` and revoke need `Authorization: Bearer <token>`
(`401 unauthorized` otherwise). It is read from the environment, compared in constant time, and never
logged or accepted in a URL; a browser `EventSource` cannot send the header, so the console should
use `fetch` streaming or its own server as a proxy. Without a token the issuer does not start (SR-04); with `ISSUER_INSECURE_DEV=1` the admin surface
is **open** and a warning is logged: local development only.
`POST /credentials` is not behind the token: the user redeems the admin-issued one-time code there
(see Enrolment).

```sh
ISSUER_ADMIN_TOKEN=demo-admin ISSUER_PROFILE=v4 npm start --prefix issuer
curl -N -H 'Authorization: Bearer demo-admin' http://127.0.0.1:8100/admin/events
```

Leaf `issuedAt`/`revokedAt` are stored in `registry.json` (a state written before this change lists
them as `null`). Each SSE connect/disconnect is one log line with the client count only.

## Enrolment (issuer.api v2, SR-03)

Nobody chooses their own attributes. The flow:

1. **Admin** (bearer token): `POST /admin/enrolments {employeeId, attributes, ttlSeconds?}` returns
   `{enrolmentId, code, expiresAt}`. The code is 192 random bits, shown **once**, stored only as a
   SHA-256 hash, single use, valid 1 h by default. The admin hands it to the employee out of band.
2. **Employee**: `zkgate keygen` (secret and salt stay in the wallet), then
   `zkgate request --issuer URL --code CODE`, which sends `{commitment, enrolmentCode}`. The issuer
   signs the **admin-assigned** attributes and returns the credential.
3. **One live credential per employee** (`employeeId`, case-insensitive). A second enrolment is
   refused while one is pending (`enrolment_pending`; cancel it with `DELETE /admin/enrolments/:id`) or
   while the first credential is live (`employee_has_credential`). Policy: **no implicit
   re-enrolment**. To replace a credential the admin revokes the old leaf and then creates a new
   enrolment; a revoked employee cannot come back on their own (their old code is spent, a missing
   code is `403`).
4. `GET /admin/enrolments` lists `{enrolmentId, employeeId, status, createdAt, expiresAt, redeemedAt,
   leafIndex}`. It shows `employeeId` (the console needs it to revoke the right person; the admin typed
   it and the issuer already knows it) but never the code, a commitment or an attribute. `/admin/leaves`,
   `/admin/tree` and `/admin/events` stay identity-free.

Where the identity lives: `employeeId` and the *pending* attributes are in `ISSUER_DATA_DIR/enrolments.json`
(mode 0600; the attributes are erased when the code is redeemed or cancelled, the `employeeId` ->
`leafIndex` link stays). They are never logged, never in `/metrics`, never sent to the gateway. The
issuer still sees only the commitment from the user (floor 6).

`ISSUER_INSECURE_DEV=1` keeps the old open form `{commitment, attributes}` for the **v3** baseline only;
v4 has no open enrolment in any mode. Metrics: `enrolmentsCreated`, `enrolmentsRedeemed`,
`enrolmentsPending`.

## Demo personas (`scripts/seed-personas.js`, G2-S1-IDEN-022)

Enrols Alice (engineer, engineering, clearance 2), Bob (contractor, operations, clearance 1) and
Carol (admin, it, clearance 3), all device-compliant and active, the way real employees are enrolled:
the script plays the **admin** (creates one enrolment per persona through `/admin/enrolments`, needs
`ISSUER_ADMIN_TOKEN` or `--admin-token`) and then each persona's wallet redeems its code with the client
library (`keygen` then `request`). One wallet home per persona, so each is a separate `ZKGATE_HOME`:
`<home>/alice`, `<home>/bob`, `<home>/carol`. Secrets stay in those wallets; the issuer receives the
commitment and the code only. Re-running skips personas already issued (a revoked persona is skipped
too: re-enrolling is the admin's decision); a stale unredeemed enrolment is cancelled and replaced.

```sh
ISSUER_ADMIN_TOKEN=demo-admin ISSUER_PROFILE=v4 npm start --prefix issuer &
ISSUER_ADMIN_TOKEN=demo-admin node issuer/scripts/seed-personas.js --issuer http://127.0.0.1:8100 --home ./demo-wallets \
     [--expiry 4070908800] [--only alice,bob] [--v3-provable]
ZKGATE_HOME=./demo-wallets/alice client/bin/zkgate status --name alice
```

- **v4 expiry** defaults to 4070908800 (2099-01-01); `--expiry` / `ZKGATE_SEED_EXPIRY` override it.
- **v3 profile.** Attributes are the same people by their D6 numbers (no dept or expiry). v3's File
  Share template admits only role in {2,3} and clearance in {2,3}, so by design none of the three
  can prove on v3 (Alice role 0; Bob clearance 1; Carol role 1). `--v3-provable` seeds Alice as
  role 2 / clearance 2 so the G0 end-to-end run has one credential that proves.
- Output: one JSON line per persona (name, leafIndex, commitment, skipped); no secrets or attributes.

## Keys

32 random bytes, hex in `ISSUER_KEY_DIR/issuer.key`, generated once (temp file + `link()`, so an
existing key is never overwritten), mode 0600; the start-up refuses a file with group/other
permissions or a malformed one (the error never prints content). The key **directory** is created
0700 (whatever the umask) and a pre-existing directory accessible by group or other is refused (SR-10). The same key is used across
restarts. Only the public key is exposed (`GET /issuer`); the signer keeps the private key in a
closure. Back the key up out of band; losing it invalidates every issued credential.

## Persistence

`ISSUER_DATA_DIR/registry.json` (mode 0600, written atomically): profile, commitments, leaves,
revocation flags and the root history. It holds no secret, salt, attribute or signature (v4
attributes exist only inside the leaf hash). On start the tree is rebuilt from the stored leaves
and the root is compared with the stored one; a mismatch or a profile change aborts the start.
If persisting fails after the tree changed, the registry halts (500 `internal`) and the process
must be restarted from the last persisted state.

## Profiles

| | `v3` | `v4` |
|---|---|---|
| depth / leaves | 2 / 4 | 16 / 65 536 |
| attributes | `role, clearance, deviceCompliant, employeeActive` (0..3, 0..3, 0/1, 0/1) | `role, dept, clearance, deviceCompliant, employeeActive, expiry` (enums per ADR 0008; `now < expiry <= 2^53-1`) |
| signed message / leaf | `commitment` | `attrHash(attributes, commitment)` |

The issuer is told only `{commitment, enrolmentCode}` (the attributes come from the admin's enrolment); a body carrying a secret or salt is rejected
with `400 forbidden_field` and the value is not logged (floor 6).

## Logs and metrics

One JSON line per request: `route` (template), `method`, `status`, `latencyMs`, `leafIndex`
(when the route has one), `code` (on errors). Never the commitment, attributes, signature, request
body or key material.
