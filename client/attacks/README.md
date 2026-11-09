# client/attacks — Attack Lab scripts (G2-S1-IDEN-021)

A library and CLI that produce, for each Attack Lab button, the exact HTTP request(s) the gateway
would receive, the expected outcome and reason code, and the evidence that the client itself
refuses (or cannot) do the dishonest part. With `--gateway` it also sends the requests and reports
actual vs expected. Used by the demo UI (Attack Lab) and the gateway's tests.

```sh
npm test --prefix client/attacks                      # node:test, ~35 s (real Groth16 proofs)
node client/attacks/bin/attacks.js list
node client/attacks/bin/attacks.js run replay forged  # prints requests + expectations, sends nothing
node client/attacks/bin/attacks.js run all --gateway http://localhost:8080 --issuer http://localhost:8001 [--admin-token T] [--skip-waits] [--lenient-codes]
```

`--gateway` needs `--issuer`: the issuer the gateway pins (personas are enrolled there; the
`revoked` attack revokes one throw-away persona through `POST /credentials/:i/revoke`). The world
plays both roles of issuer.api v2: for each persona the **admin** creates an enrolment
(`POST /admin/enrolments`, fresh `employeeId`) and the persona redeems the one-time code with its
commitment. Against a remote issuer the admin bearer token is therefore **required**
(`--admin-token` or `ISSUER_ADMIN_TOKEN`; never printed). `world.selfEnrol` / `world.reuseCode` are the
SR-03 probes (choose own attributes; re-enrol with a spent code), refused by the issuer. Without
`--issuer` an in-process issuer with a fresh key is used (offline mode: the proofs are real but no
gateway pins that key). Exit 0 ok, 1 an attack did not behave as expected, 2 usage.

## Library

```js
const lab = require("client/attacks/src");
const world = await lab.createWorld({ issuerUrl, adminToken });   // or no args: in-process issuer
world.setChallengeSource(lab.httpChallengeSource(gatewayUrl));    // else a local stand-in challenge
const built = await lab.buildAttack("replay", world);             // {id, title, scope, floor, obligations,
                                                                  //  display, local, requests, evidence}
const run = await lab.runAttack(built, { send: lab.httpSender(gatewayUrl), wait: (s) => world.advance(s) });
await world.close(); await lab.shutdown();
```

Build and run attacks one at a time: a revocation or enrolment moves the registry root under
proofs built earlier (a strict gateway then answers `ROOT_NOT_CURRENT`). Every attack enrols its
own fresh personas (new secret and salt), so nullifiers never collide between attacks.

`built.requests[i]`: `{label, method: "POST", path: "/access", body: {resource, nonce, proof, publicSignals}, expect: {outcome: "admit"|"deny", status, code, obligation}, waitSeconds?}`.
`built.local[i]`: `{stage: "client-input"|"client-precheck"|"witness"|"registry", refused: true, code, reasons}` — what
the honest client or the circuit does with the dishonest input (no proof exists; nothing is sent).
`built.display`: `[{code, text}]` for the red DENIED box. Results contain public values only; the
tests scan every output for the personas' secret, salt, commitment, signature, Merkle siblings and
forger key.

## Attacks and expected results

| id | Attack | What is sent | Expected | Obligation |
|---|---|---|---|---|
| `baseline` | honest Alice -> Wiki (control) | genuine proof | admit | 1-7 |
| `replay` | replay a captured proof | the same body twice | admit, then `NONCE_USED` | 6 |
| `replay_expired` | proof held past the nonce TTL | genuine proof after 125 s | `NONCE_EXPIRED` | 6 |
| `revoked` | revoked user tries again | proof made before the revocation (root R1); registry now at R2 | `ROOT_NOT_CURRENT` | 3 |
| `tamper` | contractor edits role to admin | local: input builder `BAD_SIGNATURE`, circuit refuses the witness. Sent: Bob's Wiki proof with public signals patched to the Admin Panel challenge | `PROOF_INVALID` | 1 |
| `forged` | self-signed credential | valid proof under a random forger key | `ISSUER_NOT_PINNED` | 2 |
| `wrong_service` | Bob -> Admin Panel; Alice's Wiki proof for Admin Panel | local: `POLICY_NOT_SATISFIED` (`ROLE_NOT_ALLOWED`, `CLEARANCE_TOO_LOW`), circuit refuses. Sent: Alice's Wiki proof (nonce from an Admin Panel challenge) on `resource: admin_panel` | `POLICY_MISMATCH` | 4 |
| `spam` | same nullifier twice in one epoch | two valid proofs, two fresh nonces, one nullifier | admit, then `RATE_LIMITED` | 7 |
| `expired` | expired credential | local: `CREDENTIAL_EXPIRED`, circuit refuses. Sent: proof with `now` = last valid second under a fresh nonce | `CHALLENGE_MISMATCH` | 5 |

Cryptographic facts the tests pin: the `forged`, `revoked`, `wrong_service` and `expired` proofs
**verify** with `circuits/scripts/verify.js` (the circuit alone cannot stop them; the gateway
obligation does); the `tamper` request fails verify; the tamper, wrong-service and expired inputs
make witness generation fail with a circuit assertion. The `tamper` patch is built to pass every
cheap check, so only Groth16 verify rejects it.

## Reason codes (PROPOSAL for the P3 gateway)

The contract (`access.public_signals v4`) names obligations, not codes. These are proposed; the
gateway may rename them, and `--lenient-codes` compares outcome only. Wire shape:
HTTP status plus `{"error":{"code":"<CODE>"}}`, success is any 2xx. Source of truth: `src/codes.js`.

| Code | HTTP | Obligation | Meaning |
|---|---|---|---|
| `MALFORMED_REQUEST` | 400 | encoding | not `{resource, nonce, proof, publicSignals}`, not 12 canonical decimals, or body nonce != signal 9 |
| `UNKNOWN_RESOURCE` | 404 | | no such service |
| `NONCE_UNKNOWN` | 403 | 6 | nonce not issued by this gateway |
| `NONCE_USED` | 403 | 6 | nonce already consumed by an admission |
| `NONCE_EXPIRED` | 403 | 6 | older than the 120 s TTL |
| `POLICY_MISMATCH` | 403 | 4 | `resourceId` or policy fields differ from the requested service's |
| `CHALLENGE_MISMATCH` | 403 | 5 | `now`, `epoch` or `resourceId` differ from the challenge stored with the nonce |
| `ISSUER_NOT_PINNED` | 403 | 2 | `issuerAx/issuerAy` != configured key |
| `ROOT_NOT_CURRENT` | 403 | 3 | `root` is not current / not acceptable under the staleness rule |
| `PROOF_INVALID` | 403 | 1 | Groth16 verification failed |
| `RATE_LIMITED` | 429 | 7 | `(nullifier, epoch)` already admitted |

### Proposed check order

The reason code of an attack that violates several things depends on the order. The tests' model
gateway (`test/helpers/modelGateway.js`, in-test only, not the P3 gateway) uses, and the expected
codes above assume: shape/encoding -> resource known -> **6** nonce known, unused, unexpired ->
**4** policy and `resourceId` of the requested service -> **5** `now`/`epoch`/`resourceId` equal the
stored challenge -> **2** issuer pin -> **3** root current -> **1** Groth16 verify -> **7**
nullifier per epoch -> admit (mark nonce used, record nullifier). Cheap checks come before the
pairing; a nonce is burned only on admission (contract: "marked used on admission"), so a denied
attempt does not consume it. Consequences worth deciding in P3:

- `wrong_service` yields `POLICY_MISMATCH` and not `NONCE_*` because the policy check precedes the
  stored-challenge comparison.
- `expired` ends in `CHALLENGE_MISMATCH` (obligation 5), not a distinct "expired" code: the circuit
  stops an expired credential from proving at the real `now`, and the gateway stops the old-`now`
  workaround.
- A real gateway that caches the root for up to 30 s (obligation 3 staleness rule) may admit the
  `revoked` proof until it refreshes; the contract's rule says a root superseded by a revocation is
  never accepted once the gateway has seen it. Run `revoked` after the gateway's refresh period, or
  give the gateway a per-request root fetch in the demo.

## Assumptions to confirm in P3

`GET /challenge?resource=<wiki|file_share|admin_panel>` -> `{nonce, resourceId, epoch, now, policy}`
(nonce a canonical decimal string) and `POST /access` as in `client/README.md`. The `replay_expired`
attack and the `expired` setup wait real time against a real issuer/gateway (125 s and 4 s); use
`--skip-waits` to skip the former.

## Floors

Private inputs stay in this process (floor 6): the library never writes an input or witness, sends
only `{proof, publicSignals}`, and the issuer sees `commitment` plus attributes only. Forger keys
are random per run and never persisted (floor 9). The attacks exercise floors 2-5 and add no gateway
state or log. `circuits/fixtures/v4` holds the static equivalents of `replay`, `revoked`, `forged`,
`spam`, `wrong_service` and `expired`; this module builds them fresh against a live issuer and
gateway.
