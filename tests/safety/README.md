# Safety floor tier (`tests/safety`)

Owner: `safety`. One file per floor (`docs/strategy.md` §6); every test ID `F<floor>.<nn>` is
registered in `MANIFEST.json`.

```sh
npm ci && npm ci --prefix issuer      # once: root (circomlib, snarkjs, zk-kit) and issuer (fastify)
npm test --prefix tests/safety        # node:test, ~1-2 min, no circom compile needed
```

Requires circom 2.2.3 on `PATH` only for F8.05 (it runs `issuer/test/crosscheck.v4.test.js`,
which compiles the v4 main at `--O0` into `build/test/`).

What the tier reuses (nothing is re-implemented): `circuits/lib`, the committed v4 artefacts
(`circuits/setup/integrated_access_v4.wasm` + verification key), `circuits/fixtures/v4`,
`circuits/scripts/verify.js`, `circuits/reports/mutation-v4.json`, `issuer/src` (in-process, temp
key/data dirs) and `client/src`. Tests named `... gateway ...` with `todo` are the gateway half of
floors 3, 4, 5 and 7: the gateway (P3) is not in this repository.

## Append-only rules (floor 10)

- Never delete, rename or move a test file or a test ID; never remove a `MANIFEST.json` entry.
- New tests get a new ID and a new manifest entry appended at the end.
- A test may be tightened, never weakened. A wrong test is fixed by adding a corrected test with a
  new ID and marking the old one `todo` with the reason, reviewed by `safety`.
- `floor10-append-only.test.js` enforces the first three mechanically (manifest subset of HEAD, no
  deletions/renames in git history); the last is a review rule.

## Changelog

### G1-S1-SAFETY-021: `issuer.api v2` (admin-approved enrolment)

Why bodies changed: **API version change, not weakening.** G1-S1-IDEN-014 replaced open enrolment
(`POST /credentials {commitment, attributes}`, `issuer.api v1`) with admin-approved enrolment
(`issuer.admin v1.1` `POST /admin/enrolments` under the bearer token, then
`POST /credentials {commitment, enrolmentCode}`, `issuer.api v2`), and the issuer now refuses to
start without `ISSUER_ADMIN_TOKEN` (SR-04). The tests below kept their ID, title and floor property;
only the path they drive changed. No assertion was weakened; every changed test asserts at least what
it did before.

| ID | What changed and why |
|---|---|
| helpers | `makeIssuer` runs the production posture (admin token, `insecureDev: false`) and returns `token` and `admin()`; new `adminEnrol`, `enrolViaAdmin` (admin enrols, the wallet redeems the code through the real client), `encodeAttrs` (D6 labels to integers, which the admin route takes) |
| F2.11 | the same seven bad attribute sets are refused `400 invalid_attributes` where attributes now enter (the admin route), and the user route refuses them outright (`attributes_not_accepted`). Added: an assigned expiry that passes before redemption is `410 enrolment_expired`, nothing signed or inserted |
| F2.14 | todo -> real (SR-03 closed): attributes rejected with/without a code; no/unknown/malformed code `403 invalid_enrolment_code`; admin route without/with a wrong bearer or a token in the URL `401`; the credential carries the admin's attributes whatever the client passes; start refused without a token (v4, v3); v4 has no open enrolment even in insecure-dev |
| F3.* setup | holders enrol through `enrolViaAdmin`; revoke and `/admin/leaves` carry the bearer (now required) |
| F3.10 | todo -> real (SR-03 closed): a revoked holder's spent code is `409 enrolment_used`, no/guessed code `403`, self-chosen attributes `400`, registry size unchanged; the admin cannot re-enrol a live holder (`employee_has_credential`), can re-enrol a revoked one only with the bearer; the old leaf stays revoked |
| F6.01 | added `issuer.api v2`-shaped bodies (with `enrolmentCode`): `forbidden_field` is still first |
| F6.02 | client allow-list is now exactly `["commitment","enrolmentCode"]`; `attributes` joined the properties that never reach the wire; a codeless call sends nothing |
| F6.03 | the only client body is `{commitment, enrolmentCode}` (and there is exactly one) |
| F7.* setup | enrolment through the admin with email-shaped employee ids; the busy session adds every v2/admin v1.1 refusal; F7.01 and F7.03 additionally require that no employee id (username/email) and no enrolment code appears in the log or in admin/metrics output |
| F8.* setup | `enrolViaAdmin`; `/admin/leaves` with the bearer |
| F9.05 | unchanged body; passes again because `makeIssuer` supplies the token |
| F1.01 | tightened: `total >= 102` (was 95), CIRC-039 added `eddsa_verifier.circom` |

New IDs: F1.09 (whole v4 closure mutated, no exception; SR-18), F5.08 (one live credential per
person; SR-03), F6.09 (corrupt pins fail closed before the code is sent; SR-09), F6.10 (issuer
enrolment state keeps no attribute/code/commitment after redemption), F9.07 (key directory 0700,
open directory refused; SR-10), F9.08 (no token, no start; bearer required on every admin route;
SR-04). F1.04 is kept and still passes (its exception branch is now unreachable; F1.09 is the strict
form).

### G1 gate floors review: PSE ppot 0080 re-key (G2-S1-CIRC-040a), SR-20 (G1-S1-IDEN-015)

No existing body changed. New IDs: F9.09 (both committed keys name a public phase 1; for
`pse-ppot-0080` the manifest blake2b equals the `ptau.sh` pin and the provenance records the source,
the 0080 transcript linkage and the checks not run; `DEV-ONLY` + single-party limitation kept while
phase 2 has fewer than two contributions), F9.10 (vkey/zkey/wasm hashes equal their manifests;
`fixtures.json` and the fixtures' vkey copy name the current key; every fixture verifies under it and
under no superseded v4 vkey from git history), F9.11 (SR-20: `buildServer` refuses to start without a
token for any non-boolean `insecureDev`). F9.10 terminates the verifier's worker threads in
`t.after`, since it is the only verifier user in its file.

### G2-S1-SAFETY-022: ceremony-ready status rule (F9.06 superseded on install by F9.12)

Problem: F9.06 requires `status === "DEV-ONLY"` and a `single-party phase 2` limitation for both
committed keys, unconditionally. A genuine multi-party install (`circuits/scripts/ceremony.sh`,
`buildManifest`: >= 2 contributions, public phase 1, public beacon -> `DEMO-ONLY`, multi-party
limitation) would fail it, and floor 10 forbids removing or renaming it.

Decision: **F9.06 is kept with its ID, title and body unchanged; only a `todo` option was added, and
it is computed, not fixed.** While every committed manifest has `phase2.contributions < 2` (now), the
option is `false` and F9.06 stays a hard test. Once a committed manifest claims >= 2 contributions,
F9.06 reports as `todo` ("superseded by F9.12"), per the "wrong test" rule above. The property it
protects (no key is presented as more trustworthy than its provenance supports) is asserted at
least as strongly by the new **F9.12**, which runs unconditionally:

- single-party (fewer than 2 contributions, or a non-public beacon, or a non-public phase 1, or any
  missing multi-party evidence) => `status: "DEV-ONLY"`; with < 2 contributions also the
  `single-party phase 2 ... could forge proofs` limitation, a `status_detail` that says single-party,
  and no multi-party limitation; a non-public beacon must be listed as a limitation;
- multi-party only with **all** of: integer `phase2.contributions >= 2` (an array is refused), public
  phase 1 (`pse-ppot-0080` / `hermez`), `phase2.beacon_public === true`, beacon and beacon
  contribution hashes, `transcript` path and `transcript_sha256`, `contributors` listing every
  contribution in order with a name and a distinct 128-hex hash; and the named transcript must
  exist (committed in the tree for the committed keys), hash to `transcript_sha256` and agree with
  the manifest on contributors, beacon and phase-1 blake2b => `status: "DEMO-ONLY"`, a
  `multi-party phase 2 (N contributors ... could forge proofs` limitation, no single-party line;
- every status is `DEV-ONLY` or `DEMO-ONLY` (never "production"), and `status_detail` says
  "not for production";
- the fixtures' `TEST_ONLY` matches the v4 key: `DEV-ONLY` + single-party limitation, no
  multi-party claim, for a single-party key; `DEMO-ONLY` + multi-party and no `single-party` for a
  multi-party key; always "Never use outside tests".

F9.12 is checked against the committed manifests and fixtures (pass), against manifests
`buildManifest` produces from synthetic transcripts (3 and 2 contributors with a public beacon ->
`DEMO-ONLY`; local beacon, dev phase 1, 1 contribution -> `DEV-ONLY`; all pass), and against 28
mismatched manifests and 7 mismatched fixture texts (each must yield a violation). For a multi-party
install, `circuits` must update `access-fixtures.js` `TEST_ONLY` (multi-party, `DEMO-ONLY`, no
"single-party") and commit the transcript at the path the manifest names.

Not asserted (observation): the committed `status_detail` reads "DEMO-ONLY (single-party phase 2)"
while `status` is `DEV-ONLY`; the status field governs, and the detail names the single-party
limitation, so it is not an overstatement, but `circuits` should align the wording when re-keying.

### P3 gateway: F3.09, F4.06, F5.07, F7.05 (todo -> real)

The gateway half of floors 3, 4, 5 and 7 now runs against the real P3 gateway. No ID, title or order
changed; each test only went from `todo` to a real body (tightening). `gateway.js` (new) starts the
compiled P3 gateway (`p3/gateway/dist`, build with `npm ci --prefix p3 && npm run build --prefix p3`;
the test FAILS with that instruction if the build is missing, it never skips), the real issuer
(`makeIssuer`, listening), the real Wiki service and the real client prover. Issuer and gateway share
one `clockAt` clock, so TTLs, epochs and the 30 s staleness window are deterministic (no sleeps).

| ID | What it asserts |
|---|---|
| F3.09 | control admit + session; insert-only root change keeps a held proof valid; after the revocation the held proofs are `ROOT_NOT_CURRENT` (immediately, inside the root cache window, and 60 s later), the pre-revocation session is revoked (401), no new proof can be made, the committed `stale_root_bob_wiki` fixture is never admitted |
| F4.06 | replay `NONCE_USED`; 4 concurrent identical requests admit exactly one; presented at exactly 120 s admitted; at 121 s `NONCE_EXPIRED` and burnt; committed fixture and forged nonces `NONCE_UNKNOWN` |
| F5.07 | second proof (fresh nonce) in the epoch `RATE_LIMITED`; a `PROOF_INVALID` attempt does not consume the budget; another user independent; 3 concurrent same-nullifier proofs admit exactly one; the next epoch changes the nullifier and admits once more |
| F7.05 | busy session (admissions, proxied requests, every denial, revocation, operator/admin reads); the gateway log, event stream, operator events and in-memory state contain no employee id/email, secret, salt, commitment, signature, attrHash, proof coordinate, session id or token value, and no attribute/identity/credential key at any depth; request log lines carry only `{id, method, url}` without query strings |
