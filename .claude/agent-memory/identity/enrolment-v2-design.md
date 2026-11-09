# Admin-approved enrolment (issuer.api v2)

POST /credentials takes `{commitment, enrolmentCode}`; the admin creates the enrolment
(`POST /admin/enrolments`). Open enrolment is gone for v4; v3 keeps it only under
`ISSUER_INSECURE_DEV=1`. Policy chosen: no implicit re-enrolment (revoke, then a new enrolment).

Things that cost time:
- The code is consumed BEFORE the leaf insert (fail safe) and reverted if the insert throws; the
  whole redeem runs inside `exclusive` so concurrent redemptions issue one credential.
- v3 attributes are unsigned: an "issuer returned altered attributes" test only bites on v4.
- Existing issuer suites run in insecure-dev (`makeApp()` default); `makeApp({secure:true})` is the
  production posture (token set). The hardened tests live in `issuer/test/enrolment.test.js`.
- tests/safety (append-only, not ours) calls the v1 API (attributes in the body, no token): it
  breaks by design, see [[safety-suite-v1-assumptions]]. Related: [[issuer-key-dir-is-config]].
