# Open enrolment voided floors 2, 3, 5 without violating them (CLOSED)

`POST /credentials` was unauthenticated in issuer.api v1: self-enrol as admin, re-enrol after
revocation, N credentials = N nullifiers. Ruled HIGH SR-03 at SAFETY-020. Closed by IDEN-014
(issuer.api v2: admin enrolment + one-time code); F2.14, F3.10 made real and F5.08 added in
SAFETY-021. Re-check at every gate that v4 has no open path (insecure-dev keeps v3's only).
See [[v2-enrolment-in-the-tier]], [[gateway-half-pending]].
