# tests/safety assumes issuer.api v1

`tests/safety/**` builds issuers without a token (helpers.makeIssuer) and calls
`client.requestCredential({attributes})` / POST /credentials with attributes. After G1-S1-IDEN-014
those break (SR-04 refuses to start; attributes are not accepted). The suite is append-only and owned
by `safety`: report the list, do not edit. See [[enrolment-v2-design]].
