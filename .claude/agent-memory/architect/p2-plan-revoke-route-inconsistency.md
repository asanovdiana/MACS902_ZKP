# p2-plan §4 names the revoke route two ways

The §4 architecture diagram says `POST /revoke/:id`; the issuer API table says
`POST /credentials/:leafIndex/revoke`. `issuer.api v1` uses the table form. Also added beyond §4:
`GET /issuer` (bootstrapping only; the gateway pins the key from config) and `410 revoked` on
`/path`. Related: [[zk-kit-pathindices-matches-v3]].
