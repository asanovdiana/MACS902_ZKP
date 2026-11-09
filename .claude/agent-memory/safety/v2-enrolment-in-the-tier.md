# issuer.api v2: how the tier enrols, and what changed under it

Since G1-S1-IDEN-014 the issuer refuses to start without `adminToken` (SR-04), so
`helpers.makeIssuer` defaults to `{adminToken: ADMIN_TOKEN, insecureDev: false}` and returns
`iss.admin(method, url, body?, token?)`. `/admin/leaves` and revoke need the bearer now. Enrol with
`h.enrolViaAdmin({iss, wallet, name, issuer, attributes, employeeId})`; the admin route takes
INTEGER attributes only (`h.encodeAttrs` maps D6 labels). `/admin/leaves` has `total`; `/metrics`
has `leaves`. `buildServer` truthy-checks `insecureDev` (SR-20): pass booleans, never strings.
Supersedes [[open-enrolment-voids-floors-2-3-5]]. See [[safety-tier-layout]].
