# A v3 credential that proves must use role 2 or 3 and clearance 2 or 3

P1's `FileShareAccess` hard-codes those numbers (ADR 0008: opaque in v3). Test credentials in
client tests use role 2 / clearance 2 (Alice) and clearance 1 for the refusal case (Bob); do not
"fix" them to D6 meanings. v3 attributes are unsigned. See [[client-tests-use-node-test-and-stub-issuer]].
