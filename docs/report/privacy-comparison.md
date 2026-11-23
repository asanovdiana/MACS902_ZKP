# Report chapter: privacy comparison, SSO vs ZK gate

Audience: the course and demo panel. The scope claims the ZK gate "leaks less than SSO"
([`docs/project-scope.md`](../project-scope.md), "Privacy comparison"). This chapter fills the
scope's table with evidence from the code and tests, and states where the claim stops.

## 1. Plain version

With SSO, the user logs in at Keycloak, receives a token that lists who they are and what they may
do, and every service request carries that token. The front door reads it, decides, and writes the
person's name, email and roles into its log next to the page they opened.

With the ZK gate, the user's machine sends a proof that "some valid, unrevoked employee whose
attributes fit this service's rule" is asking, plus twelve public numbers. None of them is a name, an
email or an attribute. The gateway logs those numbers and its decision. The only per-user number,
the nullifier, changes from service to service and every ten minutes.

Both front doors make the same access decisions for the same policies (Alice gets the Wiki and File
Share and is denied the Admin Panel; Bob is denied File Share; Carol gets the Admin Panel:
[`p3/baseline/sso-gateway/tests/sso.test.ts`](../../p3/baseline/sso-gateway/tests/sso.test.ts) and
the team attack suite against the gateway,
[`p3/gateway/tests/team-v4.e2e.test.ts`](../../p3/gateway/tests/team-v4.e2e.test.ts)).

## 2. The table, with evidence

| Data | Keycloak / SSO baseline | ZK Access Gate |
|---|---|---|
| Username, email | **Yes.** The OIDC scope is `openid profile email`. On login the SSO front door publishes an `sso.login` event with `username`, `email`, `name`, `roles` and claims `sub`, `department`, `clearance`, `device_compliant` ([`p3/baseline/sso-gateway/src/app.ts`](../../p3/baseline/sso-gateway/src/app.ts)). The service receives the username as its display label (test "service learns her identity", `sso.test.ts`). | **No.** The gateway receives `{resource, nonce, proof, publicSignals}` only (safety test F6.04). The service receives a random per-session pseudonym `zk-…` and "Anonymous credential holder" ([`p3/gateway/src/sessions/sessions.ts`](../../p3/gateway/src/sessions/sessions.ts), `routes/serviceProxy.ts`). |
| Role, department, clearance | **Yes, on every request.** Each request emits `sso.decision` with `username`, `email`, `name`, `roles`, `clearance`, `department`, `deviceCompliant` and the `path` (`app.ts`); the test asserts `roles: ['engineer']`, `clearance: 2` for Alice (`sso.test.ts`). | **No, only that the policy is met.** The public signals are `nullifier, root, issuerAx, issuerAy, roleMask, deptMask, minClearance, requireDevice, now, nonce, resourceId, epoch` ([`docs/CONTRACTS.md`](../CONTRACTS.md) `access.public_signals v4`); the four policy fields are the *service's* policy, identical for every user of that service (obligation 8). Attributes enter only the client's witness (floor 6, F6.03, F6.08). |
| Link requests to one person | **Yes.** Every `sso.decision` carries the username and the page path, so one log query lists everything a person opened. The token subject `sub` is stable across services. | **Only within one service and epoch.** `nullifier = Poseidon(secret, resourceId, epoch)`: equal for the same user, service and 10-minute epoch (needed for the rate limit, F5.02), different across services (F5.04) and epochs (F5.06); nothing else in the public signals separates users (F5.05). A session pseudonym is new for each session. |
| Breach of server logs exposes identities | **Yes.** The events above sit in the SSO front door's history and the Live View stream. | **No identity in the gateway log.** HTTP log lines hold request ID, method, path without query, status, with cookie and authorization headers redacted ([`p3/gateway/src/app/createApp.ts`](../../p3/gateway/src/app/createApp.ts)); the event bus refuses keys that look like secrets ([`p3/gateway/src/events/bus.ts`](../../p3/gateway/src/events/bus.ts)). The floor 7 test for gateway log and state is F7.05 in [`tests/safety/floor07-logs.test.js`](../../tests/safety/floor07-logs.test.js); see the caveats below. |

On screen: the SSO vs ZK page (`p3/ui/src/pages/Compare.tsx`) shows both columns for the same
service and paints the identity fields the server received red; the Gateway Live View
(`p3/ui/src/pages/LiveView.tsx`) shows the raw ZK events.

## 3. Where the claim stops (honest caveats)

- **The issuer still knows who people are.** It assigns the attributes at enrolment and can label
  leaves with an employee ID; the privacy gain is that the *gateway and services* do not learn
  identity per request ([`identity.md`](identity.md), section 6).
- **The gateway's operator Admin Console relays issuer labels.** `/api/admin/registry` (operator
  token required) returns the issuer's leaf list including an employee-ID label where the issuer has
  one (`p3/gateway/src/registry/issuerV1.ts` `listLeaves`; test data `label: 'alice'` in
  `p3/gateway/tests/registry-artifacts.test.ts`). It is not logged and not published as an event,
  but it passes through the gateway process. In a real deployment the Admin Console should talk to
  the issuer directly.
- **Network metadata is not hidden.** IP address, timing and request volume reach the gateway as
  with any web service. Nothing in this repository adds an anonymity network; the demo runs on
  localhost or the compose network without TLS (threat model, network attacker).
- **Small anonymity sets.** In the demo, three personas share each policy, so "someone who may open
  the Admin Panel" is nearly an identity. The privacy is as strong as the number of users who
  satisfy the same policy.
- **Within one service and epoch, requests are linkable** by design (the rate limit needs it).
- **`/path` access pattern.** The client fetches its Merkle path from the issuer by leaf index, which
  tells the issuer who is active and when (once per root; [`identity.md`](identity.md), section 6).
- **Gateway log and state, floor 7:** F7.05 is the gateway test for this table's last row. Its
  final status is recorded with the safety counts in the [Results](README.md#8-results) section.

## 4. Summary

For the same access decision, the SSO front door records who the person is, their attributes and
every path they open; the ZK gate records a proof's public signals and a verdict. That is the
difference the scope asked us to show. It does not remove what the issuer knows, network
metadata, or linkability inside one service and epoch.
