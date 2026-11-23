# Report chapter: gateway, services and demo (P3)

Audience: the course and demo panel. Plain explanation first, then technical detail. Every number
is taken from a committed file, named next to it; anything not in a committed file is marked
"not measured".

## 1. The idea in plain words

The circuit chapter ends with a warning: a valid proof is only half of the guarantee. A proof says
"someone holding an issuer-signed credential satisfies *some* policy for *some* challenge". The
**gateway** turns that into "this request may open the Wiki right now". It hands out a fresh
challenge, checks that the proof answers exactly that challenge, for exactly this service, against
the current list of valid credentials and the real issuer key, and only then opens a short session.
It never learns a name.

Behind the gateway sit three small services (Wiki, File Share, Admin Panel). They accept a request
only if a trusted front door vouches for it. For comparison, a normal Keycloak single sign-on (SSO)
front door guards the same three services. The demo web app shows both side by side.

All P3 code lives in `p3/` and uses the team's circuit, issuer and client unchanged
([`p3/README.md`](../../p3/README.md)).

| Part | Scope item | Code |
|---|---|---|
| ZK gateway (verifier, reverse proxy, sessions, events) | M5 | `p3/gateway/` |
| Wiki, File Share, Admin Panel | M5 | `p3/services/` |
| Demo UI (five screens plus two extra pages) | M6 | `p3/ui/` |
| Keycloak realm and OIDC front door | M7 | `p3/baseline/` |
| Benchmarks | M8 | `p3/bench/` |
| Docker packaging | | `p3/docker-compose.yml`, `p3/docker/` |

## 2. The gateway (M5)

### 2.1 Request flow

1. The client asks `GET /challenge?resource=wiki`. The gateway stores a challenge with a 128-bit
   random `nonce`, the service's `resourceId`, `now` (unix seconds), `epoch = floor(now / 600)` and
   the service policy, and returns exactly those five fields
   ([`p3/gateway/src/routes/teamAccess.ts`](../../p3/gateway/src/routes/teamAccess.ts),
   [`p3/gateway/src/security/challenges.ts`](../../p3/gateway/src/security/challenges.ts)).
2. The client proves locally and sends `POST /access {resource, nonce, proof, publicSignals}`.
3. The verification pipeline runs cheap checks first and Groth16 last
   ([`p3/gateway/src/verification/pipeline.ts`](../../p3/gateway/src/verification/pipeline.ts)).
4. On admission the gateway sets a resource-scoped, HttpOnly session cookie (10 minutes by default,
   `SESSION_TTL_SECONDS = 600` in [`p3/gateway/src/config/env.ts`](../../p3/gateway/src/config/env.ts))
   and proxies `/svc/<resource>/...` to the service with a signed assertion.

The UI uses an equivalent `/api/zk/*` route pair over the same challenge store and pipeline.

### 2.2 How the eight contract obligations are enforced

Obligations from [`docs/CONTRACTS.md`](../CONTRACTS.md) `access.public_signals v4`. Each line names
where it is enforced and the wire code the client sees (codes in `TEAM_CODES`, `pipeline.ts`,
adopted from [`client/attacks/README.md`](../../client/attacks/README.md)).

| # | Obligation | Enforcement in `p3/gateway/src/` | Denial code |
|---|---|---|---|
| 1 | Groth16 verify against the committed v4 key | `verification/groth16.ts` calls `snarkjs.groth16.verify` with the key loaded and hash-checked by `verification/artifacts.ts`; exceptions count as invalid | `PROOF_INVALID` |
| 2 | Pin `issuerAx, issuerAy` | compared with `config.trustedIssuer` (pin file written by `npm run v4:setup`); no pin configured → fail closed (`503`) | `ISSUER_NOT_PINNED` |
| 3 | `root` current, or acceptable under the 30 s insert-only rule | `registry/issuerV1.ts` `assessProofRoot`: current root, or in `/root/history`, superseded ≤ `ROOT_STALENESS_SECONDS` (default and maximum 30) ago, and only by inserts; issuer unreachable → fail closed | `ROOT_NOT_CURRENT` |
| 4 | Policy fields and `resourceId` equal the requested service | `roleMask, deptMask, minClearance, requireDevice` compared with `POLICIES[resource]`; `resourceId` with the service; the requested service must equal the challenged one | `POLICY_MISMATCH` |
| 5 | `now`, `epoch` equal the stored challenge | `sig('now') === challenge.now`, `sig('epoch') === challenge.epoch`; skew bound = nonce TTL | `CHALLENGE_MISMATCH` |
| 6 | Nonce issued here, unexpired (TTL 120 s), single-use | `security/challenges.ts` `consume`: synchronous check-and-mark, so two concurrent submissions cannot both pass; any attempt burns the nonce; `CHALLENGE_TTL_SECONDS = 120` | `NONCE_UNKNOWN`, `NONCE_USED`, `NONCE_EXPIRED` |
| 7 | `(nullifier, epoch)` admitted at most once | `security/nullifiers.ts`, keyed on `(resource, epoch, nullifier)`, `NULLIFIER_MAX_PER_EPOCH = 1`; recorded only after Groth16 passes, so an invalid proof never spends the budget | `RATE_LIMITED` (HTTP 429) |
| 8 | Logs and state hold only public signals and decisions | see section 2.4 | — |

**Encoding.** Every public signal must be a canonical decimal below the field prime before any
check runs (`verification/schema.ts`), and replay and rate-limit state are keyed on canonical values,
never on proof bytes (Groth16 proofs are re-randomisable; safety test F4.03).

**Fail-closed authorization gate.** A session is issued only when the active circuit profile has
every required capability and the keys are acceptable (`authorizationEligible` in `pipeline.ts`).
The committed keys are DEV-ONLY, so the gateway accepts them only with `ALLOW_DEMO_KEYS=true`, which
production mode refuses (`config/env.ts`). The earlier P1 v3 circuit still runs as a diagnostic
profile (`ZK_PROFILE=p1-integrated-v3`): it reports proof validity and never grants access
([`p3/gateway/src/verification/profiles.ts`](../../p3/gateway/src/verification/profiles.ts)).

### 2.3 Sessions and revocation

A session stores only a random ID, the resource, a random per-session pseudonym, the root it was
authorized under and its expiry ([`p3/gateway/src/sessions/sessions.ts`](../../p3/gateway/src/sessions/sessions.ts)).
Every proxied request re-checks the registry: a session survives enrolments but is dropped as
`SESSION_REVOKED_ROOT_CHANGED` once a revocation has happened since it was issued
(`routes/serviceProxy.ts`, `sessionRootValid`). For this per-request check the root may be cached for
`ROOT_CACHE_MS` (default 2000 ms, capped at 30 000 ms in `config/env.ts`).

**Revocation-cache fix (PR #3).** New authorizations never use that cache: `assessProofRoot`
fetches the root with `maxAgeMs: 0`, so a revocation takes effect for new proofs immediately rather
than after the cache expires. The regression test is "REGRESSION: a revocation takes effect for new
proofs even inside the root cache window" in
[`p3/gateway/tests/registry-artifacts.test.ts`](../../p3/gateway/tests/registry-artifacts.test.ts):
with a 30 s cache holding the old root, the old root is refused with status `revoked`.

### 2.4 What the gateway logs and keeps (obligation 8)

- HTTP log (pino): request ID, method, path without query string, status code; cookie,
  authorization and `set-cookie` headers are redacted (`app/createApp.ts`).
- Event bus (feeds the Live View): challenge, `proof.submitted`, `verification.completed` with the
  twelve public signals, check list, decision, timings, and the nullifier. The bus refuses to
  publish any event with a key matching `secret|salt|witness|password|token|cookie|session id|private`
  (`events/bus.ts`). Test: "events never contain session identifiers or private data" in
  [`p3/gateway/tests/full-profile.integration.test.ts`](../../p3/gateway/tests/full-profile.integration.test.ts).
- State: challenges, `(resource, epoch, nullifier)` counters, sessions as above.
- Services receive `subject = zk-<random>` (new per session) and display "Anonymous credential
  holder".

Caveat: the operator-only admin route `/api/admin/registry` relays the issuer's leaf list, which can
include the employee ID label the issuer admin typed at enrolment (`registry/issuerV1.ts`
`listLeaves`). It is fetched on demand for the Admin Console, is not logged and is not put on the
event bus, but it does pass through the gateway process. The floor 7 test for the gateway is F7.05
(section 7).

## 3. Protected services and front-door assertions

`p3/services/` runs the Wiki, File Share and Admin Panel. They have no published ports in Docker
(internal network only) and every request must carry `x-zkag-assertion`: an HS256 JWT valid for
30 s, audience `zkag-service:<resource>`, signed with a per-front-door secret (ZK gateway or SSO
baseline) ([`p3/shared/src/assertion.ts`](../../p3/shared/src/assertion.ts),
[`p3/services/src/common.ts`](../../p3/services/src/common.ts)). Missing, expired, wrong-audience or
untrusted-signer assertions are refused (tests in
[`p3/services/tests/services.test.ts`](../../p3/services/tests/services.test.ts) and "direct upstream
bypass" in `full-profile.integration.test.ts`). The gateway strips any client-supplied assertion or
identity headers before forwarding.

Policies (from `docs/CONTRACTS.md`): Wiki any role, device compliant; File Share engineer or admin,
clearance ≥ 2; Admin Panel admin, clearance 3, device compliant.

## 4. Demo UI (M6)

One React app (`p3/ui/src/pages/`, flow logic in `p3/ui/src/features/`):

| Screen | File | Shows |
|---|---|---|
| 1 User Portal | `Portal.tsx`, `features/portal/` | pick Alice, Bob or Carol and a service; eight animated steps from challenge to access, with proving and verify times. The persona goes only to the user-side prover |
| 2 Gateway Live View | `LiveView.tsx` | authenticated WebSocket stream of gateway events: public signals, proof size, checks, verdict, verify time |
| 3 SSO vs ZK | `Compare.tsx` | same service through Keycloak (left) and the ZK gateway (right); identity fields the server received are red |
| 4 Admin Console | `Admin.tsx` | issue and revoke through the team issuer, draw the Merkle tree, watch the root change |
| 5 Attack Lab | `AttackLab.tsx`, `features/attack-lab/` | runs the team attack suite (`client/attacks`) with real proofs against this gateway; PASS only if every step gets the expected code |
| extra: Performance | `Performance.tsx` | reads `p3/bench/results/latest.json` through the gateway; nothing estimated |
| extra: Integration Status | `Integration.tsx` | active circuit profile, its capabilities, key trust status |

The prover in the demo is `p3/integration/wallet-prover/`, a Node process wrapping the team client
and holding the persona wallets. It plays the user's machine; proving in the browser (N1) is not
built.

## 5. Keycloak / OIDC baseline (M7)

`p3/baseline/keycloak/realm-zkag.json` defines users `alice`, `bob`, `carol` with role, department,
clearance and device attributes (access token lifespan 300 s, SSO idle timeout 1800 s, same file).
`p3/baseline/sso-gateway/` is an Authorization Code + PKCE (S256) front door: it validates the JWT
on every request, evaluates the same policies, and forwards with its own assertion. Its tests reject
HS256 and `alg=none` tokens and forged login state
([`p3/baseline/sso-gateway/tests/sso.test.ts`](../../p3/baseline/sso-gateway/tests/sso.test.ts)).
What it learns is the subject of the [privacy comparison](privacy-comparison.md).

## 6. Docker packaging

`cd p3 && docker compose up --build` (also `make demo` in `p3/Makefile`) starts Keycloak 26.0.7,
the team issuer, a one-shot `setup` container that enrols the personas and writes the issuer pin,
the services (internal network only), the gateway, the wallet prover, the SSO front door and the UI
on port 8088 ([`p3/docker-compose.yml`](../../p3/docker-compose.yml)). The gateway starts only after
setup succeeds and runs with `ALLOW_DEMO_KEYS=true`. All secrets in the compose file are development
defaults. `make test-keycloak` drives a real Keycloak PKCE login (`p3/baseline/sso-gateway/tests/keycloak.live.test.ts`), and `make e2e` runs the Playwright demo tests against the stack.

## 7. Tests

- `full-profile.integration.test.ts`: grant, cross-resource cookie refusal, session expiry, logout,
  revocation invalidating sessions, replay and every mismatch, duplicate and concurrent nullifiers,
  fail-closed without issuer pin or reviewed keys, proxy path traversal, CSRF, oversized payloads,
  team `/challenge` + `/access` codes, staleness semantics.
- [`p3/gateway/tests/team-v4.e2e.test.ts`](../../p3/gateway/tests/team-v4.e2e.test.ts): the team issuer, this
  gateway with the committed v4 key and the team attack library, in process. Every attack id in
  `client/attacks` must get exactly its expected outcome and code, including the 125 s
  `replay_expired` wait (driven by an offset clock, no step skipped).
- Gateway safety floors F3.09 (revoked), F4.06 (used and expired nonce), F5.07 (nullifier rate
  limit) and F7.05 (gateway log and state) in `tests/safety/` are the gateway half of floors 3, 4, 5
  and 7; final status in [Results](README.md#8-results).

## 8. Benchmark results

Source: [`p3/bench/results/latest.json`](../../p3/bench/results/latest.json) (same values in
`latest.csv`), generated 2026-11-09T22:17:46Z, 100 samples per row after one warm-up, HTTP/1.1 over
loopback. Machine: Intel Core i9-9880H @ 2.30 GHz, 16 logical cores, 16 GiB, macOS (darwin 25.3.0),
Node v23.7.0. Values rounded to two decimals.

**v4 (the product circuit, real issuer, real proofs):**

| Row id | What | Median | p95 |
|---|---|---:|---:|
| `v4-prove` | client proving: Merkle path fetch + witness + Groth16 + local verify | 785.66 ms | 1007.86 ms |
| `v4-verify` | gateway verify, `snarkjs.groth16.verify`, warm, 12 public signals | 12.23 ms | 14.48 ms |
| `v4-e2e` | challenge → prove → `/access` admitted, session issued | 803.55 ms | 1035.17 ms |
| `zk-session-request` | request with a ZK session (root check + proxy) | 1.90 ms | 3.05 ms |
| `sso-request` | SSO request: JWT validation + policy + proxy | 2.72 ms | 5.69 ms |
| `v4-proof-size` | proof size | 256 B | 256 B |

v4 constraints 9208 and proof size 723 B as JSON (`v4-constraints`, `v4-proof-size` note, same
file).

**v3 diagnostic rows** (P1's circuit, never admits; kept for the server-side cost breakdown):
`gateway-e2e` challenge + verify over HTTP 20.66 / 27.07 ms; `gateway-pipeline` server-side
pipeline 15.55 / 21.08 ms; `gateway-reject-invalid` 11.36 / 15.28 ms; `gateway-reject-replay`
1.66 / 3.47 ms; `zk-vs-sso` (ZK challenge + verify minus SSO request) 17.94 / 21.38 ms (median /
p95, same file). A replay is rejected about seven times faster than an invalid proof because the
nonce check runs before Groth16.

**Reading the numbers.**

- Per request with a session, ZK (1.90 ms median) and SSO (2.72 ms) cost about the same. The ZK
  overhead is paid once per session: about 0.8 s, almost all of it client proving.
- SSO login round trip through Keycloak: **not measured** (`keycloak-login` is `blocked`: needs an
  interactive browser login). So the scope's "end-to-end latency, ZK vs Keycloak" is answered for
  per-request cost only, not for login.
- Gateway verify misses the scope's 10 ms target: 12.23 ms median with stock snarkjs. The faster
  verifier measured in [`results-p2.md`](results-p2.md) (5.61 ms median,
  [`circuits/reports/perf-v4.md`](../../circuits/reports/perf-v4.md), a different machine) is not
  wired into the gateway.
- v4 challenge + verify on the server alone (without proving): **not measured**; only the v3 row
  above exists.
- Browser proving (`prove-browser`) and proving vs depth (`prove-vs-depth`): **not measured**
  (blocked, same file).
