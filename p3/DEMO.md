# P3 demo runbook (≈ 8 minutes)

## Before the presentation (once)

```bash
# repository root, Docker Desktop running
make demo            # builds and starts everything; first build takes a few minutes
```

Open **<http://localhost:8088>**. Use `localhost`, not `127.0.0.1`, because Keycloak redirects back
to `localhost`. Sign in to the console with `OPERATOR_TOKEN` from `p3/env.example` (development value).
Keycloak runs at <http://localhost:8080>. Demo users and their development passwords are in
`p3/baseline/keycloak/realm-zkag.json`: `alice` (engineer), `bob` (contractor), `carol` (admin).

**Fresh state.** `make demo-reset` recreates the issuer registry and wallets: revocations are
permanent in the team issuer, so this is the only way to undo the revocation scene. Admin Console →
_Reset demo_ only clears gateway state (nonces, nullifiers, sessions, events).

**Dry run.** `E2E_KEYCLOAK=1 make e2e` (10 browser tests) should pass before you go on stage.

## Script

| #   | Screen            | Do                                                                            | Say / show                                                                                                                                                                                                  |
| --- | ----------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | SSO vs ZK         | _Log in with Keycloak_ → alice → _Open Wiki via SSO_                          | **Successful authentication.** The left column fills from the real SSO event: username, email, name, stable subject, role, department, clearance (red). Below: the RS256 JWT checks against the realm keys. |
| 2   | SSO vs ZK         | _Request via ZK gateway_ (Alice)                                              | **Authorized access with a valid ZKP.** Same decision (GRANTED), right column "not received". 256-byte proof, 12 public signals, all eight obligations PASS.                                                |
| 3   | User Portal       | Alice → File Share → _Request access_                                         | The proof lifecycle with real timings (≈0.8 s proving, ≈12 ms verify); File Share opens. The service sees only "Anonymous credential holder".                                                               |
| 4   | User Portal       | Bob → File Share; then Carol → Admin Panel                                    | **Unauthorized access rejected.** Bob's own client refuses (`POLICY_NOT_SATISFIED`): no valid proof can exist. Carol is admitted.                                                                           |
| 5   | Admin Console     | Revoke Bob's leaf (`leaf-1`, label "bob") → User Portal: Bob → Wiki           | **Revoked credential rejected.** The root changes and the tree greys Bob's leaf; Bob can no longer prove (no Merkle path). Attack Lab #2 shows a held pre-revocation proof denied `ROOT_NOT_CURRENT`.       |
| 6   | Attack Lab        | _Run_ Replay (#1), then _Run with real wait_ on #1b (≈2 min; talk through it) | **Reused / expired nonce.** Replay → `NONCE_USED`; the held proof after 125 s → `NONCE_EXPIRED`.                                                                                                            |
| 7   | Attack Lab        | _Run_ Spam (#6)                                                               | **Nullifier reuse.** First proof admitted, second (fresh nonce, same epoch) → `429 RATE_LIMITED`. Then _Run all_ for the remaining attacks: every one ends with the team's expected code.                   |
| 8   | Gateway Live View | Click any `verification.completed`                                            | **Privacy-preserving logging.** Only public signals and decisions; the "never received" list. Point to test F7.05, which scans the gateway log and state automatically.                                     |
| 9   | Performance       | —                                                                             | Measured medians and p95 (`p3/bench/results/latest.json`).                                                                                                                                                  |

## Recording plan (backup video)

1. Set the display to 1440×900 at 100 % zoom and turn on Do Not Disturb.
2. Run `make demo-reset`, wait until the header shows "Real ZK authorization active", then sign in.
3. Record the browser window with macOS ⇧⌘5 → _Record Selected Portion_ (or OBS at 30 fps). Speak
   over it or add captions later.
4. Record scenes 1–9 in order as **one take per scene**. For scene 6, also record the full 125 s wait,
   then cut it to a 5 s countdown in the edit, saying on screen that it was shortened.
5. Export at 1080p as `docs/report/demo-recording.mp4` (or link it from the report if it is too
   large for git).
6. No recording exists yet; this is the plan.

## Troubleshooting

- **Header says "authorization blocked"**: check `curl -s localhost:8088/api/status`; `missing` names
  the cause (issuer pin, artefacts, registry). `make demo-reset` re-runs the setup step.
- **Keycloak login loops back to the login page**: you opened `127.0.0.1`; use `localhost`.
- **Prover pill red / 401 from `/p2`**: sign in to the console first (the prover requires an operator
  session).
- **Live feed red after a container restart**: sign in again (operator sessions are in memory).
