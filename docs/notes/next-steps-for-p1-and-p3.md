# Next steps — for P1 (circuits) and P3 (gateway + demo)

**From:** P2 · **Date:** 2026-11-08 · **Status:** P2's checkpoint G1 is done (CONDITIONAL — nothing
failed; the open conditions below are team or other-lane work).

Where everything is: overview [`../p2-work.md`](../p2-work.md) · contracts
[`../CONTRACTS.md`](../CONTRACTS.md) · checkpoint [`../gates/G1/summary.md`](../gates/G1/summary.md).

---

## For everyone

1. **Use the shared repository.** This code is the complete project as of this note, including P1's
   v3 files unchanged. Once it is in the team's shared repository, set the repository address in
   `.claude/kit.yaml` (`forge.remote`, currently a placeholder) and work from there.
2. **Key ceremony (about 3 minutes each).** The committed proving keys use a public phase 1 (PSE
   Perpetual Powers of Tau) but a single-party phase 2, so they are demo-only. Each of us adds one
   contribution in turn, then we publish a beacon and commit the new keys and regenerated test proofs
   in one commit. Tooling and steps: `circuits/scripts/ceremony.sh`, `circuits/setup/ARTIFACTS.md`
   ("Re-keying"). This should happen before the demo freeze.
3. Setup on your machine: Node ≥ 20, circom **2.2.3**, then `npm ci && npm ci --prefix issuer` and
   `npm run test:all`.

---

## P1 — circuits

**What waits on you**

| # | What | Why |
|---|---|---|
| 1 | **Review the v4 circuit** — `circuits/integrated_access_v4.circom`, `components/integrated_access_v4_gate.circom` and the six new components (`attribute_hash`, `issuer_key`, `access_policy_v4`, `expiry`, `challenge_binding`, `merkle_membership_n`) | The scope requires a second reviewer on every circuit change. Your v3 files are unchanged; v4 reuses your signature check, commitment and Merkle logic. |
| 2 | Tell us if anything should change (naming, structure, the attribute set, `employeeActive` always required) | P2 will adapt the issuer and client; the shared encoder `circuits/lib` is the one place to change encodings. |
| 3 | Remove or finish `circuits/components/integrated_access.circom` | It is a 2-line fragment that does not compile; nothing uses it. |
| 4 | Optional cleanup in v3: the two `x*(x-1) === 0` checks on `deviceCompliant` / `employeeActive` in the main file are redundant (the policy already forces `=== 1`) | Safety accepted them as harmless. |
| 5 | Lead or join the key ceremony (above) | Owner of the trusted setup. |

**Useful to know:** decisions are in `docs/adr/0002`–`0009`; the circuit's tests run with root
`npm test`; every v4 constraint is covered (102/102 in `circuits/reports/mutation-v4.md`).

---

## P3 — gateway, demo services, UI, Keycloak, packaging

**What waits on you**

| # | What | Where it is specified |
|---|---|---|
| 1 | **The gateway (M5)** — verify proofs and enforce the eight obligations below | `docs/CONTRACTS.md`, `access.public_signals v4` |
| 2 | Confirm or change the endpoints the client assumes: `GET /challenge?resource=<wiki\|file_share\|admin_panel>` → `{nonce, resourceId, epoch, now, policy}`, and `POST /access {resource, nonce, proof, publicSignals}` | `client/README.md` |
| 3 | Confirm or rename the proposed rejection codes and their check order | `client/attacks/README.md` |
| 4 | **Demo UI (M6):** User Portal (uses the client library), Admin Console (uses the issuer admin API and live events), Gateway Live View, SSO split screen, Attack Lab (uses `client/attacks`) | `issuer/README.md`, `client/README.md`, `client/attacks/README.md` |
| 5 | Keycloak baseline (M7), Docker Compose, `make test`, `make demo`, CI pipeline | none yet — see risk R-007 |

**The eight gateway obligations** (the circuit cannot do these itself):

1. Verify the proof with the committed v4 verification key (`circuits/scripts/verify.js`, about 5.6 ms;
   keep one long-running process).
2. Pin the issuer key (`issuerAx, issuerAy`) to the real issuer key from configuration — **never** the
   TEST-ONLY key in the fixtures (a forger can otherwise prove with their own key).
3. Accept only the current registry root (at most 30 s old; never across a revocation).
4. The policy fields and `resourceId` must match the service actually requested.
5. `now` and `epoch` must be the ones from the challenge the gateway issued (`epoch = floor(now/600)`).
6. Each nonce is used once and expires (TTL 120 s).
7. The same `(nullifier, epoch)` is admitted at most once (rate limit).
8. Logs and state contain only public signals and decisions — never names, roles or other attributes.

**Ready-made material for testing the gateway**

- `circuits/fixtures/v4/` — 11 real proofs: 5 that must be admitted and 6 that must be rejected
  (stale root, forged issuer, old `now`, same-epoch nullifier, wrong service, replay), each mapped to
  the obligation that rejects it.
- `client/attacks/` — 9 scripted attacks with the expected code; `node client/attacks/bin/attacks.js run all --gateway URL --issuer URL` runs them against your gateway.
- `tests/safety/` — four floor tests (F3.09, F4.06, F5.07, F7.05) are waiting for the gateway; they
  must become real and pass at your checkpoint.
- Issuer for development: `ISSUER_PROFILE=v4 ISSUER_ADMIN_TOKEN=… npm start --prefix issuer`, then
  `node issuer/scripts/seed-personas.js` (see the root README quick start).

---

## What P2 will do next

- Adapt the issuer and client to anything P1's review changes.
- Adjust the client to P3's final endpoints and codes, and help wire the User Portal and Admin Console
  to the client library and issuer admin API.
- Take part in the key ceremony and regenerate the test proofs with the new keys.
