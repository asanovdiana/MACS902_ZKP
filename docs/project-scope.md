# ZK Access Gate — Project Scope

Oct 17, 2026 · @Alex

## Overview

We are building **ZK Access Gate**: a zero-trust gateway that lets employees into internal services by proving they meet the access policy, without ever telling the gateway who they are.

**The problem.** Normal access control (logins, SSO, JWT tokens) hands the server your identity, email, roles and a trail of everything you touched. That trail is a privacy risk and a juicy target: one breached log or token leaks who did what.

**Our answer.** The user holds a signed credential from the company. For each request, they generate a zero-knowledge proof that says: *my credential is valid, not revoked, and satisfies this resource's policy*. The gateway checks the proof in milliseconds and learns only **allowed** or **denied**.

**What the final result must show:**

1. A working system: issuer, user client, gateway, three protected demo services.
2. A visual demo that makes the privacy difference obvious, side by side with a normal SSO login.
3. Attacks that fail on screen: replay, revoked user, forged or tampered credential.
4. Measured results: proof time, verify time, proof size, latency vs. the SSO baseline.

**How to read this doc.** Must-haves are the project; build them first and in order. Nice-to-haves only start once every must-have passes its done criteria.

## Core concepts, explained simply

Everyone on the team should be able to explain these five ideas in one sentence each before week 2 ends.

| Concept | Plain explanation | Technical detail we use |
| --- | --- | --- |
| Zero-knowledge proof (ZKP) | Proving a statement is true without showing the data behind it. Like proving you're over 18 without showing your birth date. | Groth16 SNARK: proof \~200 bytes, verify in milliseconds. Circuits written in Circom. |
| Zero trust | Never trust a request because of where it comes from; check every request, every time. | Every access needs a fresh proof; sessions last 10 minutes, then re-prove. |
| Credential | A digital ID card the company signs, listing your attributes (role, department, clearance, device OK). Only you hold it. | Attributes hashed with Poseidon; hash signed with EdDSA on the BabyJubJub curve (both cheap inside circuits). |
| Merkle tree | A list of all valid credentials compressed into one fingerprint (the root). You can prove you're on the list without saying which entry. | Depth-16 Poseidon tree (up to 65,536 users). Revoking = removing the leaf, which changes the root. |
| Nullifier | A one-time tag derived from your secret. Same person + same resource + same time window = same tag, so abuse can be rate-limited, but tags can't be linked across resources. | `Poseidon(user_secret, resource_id, epoch)` as a public output. |

**What gets proven on every request**, in one sentence: *"I know a secret matching a credential that the issuer signed, that credential is in the current valid-credentials tree, its attributes satisfy this policy, and this proof is bound to your fresh challenge."*

**Public inputs (the gateway sees):** policy parameters, Merkle root, challenge nonce, resource ID, epoch, nullifier. **Private inputs (never leave the user's machine):** attributes, issuer signature, Merkle path, user secret.

## Architecture

&#91;embedded content: system architecture · 7 components\]

The user proves locally; the gateway checks the proof against the issuer's current root and forwards only allowed requests. Keycloak (dashed) guards the same services as the comparison baseline.

**Request flow:** user clicks a service → gateway sends a fresh nonce → client generates the proof → gateway verifies it and checks the root, nonce and nullifier → session issued → request forwarded.

## Tech stack

One mature, well-documented toolchain; no experimental crypto libraries in the must-haves.

| Layer | Choice | Why |
| --- | --- | --- |
| Circuits | Circom 2 + circomlib (Poseidon, EdDSA, Merkle, comparators) | Most tutorials and examples; Semaphore uses the same building blocks |
| Proving system | Groth16 via snarkjs | Smallest proofs, fastest verify; runs in Node and the browser |
| Trusted setup | Public Hermez Powers of Tau + our own phase-2 contribution | Standard approach; single-party phase 2 noted as a limitation |
| Issuer + gateway | Python FastAPI (verifier calls snarkjs, or a Node verify microservice) | Fast to build; we know it |
| Merkle registry | `@zk-kit/incremental-merkle-tree` (Node) or a Poseidon tree in Python | Must use the same Poseidon parameters as the circuit |
| Demo UI | React + Vite + Tailwind, WebSocket for live events | Live visual updates for the demo |
| Protected services | 3 small mock apps: Wiki, File Share, Admin Panel | Different policies per service |
| Baseline | Keycloak (OIDC) in front of the same 3 services | Industry-standard comparison |
| Packaging | Docker Compose, one `make demo` command | The whole demo boots on any laptop |
| Testing | Mocha/circom\_tester for circuits, pytest for services | Negative tests are mandatory for every constraint |
| Repo | One monorepo: `circuits/`, `issuer/`, `gateway/`, `client/`, `ui/`, `bench/`, `docs/` | One place to clone and run |

## Must-haves (build these first, in order)

Eight items make up the project. Each has a done criterion; an item isn't done until its criterion passes on a fresh `make demo`.

**M1. Credential issuer** The company's ID office. Admin enters a user's attributes; the issuer signs them and hands the user a credential file.

- Attributes: `role` (engineer / admin / contractor / finance), `dept` (4 values), `clearance` (0 to 3), `device_compliant` (0/1), `expiry` (timestamp), `secret_commitment` = Poseidon(user secret).
- The user secret is generated on the user's side; the issuer only sees its commitment.
- *Done when:* a credential file is issued and its signature verifies in a script.

**M2. Credential registry + revocation** The list of valid credentials, as a Merkle tree.

- Issuing adds a leaf; revoking removes it; the issuer publishes the current root.
- Gateway pulls the root on every request (or every 30 s, documented as the staleness window).
- *Done when:* a revoked user's proof against the new root fails.

**M3. Access circuit (the heart of the project)** One generic Circom circuit that proves, in order:

1. The user knows the secret behind `secret_commitment`.
2. The issuer's EdDSA signature over the attribute hash is valid.
3. The credential leaf is in the Merkle tree with the public root.
4. Attributes satisfy the policy: role in `role_mask`, dept in `dept_mask`, `clearance ≥ min_clearance`, `device_compliant` if required, `expiry > now`.
5. The proof is bound to the gateway's `nonce` and `resource_id`.
6. Output `nullifier = Poseidon(secret, resource_id, epoch)`.

- Policies are *public inputs*, so one circuit serves every service with no recompiling.
- *Done when:* valid proofs pass and every negative test (one per constraint) fails.

**M4. User client (prover)** Runs on the user's side: fetches a challenge, builds the inputs, generates the proof, sends it.

- CLI first (Node + snarkjs); the demo UI calls the same code.
- *Done when:* end-to-end proof generation works from a credential file.

**M5. Gateway (verifier) + protected services** A reverse proxy in front of three services:

| Service | Policy |
| --- | --- |
| Wiki | Any role, clearance ≥ 0, device compliant |
| File Share | engineer or admin, clearance ≥ 2 |
| Admin Panel | admin only, clearance 3, device compliant |

- Issues a fresh nonce per request; verifies the proof, root, nonce freshness, epoch and nullifier rate limit; issues a 10-minute session cookie.
- Logs exactly what it sees (this log is shown in the demo).
- *Done when:* the right user gets in and the wrong one gets a clear denial reason.

**M6. Visual demo UI** The screens the audience watches (see Demo plan). Must include: User Portal, Gateway Live View, Admin Console, Attack Lab, and the side-by-side SSO comparison.

- *Done when:* the full demo script runs end to end without touching a terminal.

**M7. SSO baseline** Keycloak protecting the same three services with normal OIDC login.

- *Done when:* the demo can show both gateways' logs for the same request side by side.

**M8. Evaluation + report** Benchmarks, security test suite, threat model, results charts, recorded demo video as backup.

- *Done when:* every metric in the Evaluation section has a measured number.

## Demo plan

The demo's one message: **the ZK gateway makes the same access decisions as SSO, while learning nothing about who you are, and attacks still fail.** Every screen exists to show that.

### Screens (one web app, five tabs)

| Screen | What it shows | Why it matters |
| --- | --- | --- |
| User Portal | Pick a persona (Alice, engineer / Bob, contractor / Carol, admin), click a service, watch the proof steps animate: challenge received → proving (with timer) → proof sent → result | Makes the invisible proof visible |
| Gateway Live View | Scrolling log of exactly what the gateway received: proof bytes, public inputs, verdict, verify time. **No name, no email, no role.** | The core privacy claim, on screen |
| SSO vs ZK split screen | Same request through Keycloak (left) and ZK Gateway (right); fields the server learned highlighted in red on the SSO side | The audience gets it in five seconds |
| Admin Console | Issue credentials, revoke a user, watch the Merkle root change (tree drawn, revoked leaf greyed out) | Shows revocation works without identity |
| Attack Lab | One button per attack, each ends in a red DENIED with the exact reason | Proves it's secure, not just private |

### Attack Lab buttons

| Attack | Expected result |
| --- | --- |
| Replay a captured proof | Denied: nonce already used / expired |
| Revoked user tries again | Denied: root mismatch, not in tree |
| Tamper attributes (contractor edits role to admin) | Denied: issuer signature invalid |
| Forged credential (self-signed) | Denied: signature not from issuer |
| Valid user, wrong service (Bob → Admin Panel) | Denied: policy not satisfied (proof can't be generated) |
| Spam requests | Rate-limited: same nullifier in this epoch |
| Expired credential | Denied: expiry check fails |

### Demo script (\~8 minutes)

1. **The problem (1 min).** Log into the Wiki via Keycloak. Show its log: name, email, roles, every page visited.
2. **Same thing, ZK (1.5 min).** Alice opens the Wiki via the ZK gateway. Proof animates; access granted. Gateway log shows no identity.
3. **Split screen (1 min).** Side-by-side comparison; red highlights on what SSO leaked.
4. **Policies work (1 min).** Alice gets File Share; Bob (contractor) is denied; Carol opens the Admin Panel.
5. **Revocation (1 min).** Admin revokes Bob live; root changes on screen; Bob's next attempt fails.
6. **Attack Lab (1.5 min).** Run 4–5 attacks; each turns red with its reason.
7. **Numbers (1 min).** Results charts: prove time, verify time, proof size, latency vs. SSO.

**Backup:** a recorded video of the full script, in case anything breaks live.

## Nice-to-haves (only after all must-haves pass)

In priority order: highest demo and research value per week of effort first. Pick from the top.

| # | Addition | What it adds | Effort |
| --- | --- | --- | --- |
| N1 | In-browser proving | Proof generated in the user's browser (snarkjs WASM); secrets never touch our servers. Strongest privacy story. | \~3 days |
| N2 | Accountable anonymity (identity escrow) | Each proof carries the user's ID encrypted to an auditor key; opened only if 2 of 3 auditors approve. Answers "what if an insider abuses access?" This is the main research contribution. | \~1.5 weeks |
| N3 | Live metrics dashboard | Real-time charts of proof time, verify time, requests per service, denials by reason | \~3 days |
| N4 | Real device posture | A small agent checks the actual machine (OS version, disk encryption, firewall) before proving, instead of an issuer-set flag | \~4 days |
| N5 | PLONK / Noir comparison | Same circuit in a system with no per-circuit trusted setup; compare proof size, prove and verify time | \~1 week |
| N6 | Network-level gate | WireGuard tunnel opened only after a valid proof, not just HTTP access | \~4 days |
| N7 | Merkle root transparency log | Append-only, signed history of roots so users can detect a malicious issuer | \~3 days |
| N8 | Mobile prover | Proof generation on a phone; measure prove time on mobile hardware | \~1 week |

**Rule:** a nice-to-have never breaks a must-have. Build each on a branch and merge only when `make demo` still passes.

## Timeline (8 weeks)

&#91;embedded content: 8-week roadmap · 3 lanes, 4 gates\]

Week 4 is the critical gate: if an end-to-end proof doesn't verify by then, apply the circuit fallback in Risks immediately. Greyed items are nice-to-haves, attempted only if the gate before them passed on time.

## Team roles

Each must-have has exactly one owner; everyone reviews the circuit. Names to be filled in.

| Role | Owns | Also helps with |
| --- | --- | --- |
| P1 Circuits | M3 access circuit, circuit tests, trusted setup, constraint optimisation | Threat model, results write-up |
| P2 Identity | M1 issuer, M2 registry + revocation, M4 client prover | Admin Console screen, attack scripts |
| P3 Gateway + Demo | M5 gateway + services, M6 demo UI, M7 Keycloak baseline | Benchmarks, demo video |

**Two-person team:** P2 takes the client and gateway; P3's demo UI becomes shared work in week 5; drop N-items entirely unless ahead.

**Shared rules:**

- One interface contract written in week 1 (credential JSON format, proof request/response API, public-input order). Nobody changes it without telling the others.
- Every PR that touches the circuit needs a second reviewer.
- Weekly 30-minute sync: demo what works, update the checkpoint.

## Evaluation

The final report proves three claims with numbers: it's fast enough, it's secure, and it leaks less than SSO. Targets are our estimates; we report whatever we measure.

### Performance (run each 100 times, report median and p95)

| Metric | Target |
| --- | --- |
| Circuit size (constraints) | Report it; expect roughly 10k–40k |
| Proving time, native (Node) | < 3 s |
| Proving time, browser (if N1) | < 10 s |
| Verify time at gateway | < 10 ms |
| Proof size | \~200 bytes (Groth16 is fixed size) |
| End-to-end request latency, ZK vs. Keycloak | Report the overhead |
| Proving time vs. Merkle depth (8, 16, 20) | Show how it scales |

### Security tests (all must pass)

- [ ] Valid user + satisfied policy → granted
- [ ] Policy not satisfied → no valid proof possible
- [ ] Replayed proof → denied
- [ ] Revoked credential → denied
- [ ] Tampered attribute → denied
- [ ] Forged issuer signature → denied
- [ ] Expired credential → denied
- [ ] Same nullifier twice in one epoch → rate-limited
- [ ] Two proofs from one user to different services → nullifiers unlinkable
- [ ] Every circuit constraint has a negative test that fails when the constraint is removed

### Privacy comparison (what the server learns)

| Data | Keycloak / SSO | ZK Access Gate |
| --- | --- | --- |
| Username, email | Yes | No |
| Role, department, clearance | Yes | No (only that the policy is met) |
| Link requests to one person | Yes | Only within one service and epoch |
| Breach of server logs exposes identities | Yes | No |

### Threat model

Cover: malicious user, compromised gateway, malicious issuer, network attacker, insider abuse. For each: what they can do, what stops them, what's out of scope.

## Risks and fallbacks

The biggest risk is the circuit slipping past week 4; every fallback below protects the demo first.

| Risk | Sign it's happening | Fallback |
| --- | --- | --- |
| Circom learning curve | No working toy circuit by end of week 1 | Start from Semaphore's circuit and adapt it instead of writing from scratch |
| Circuit not end-to-end by week 4 | Checkpoint missed | Cut nullifier and expiry; keep signature + membership + policy. Still a complete project. |
| Under-constrained circuit bug | A negative test passes when it should fail | Fix before anything else; it's a real security hole |
| Poseidon mismatch between circuit and Python/Node | Valid credentials fail to prove | Use one library's Poseidon everywhere; add a cross-check test in week 2 |
| Demo UI eats too much time | Week 6 and screens still incomplete | Drop Admin Console tree drawing; keep User Portal, Gateway Live View, split screen, Attack Lab |
| Live demo breaks | Anything | Recorded video backup; demo runs offline from Docker |
| Teammate unavailable | Missed sync | Interface contract + one owner per item means work can be reassigned |

## Final deliverables

What we hand in at the end; tick each off when done.

- [ ] Monorepo with README, architecture diagram and one-command setup (`make demo`)
- [ ] Working system: issuer, registry, circuit, client, gateway, 3 services, Keycloak baseline
- [ ] Demo web app with all 5 screens
- [ ] Live demo script rehearsed at least twice
- [ ] Recorded demo video (\~8 min)
- [ ] Report: problem, background, design, circuit explanation, threat model, results, privacy comparison, limitations, future work
- [ ] Results charts and benchmark raw data
- [ ] Security test suite passing in CI
- [ ] Presentation slides
