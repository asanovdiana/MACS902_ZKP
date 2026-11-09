# ZK Access Gate — Technology Explained

Oct 19, 2026 · @Alex

Every technology in the project, explained in plain words first and technically second. Read it once before week 1; come back to the glossary when a term confuses you.

## The big picture

Think of our system as a **nightclub with a very private bouncer**.

- The **company (issuer)** gives each employee a tamper-proof membership card listing their role, department and clearance.
- The **bouncer (gateway)** guards each room. Each room has a rule, like "admins only, clearance 3".
- Normally you'd hand the bouncer your card and he'd read everything on it and write your name in his log.
- In our system, you **keep the card in your pocket**. Instead you hand over a sealed mathematical note that says: *"My card is genuine, it hasn't been cancelled, and it satisfies this room's rule."* The bouncer can check the note is true, but learns nothing else. Not your name, not your role.

**The journey of one request:**

1. Alice clicks "open File Share" in her browser.
2. The gateway replies with a random one-time number (a **nonce**) and the File Share policy.
3. Alice's client combines her secret credential, the policy and the nonce, and generates a **zero-knowledge proof** (a few seconds).
4. The gateway **verifies** the proof (a few milliseconds), checks the nonce is fresh and the credential list is current.
5. If everything checks out, Alice gets a 10-minute session and File Share opens. The gateway's log says only: *"someone authorised accessed File Share."*

Every technology below exists to make one of these steps work.

## Cryptography building blocks

Six small tools, combined, give us everything the proof needs.

### Hash function

**Simply:** a blender for data. Put anything in, get a fixed-size fingerprint out. The same input always gives the same fingerprint; you can't turn the fingerprint back into the input; changing one letter changes the whole fingerprint. **In our project:** we hash the credential's attributes into one number, and hash the user's secret so the issuer never sees the secret itself.

### Poseidon

**Simply:** a hash function designed to be cheap *inside* a zero-knowledge proof. SHA-256 works fine on a normal computer but is very expensive to prove; Poseidon is built from the exact maths ZK circuits are good at. **Technically:** an arithmetic-friendly hash over a prime field; roughly a few hundred constraints per hash vs. tens of thousands for SHA-256. **Watch out:** the circuit, the issuer and the client must all use the *same* Poseidon parameters, or nothing will match.

### Digital signature (EdDSA on BabyJubJub)

**Simply:** a wax seal only the company can make, but anyone can check. The issuer "seals" the credential hash; if anyone changes one attribute, the seal breaks. **Technically:** EdDSA is a signature scheme; BabyJubJub is an elliptic curve chosen because it lives inside the same number field Circom uses, so checking the signature inside a proof is affordable.

### Merkle tree

**Simply:** a way to summarise a huge list into one short fingerprint (the **root**). You can prove "my item is in the list" by showing just a short path of fingerprints, about 16 for 65,000 items, without revealing which item is yours (inside a ZK proof). **In our project:** the list of all valid credentials. Revoking someone removes their entry, which changes the root; their old proofs no longer match.

### Nullifier

**Simply:** an anonymous ticket stub. The same person, same service, same time window always produces the same stub, so the gateway can say "you've used this already" without knowing who you are. Different services give different stubs, so they can't be linked together. **Technically:** `Poseidon(user_secret, resource_id, epoch)`, output publicly by the circuit.

### Nonce

**Simply:** a random one-time number the gateway hands out. The proof must include it, so a recorded proof is useless later. This stops **replay attacks**.

## Zero-knowledge proofs

A zero-knowledge proof convinces someone a statement is true while revealing nothing beyond the fact that it's true.

**Classic analogy (Where's Waldo):** you want to prove you found Waldo without showing where. You cover the page with a huge sheet of cardboard that has a small Waldo-sized hole, and position it so only Waldo shows through. The other person sees Waldo, so they know you found him, but they have no idea where on the page he is.

**Three properties every ZKP has:**

| Property | Plain meaning |
| --- | --- |
| Completeness | If the statement is true, an honest prover can always convince the verifier |
| Soundness | If it's false, a cheater can't convince the verifier (except with negligible probability) |
| Zero-knowledge | The verifier learns nothing except "it's true" |

### SNARK

**Simply:** a kind of ZKP that's tiny and fast to check. **S**uccinct (small), **N**on-interactive (one message, no back-and-forth), **AR**gument of **K**nowledge (the prover really knows the secret data).

### Groth16

**Simply:** the specific SNARK we use. Its proofs are always about 200 bytes and verify in milliseconds, no matter how complex the statement. **Trade-off:** it needs a **trusted setup** for each circuit (see below).

### Circuit

**Simply:** the statement we want to prove, written as a big set of maths equations. "Signature is valid AND credential is in the tree AND role is allowed" becomes thousands of small equations. If all equations hold, the statement is true. **Constraint:** one of those small equations. Circuit size is measured in constraints; more constraints = slower proving.

### Witness

**Simply:** all the secret values that make the equations true: the attributes, the signature, the Merkle path, the user secret. The prover has it; the verifier never sees it.

### Public vs. private inputs

- **Public:** values both sides know (policy, Merkle root, nonce, nullifier). The verifier checks the proof against these.
- **Private:** the witness. Stays on the user's machine.

### Proving key and verification key

**Simply:** produced once per circuit during setup. The client uses the **proving key** to make proofs; the gateway uses the much smaller **verification key** to check them.

### Trusted setup (Powers of Tau)

**Simply:** Groth16 needs some secret random numbers to create the keys. If anyone kept those numbers (called "toxic waste"), they could forge proofs. So setup is done as a ceremony where many people each add randomness; as long as *one* of them deletes theirs, it's safe. **In our project:** we reuse a large public ceremony (Powers of Tau, phase 1) and do the circuit-specific phase 2 ourselves. We state this as a limitation in the report.

## Circom and snarkjs

**Circom** is the language we write circuits in. **snarkjs** is the tool that turns a circuit into keys, proofs and verifications.

### Writing a circuit feels like this

You don't write steps that run in order like Python. You declare **signals** (values) and **constraints** (equations that must hold). The smallest useful example, "I know a secret whose hash is `h`":

```
pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";

template KnowSecret() {
    signal input secret;   // private: only the prover knows it
    signal input h;        // public: everyone knows it

    component hasher = Poseidon(1);
    hasher.inputs[0] <== secret;
    h === hasher.out;      // the constraint: hash(secret) must equal h
}

component main {public [h]} = KnowSecret();
```

Our real circuit is the same idea, just bigger: it chains circomlib's Poseidon, EdDSA verifier, Merkle proof and comparator components.

### The three operators (and the classic bug)

| Operator | Meaning | Safe? |
| --- | --- | --- |
| `<==` | Assign a value **and** add a constraint | Yes, use by default |
| `===` | Add a constraint only | Yes |
| `<--` | Assign a value **without** a constraint | Dangerous |

With `<--`, the honest prover computes the right value, but nothing *forces* it. A cheater can put any value there and the proof still verifies. This **under-constrained circuit** bug is the most common real-world ZK vulnerability. Rule for us: every `<--` must be followed by an `===` that checks it, plus a negative test.

### The snarkjs pipeline

1. **Compile:** `circom access.circom --r1cs --wasm` turns the circuit into equations (`.r1cs`) and a witness generator (`.wasm`).
2. **Setup:** take the public Powers of Tau file, run Groth16 setup, add our contribution → proving key (`.zkey`) and verification key (`.json`).
3. **Prove (client):** inputs + `.wasm` + `.zkey` → `proof.json` + `public.json`.
4. **Verify (gateway):** verification key + proof + public inputs → true / false.

Steps 1–2 happen once per circuit change; 3–4 happen on every request.

## Identity and zero trust

This is the world our project improves on; we need to explain it well to show what we changed.

### Zero trust

**Simply:** the old model was a castle: once you're inside the company network, you're trusted. Zero trust says never trust by location; check **every request**, every time, against a policy. **Our twist:** zero trust usually means checking *more* about you on every request. We check just as often but learn *less*.

### SSO (single sign-on)

**Simply:** log in once, get into many apps. The company's login server vouches for you to every app.

### OIDC (OpenID Connect)

**Simply:** the standard "language" SSO systems use. It's what powers "Log in with Google" buttons. **Technically:** built on OAuth 2.0; after login, the app receives an ID token describing who you are.

### JWT (JSON Web Token)

**Simply:** a signed note from the login server, e.g. `{"name": "Alice", "email": "alice@corp", "roles": ["engineer"]}`. The app checks the signature and trusts the contents. **The privacy problem:** every app sees everything in the token, and logs it. This is exactly what our demo's split screen highlights in red.

### Keycloak

**Simply:** a free, open-source SSO server that speaks OIDC. We use it as our **baseline**: the "normal" way, protecting the same three services, so we can compare fairly.

### Sessions

**Simply:** after a successful check, the gateway gives the browser a short-lived cookie so you don't prove on every click. Ours lasts 10 minutes, then you prove again, which keeps the zero-trust "check continuously" promise.

### Replay attack

**Simply:** an attacker records a valid login message and sends it again later to get in. We stop it with the nonce: each proof is bound to a one-time number the gateway only accepts once.

## Backend and infrastructure

The plumbing that connects the cryptography to real web services.

| Technology | Simply | Where we use it |
| --- | --- | --- |
| FastAPI (Python) | A quick way to build web APIs in Python; auto-generates API docs | Issuer service, gateway |
| Node.js | JavaScript outside the browser | Running snarkjs (proving and verifying), Merkle tree library |
| Reverse proxy | A front door that receives every request and decides whether to pass it to the service behind it | The gateway sits in front of Wiki, File Share and Admin Panel |
| WebSocket | A connection that stays open so the server can push updates instantly, instead of the page asking repeatedly | Live event feed to the demo screens |
| Docker | Packages each service with everything it needs, so it runs identically on any laptop | Every component is a container |
| Docker Compose | Starts all containers together with one command and wires them up | `make demo` boots the whole system |
| Mock services | Tiny fake apps that just show a page | Wiki, File Share, Admin Panel: things worth protecting in the demo |

**Why Python and Node together?** snarkjs (the ZK tool) is JavaScript, but we're fastest at writing APIs in Python. The gateway either calls a small Node verify service, or shells out to snarkjs. Either is fine; pick one in week 1 and record it in the interface contract.

## Frontend

The final result is judged on the demo as well as the tech, so the UI matters as much as the circuit.

| Technology | Simply | Where we use it |
| --- | --- | --- |
| React | Builds web pages from reusable pieces ("components") that update automatically when data changes | All five demo screens |
| Vite | The development tool that runs and bundles the React app; very fast reloads | Building and serving the UI |
| Tailwind CSS | Style elements with short class names directly in the markup instead of separate CSS files | Making the demo look polished quickly |
| snarkjs in the browser (nice-to-have N1) | The same proving library, compiled to run in the user's browser | Proof generated on the user's own device |

**Design rule for the demo:** every cryptographic step should be *visible*. Animate "challenge → proving → verified", show timers, colour denials red with the reason. If the audience can't see it, it didn't happen.

## Testing

In a security project, tests are evidence. Each one becomes a line in the report.

| Technology | Simply | Where we use it |
| --- | --- | --- |
| circom\_tester + Mocha | Runs a circuit with chosen inputs and checks it accepts or rejects them | Every circuit constraint |
| pytest | Python's standard test runner | Issuer, registry, gateway logic |
| CI (GitHub Actions) | Runs all tests automatically on every push | Nobody merges a broken circuit |

### Positive vs. negative tests

- **Positive test:** valid inputs → proof works. Easy, and not enough.
- **Negative test:** deliberately wrong inputs → proof must fail. Examples: wrong signature, attribute changed, path for a revoked leaf, clearance one below the minimum.

**The key trick:** for every constraint, temporarily delete it and check that at least one negative test now passes when it shouldn't. If no test notices, that constraint isn't really tested, and an attacker might not notice either.

## Glossary

| Term | One-line meaning |
| --- | --- |
| Attribute | A fact on the credential: role, department, clearance, device compliant, expiry |
| BabyJubJub | Elliptic curve that makes signature checks cheap inside Circom circuits |
| Circuit | The statement to prove, written as equations |
| Commitment | A hash that locks in a secret value without revealing it |
| Constraint | One equation in the circuit; circuit size is counted in these |
| Credential | The signed digital ID card the issuer gives each user |
| EdDSA | The signature scheme the issuer uses to seal credentials |
| Epoch | A time window (e.g. 10 minutes) used for rate limiting and sessions |
| Gateway | Our verifier: checks proofs and guards the services |
| Groth16 | The SNARK we use: \~200-byte proofs, millisecond verification |
| Issuer | The company service that signs credentials and maintains the registry |
| Merkle root | One fingerprint summarising every valid credential |
| Merkle path | The short chain of hashes proving one entry belongs under the root |
| Nonce | One-time random number that stops replay attacks |
| Nullifier | Anonymous per-service, per-epoch tag used for rate limiting |
| OIDC | The standard protocol behind SSO logins |
| Poseidon | ZK-friendly hash function |
| Powers of Tau | The public multi-party ceremony behind our trusted setup |
| Proving key | Large file the client uses to generate proofs |
| Public input | A value the verifier sees and checks the proof against |
| Private input / witness | Secret values that make the circuit's equations hold |
| Replay attack | Re-sending a recorded valid message to gain access |
| Revocation | Cancelling a credential by removing it from the Merkle tree |
| SNARK | Succinct, non-interactive zero-knowledge proof |
| snarkjs | The JavaScript tool that does setup, proving and verifying |
| Trusted setup | One-time key generation that must destroy its secret randomness |
| Under-constrained | Circuit bug where a value isn't forced by any equation, so cheaters can fake it |
| Verification key | Small file the gateway uses to check proofs |
| Zero trust | Verify every request against policy; never trust by network location |
