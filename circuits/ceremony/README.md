# Multi-party phase-2 ceremony

`circuits/scripts/setup.sh` does a **single-party** phase 2: whoever ran it could, in principle,
have kept the randomness ("toxic waste") and forge proofs. `circuits/scripts/ceremony.sh` removes
that limitation without changing the circuit: each teammate adds one phase-2 contribution **on their
own machine, in turn**, and the final proving/verification key is sound as long as **at least one**
of them generated their randomness honestly and did not keep it. A public random beacon, announced
before the ceremony starts, closes it.

Phase 1 is unchanged: the public PSE Perpetual Powers of Tau, contribution 0080, power 15
(`~/zkp-cache/ptau/ppot_0080_15.ptau`, pinned in `circuits/scripts/ptau.sh`). The committed
`circuits/setup/integrated_access_v{3,4}.*` keys and `circuits/fixtures/v4/**` stay untouched until
the team runs this for real and installs the result in one commit
([After the ceremony](#after-the-ceremony)).

All commands run from the **repository root**. `npm run ceremony:<cmd> -- <args>` is the same as
`circuits/scripts/ceremony.sh <cmd> <args>`.

## Roles (team of 3), for `integrated_access_v4`

| Who | Runs | Sends on (out of band) |
|---|---|---|
| **P1, coordinator** (also contributor 1) | `init`, `contribute`, later `finalize` + `install` + the commit | `integrated_access_v4_0001.zkey` + `transcript.json` to P2 |
| **P2** | `verify` P1's zkey, `contribute` | `integrated_access_v4_0002.zkey` + `transcript.json` to P3 |
| **P3** | `verify` P2's zkey, `contribute` | `integrated_access_v4_0003.zkey` + `transcript.json` back to P1 |

With two people, drop P3 and P1 finalizes P2's zkey. `finalize` refuses fewer than **2**
contributions whatever `CEREMONY_MIN_CONTRIBUTIONS` says (it can only raise the floor): one
contribution is the single-party setup again. For `integrated_access_v3` replace the name and use
`npm run ceremony:init:v3`.

### What every machine needs

- The repository at the **same commit** (P1 names it in the team channel), `npm ci` at the root.
- circom **2.2.3** in `~/.cargo/bin` (the r1cs must hash to `r1cs_sha256` in the transcript; a
  different compiler or tree is refused with a message naming the hash).
- The **same phase-1 file**: `PTAU_SOURCE=pse PTAU_POWER=15 circuits/scripts/ptau.sh` downloads
  `ppot_0080_15.ptau` (~38 MB) into `~/zkp-cache/ptau/` and checks its pinned blake2b. Every step
  checks it against `ptau.blake2b` in the transcript. `PTAU=<path>` points at a copy elsewhere.

## What travels and what is committed

| File (`circuits/ceremony/<name>/`) | Where |
|---|---|
| `transcript.json` | travels **with** each zkey; committed at the end |
| `<name>.verification_key.json`, `<name>.manifest.json` | written by `finalize`; committed at the end |
| `<name>_NNNN.zkey`, `<name>_final.zkey` | **out of band** only (shared drive, `scp`; ~6.1 MB each for v4); gitignored |
| `build/` | rebuilt on each machine from the circuit; gitignored |

A received zkey is never trusted as-is: `contribute`, `verify` and `finalize` first run
`snarkjs zkey verify` against the locally compiled r1cs and the PSE ptau (this replays every
contribution in the zkey cryptographically) and then match the chain inside the zkey against the
transcript. The transcript alone proves nothing; what makes it trustworthy is that each participant
publishes their own contribution hash **before** passing the zkey on, and everyone checks the
chain against those published hashes.

## Step by step

### 0. P1, before anyone starts: announce the beacon

Pick the beacon now and post it in the team channel, e.g. *"the beacon is drand mainnet round R"*
(a round about a day in the future: `https://api.drand.sh/public/R`, field `randomness`, 64 hex) or
*"the hash of Bitcoin block H"* (a block height in the future). Fixing it in advance means nobody,
including P1, can choose it after seeing the contributions. Also post the commit everyone checks out.

### 1. P1: init and contribute

```sh
git checkout <announced commit> && npm ci
npm run ceremony:init:v4        # = PTAU_SOURCE=pse circuits/scripts/ceremony.sh init circuits/integrated_access_v4.circom integrated_access_v4
circuits/scripts/ceremony.sh contribute integrated_access_v4 \
  circuits/ceremony/integrated_access_v4/integrated_access_v4_0000.zkey "Person One"
```

`init` compiles at `--O2` with the same flags as `setup.sh`, runs `groth16 setup` (deterministic:
anyone can reproduce `_0000` from the r1cs + ptau) and writes the transcript (circuit source sha256,
r1cs sha256, snarkjs circuit hash, ptau source + blake2b + provenance). `contribute` verifies the
zkey you hand it, contributes with fresh entropy, appends to the transcript and prints the
**contribution hash**. Post that hash in the team channel, then send
`integrated_access_v4_0001.zkey` and `transcript.json` to P2.

### 2. P2: verify, then contribute

Put both received files into `circuits/ceremony/integrated_access_v4/`, then:

```sh
git checkout <announced commit> && npm ci
circuits/scripts/ceremony.sh verify integrated_access_v4 circuits/ceremony/integrated_access_v4/integrated_access_v4_0001.zkey
```

Check that the printed chain shows `#1 Person One` with **exactly the hash P1 posted**. Then:

```sh
circuits/scripts/ceremony.sh contribute integrated_access_v4 \
  circuits/ceremony/integrated_access_v4/integrated_access_v4_0001.zkey "Person Two"
```

Post your hash; send `integrated_access_v4_0002.zkey` + `transcript.json` to P3. (`contribute`
re-runs the same verification itself, so a forgotten `verify` is still safe; running it first lets
you compare hashes before you contribute.)

### 3. P3: same as P2

```sh
circuits/scripts/ceremony.sh verify integrated_access_v4 circuits/ceremony/integrated_access_v4/integrated_access_v4_0002.zkey
#   -> #1 Person One, #2 Person Two, with the hashes they posted?
circuits/scripts/ceremony.sh contribute integrated_access_v4 \
  circuits/ceremony/integrated_access_v4/integrated_access_v4_0002.zkey "Person Three"
```

Post your hash; send `integrated_access_v4_0003.zkey` + `transcript.json` back to P1.

### 4. P1: finalize with the announced beacon

Once the announced drand round / block exists, read its value and:

```sh
BEACON_SOURCE="drand mainnet round R" \
  circuits/scripts/ceremony.sh finalize integrated_access_v4 \
  circuits/ceremony/integrated_access_v4/integrated_access_v4_0003.zkey <beacon-hex>
```

This verifies `_0003` (must be the latest, ceremony still open), applies the beacon (2^10
iterations), verifies the final zkey against r1cs + ptau + the whole chain, exports the
verification key and writes `circuits/ceremony/integrated_access_v4/integrated_access_v4.manifest.json`.
Without a beacon argument it uses local randomness and records `beacon.public: false`; the manifest
then stays `DEV-ONLY`. That is fine for rehearsals, not for the real thing.

Post the beacon value and the printed beacon contribution hash. Send `integrated_access_v4_final.zkey`
+ `transcript.json` to P2 and P3.

### 5. P2 and P3: final check

```sh
circuits/scripts/ceremony.sh verify integrated_access_v4 circuits/ceremony/integrated_access_v4/integrated_access_v4_final.zkey
```

Each participant confirms their own name and hash are in the chain, in order, that the beacon is
the announced value, and that the verification key matches the final zkey (`verify` checks that
when `integrated_access_v4.verification_key.json` is present). Say "OK" in the channel.

## After the ceremony

P1, in **one commit** (the old fixtures stop verifying the moment the vkey changes):

```sh
npm run ceremony:install -- integrated_access_v4
#   hash checks (final zkey = manifest = transcript beacon entry; vkey, transcript, r1cs, wasm = manifest),
#   then copies circuits/setup/integrated_access_v4.{zkey,wasm,verification_key.json,manifest.json}
#   and build/integrated_access_v4/, then runs artifacts.sh check (exported vkey == committed vkey)
npm run prove:fixtures:v4       # regenerates circuits/fixtures/v4/** against the new zkey
npm test && npm run test:all    # see "Tests that change with the install" below
```

Then commit the keys, manifests and fixtures together (one `git add` with explicit paths, then
`git commit --only` with the same paths):

```
circuits/ceremony/integrated_access_v4/transcript.json
circuits/ceremony/integrated_access_v4/integrated_access_v4.verification_key.json
circuits/ceremony/integrated_access_v4/integrated_access_v4.manifest.json
circuits/setup/integrated_access_v4.zkey
circuits/setup/integrated_access_v4.wasm
circuits/setup/integrated_access_v4.verification_key.json
circuits/setup/integrated_access_v4.manifest.json
circuits/setup/ARTIFACTS.md            (sizes + hashes table)
circuits/setup/README.md               (status paragraph)
circuits/fixtures/v4/
circuits/scripts/access-fixtures.js    (TEST_ONLY text: it still says "single-party phase 2")
circuits/test/setup_v4.test.js  circuits/test/fixtures_v4.test.js   (assertions below)
```

e.g. `git commit --only <the same paths> -m "feat(circuits): integrated_access_v4 keys from the multi-party ceremony"`.

### Tests that change with the install

- `tests/safety` **F9.06** asserts, unconditionally, `status === "DEV-ONLY"` and a
  `single-party phase 2` limitation for both committed manifests, and `/DEV-ONLY/` in the fixtures'
  `TEST_ONLY`. A ceremony manifest has neither (with ≥ 2 contributions, PSE phase 1 and a public
  beacon its status is `DEMO-ONLY`). `tests/safety/**` is append-only and owned by `safety`: they
  must supersede F9.06 (e.g. a new test that accepts a multi-party manifest) **before** the install
  commit. Ask them first; do not install over a red floor.
- F9.09 is compatible as is: it compares `phase2.contributions >= 2` (a number; the chain is in
  `phase2.contributors`), and the ceremony manifest keeps the `ptau` block and the
  "pinned on first download" phase-1 limitation it checks.
- F9.10 (`fixtures.json` names the current zkey/vkey; every superseded v4 vkey refuses every
  current fixture) holds after `prove:fixtures:v4`.
- `circuits/test/setup_v4.test.js` ("records DEV-ONLY status, the single-party limitation...") and
  `circuits/test/fixtures_v4.test.js` (`TEST_ONLY` matches `single-party phase 2`) pin the
  single-party wording for v4; for v3 the same holds in `circuits/test/setup.test.js`. Update them
  in the install commit.

## What to publish

- Before step 1 (P1): the beacon announcement and the commit.
- Each contributor: their contribution hash, printed by `contribute`, in the team channel (or a
  signed commit message) **before** passing the zkey on. That is the attestation: "this hash is
  mine, I used fresh randomness and did not keep it".
- P1 at step 4: the beacon value and the beacon contribution hash.
- The committed `transcript.json` + `manifest.json` let anyone re-check the chain later with
  `ceremony.sh verify` given the final zkey (`circuits/setup/integrated_access_v4.zkey` is that
  file).

## Entropy

`contribute` reads 64 bytes from `/dev/urandom` and feeds them to snarkjs **on stdin** through a
bash builtin (`printf ... |`), never on the command line, so they are not in `ps` or shell history,
and never in a log, the transcript or the manifest (`circuits/test/ceremony.test.js` checks). snarkjs
mixes in its own `crypto.randomBytes`. On a terminal it also offers to take extra text you type
(hidden). The secret only exists in the memory of that one `snarkjs` process, which exits when the
contribution is written; there is no file to delete. Do not contribute inside a VM snapshot you
keep, and do not record the terminal session.

## Transcript format (`zk-access-gate.ceremony-transcript v1`)

```jsonc
{
  "format": "zk-access-gate.ceremony-transcript v1",
  "name": "integrated_access_v4",
  "circuit": "circuits/integrated_access_v4.circom",   // repo-relative
  "circuit_source_sha256": "…",          // sha256 of the main .circom file
  "circom_version": "2.2.3", "circom_flags": "--O2 --r1cs --wasm --sym", "snarkjs_version": "0.7.6",
  "constraints": 9208, "n_pub_in": 11, "n_out": 1,
  "r1cs_sha256": "…",                    // must match a local recompile
  "snarkjs_circuit_hash": "…",           // 128 hex, as printed by groth16 setup / zkey verify
  "ptau": { "source": "pse-ppot-0080", "file": "ppot_0080_15.ptau", "power": 15, "blake2b": "…", "provenance": "…" },
  "created": "ISO date",
  "initial": { "zkey": "integrated_access_v4_0000.zkey", "zkey_sha256": "…" },
  "contributions": [
    { "order": 1, "participant": "Person One", "contribution_hash": "…128 hex…",
      "zkey": "integrated_access_v4_0001.zkey", "zkey_sha256": "…", "prev_zkey_sha256": "…", "date": "…" }
  ],
  "beacon": null | { "name": "integrated_access_v4 final beacon", "hash": "…", "iterations_exp": 10,
      "source": "drand mainnet round R", "public": true, "contribution_hash": "…",
      "zkey": "integrated_access_v4_final.zkey", "zkey_sha256": "…", "prev_zkey_sha256": "…", "date": "…" }
}
```

`verify <name> <zkey>` passes only if: `snarkjs zkey verify` against the r1cs and the ptau prints
`ZKey Ok!` and exits 0; the zkey's sha256 is in the transcript; the contributions snarkjs reads out
of the zkey equal the transcript entries up to that zkey (same count, order, hashes and names);
every entry's `prev_zkey_sha256` is the previous entry's `zkey_sha256` and no zkey or hash repeats;
the circuit hash matches; and, for a finalized ceremony, the ceremony vkey is the final zkey's key.
`contribute` and `finalize` additionally require the zkey to be the **latest** one and the ceremony
open (no forks, nothing after the beacon).

## The manifest `finalize` writes

The `setup-manifest.js` shape (same fields, `ptau` block with provenance) with:

- `phase2.contributions`: the number of contributions (≥ 2); `phase2.contributors`:
  `[{order, participant, hash}]`; `beacon_hash`, `beacon_source`, `beacon_public`,
  `beacon_contribution_hash`, `transcript` (repo-relative path), `transcript_sha256`, `limitation`.
- `limitations`: the single-party line is replaced by "multi-party phase 2 (N contributors: …):
  sound as long as at least one contributor … destroyed it"; the phase-1 TOFU-pin line stays; a
  non-public beacon adds a line.
- `status`: `DEMO-ONLY` only with ≥ 2 contributions, a public phase 1 (PSE / Hermez) **and** a
  public beacon; otherwise `DEV-ONLY`, with `status_detail` saying why.

## Measured: rehearsal on `integrated_access_v4` (G2-S1-CIRC-040b)

One machine playing all three people, 4-core sandbox, PSE ppot 0080 power 15, in a temp dir (keys
discarded, nothing committed):

| Step | Wall time |
|---|---|
| `init` (compile + `groth16 setup`) | 27.5 s |
| `contribute` #1 / #2 / #3 (each includes verifying the received zkey) | 28.7 / 27.0 / 27.1 s |
| `verify` `_0003` | 24.4 s |
| `finalize` (verify + beacon 2^10 + final verify + vkey + manifest) | 50.6 s |
| `verify` `_final` (incl. vkey match) | 23.9 s |
| `install` (hash checks + copy + `artifacts.sh check`) | 0.8 s |
| `prove:fixtures:v4` with the rehearsal pair (`--out` a temp dir) | 12.9 s |

About 4 minutes of compute in total; each step is dominated by `snarkjs zkey verify` against the
power-15 ptau. Each zkey is ~6.1 MB, the transcript ~4 KB. The rehearsal manifest came out
`DEMO-ONLY`, 3 contributions, 9208 constraints, 12 public signals; the 11 fixtures re-proved with
the rehearsal pair verify under its vkey, and 0 of the 11 committed fixtures do (as expected:
fixtures must be regenerated with the new key).

## Tests

`circuits/test/ceremony.test.js` runs the whole flow on the ChallengeBinding test main (262
constraints) in a temp dir, with the cached PSE ptau when present (else a power-8 DEV-ONLY ptau):
init → 3 contributions → finalize → install → a fresh in-process proof verifies under the installed
vkey; transcript order and chaining; manifest shape and floor-9 compatibility; and negatives:
tampered intermediate zkey (also with its transcript hash patched), transcript entry removed /
reordered / relabelled, forked chain, contribution after finalize, finalize with 1 contribution
(also with `CEREMONY_MIN_CONTRIBUTIONS=1`), install after a tampered final zkey or transcript, bad
participant name, and no entropy in any log, transcript or manifest. `SKIP_SETUP=1` skips the
end-to-end part (about 1 minute).
