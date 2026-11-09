#!/usr/bin/env bash
# Phase 1 (Powers of Tau) for Groth16 over bn128.
#
#   circuits/scripts/ptau.sh                 # power from PTAU_POWER (default 15), source from PTAU_SOURCE
#   circuits/scripts/ptau.sh --print-pins    # print "<power> <blake2b-512>" for every pinned Hermez file
#   circuits/scripts/ptau.sh --print-pse-pins  # same for every pinned PSE ppot 0080 file
#
# Prints the path of a phase-2-ready .ptau on stdout (last line); logs go to stderr.
#
# PTAU_SOURCE=auto (default) | pse | hermez | dev
#   pse     PSE Perpetual Powers of Tau, contribution 0080, prepared for phase 2:
#           ppot_0080_<NN>.ptau from PSE's official bucket (PSE_PTAU_URL below). Checked against
#           the blake2b-512 pinned in PSE_B2. A mismatch is fatal. This is the phase 1 of the
#           committed keys (G2-S1-CIRC-040a); see "PSE provenance" below.
#   hermez  Download powersOfTau28_hez_final_<NN>.ptau (the public Hermez ceremony: 54
#           contributions + beacon, already prepared for phase 2) and check its blake2b-512
#           against the hash pinned below, copied from the snarkjs README. A mismatch is fatal.
#           NO LONGER DOWNLOADABLE (2026-11-08): the Google bucket and the hermez S3 bucket both
#           return AccessDenied at the source. Kept for anyone holding a cached copy.
#   dev     Use the cached pot<NN>_DEV-ONLY_final.ptau in PTAU_DIR if its blake2b matches its
#           .info.json sidecar, else run a local ceremony: new, two contributions with
#           /dev/urandom entropy, a beacon, prepare phase2, verify (~10 min at power 15).
#           DEV-ONLY: every contributor was this machine, so whoever ran it could forge proofs.
#   auto    pse, then hermez; if both fail (offline, 403, no pin), fall back to dev with a loud
#           warning.
#
# A power-N file supports circuits with up to 2^N constraints (minus public inputs + 1).
# setup.sh raises N if a circuit needs more. Files are cached in PTAU_DIR (default
# ~/zkp-cache/ptau, outside the tree) and reused while their hash still matches.
source "$(dirname "${BASH_SOURCE[0]}")/setup-lib.sh"

# blake2b-512 of powersOfTau28_hez_final_<NN>.ptau, from the table in snarkjs 0.7.6 README.md
# ("Prepared (phase2) Ptau files for bn128 with 54 contributions and a beacon").
# circuits/test/setup.test.js cross-checks every pin against the installed snarkjs README.
declare -A HERMEZ_B2=(
  [8]=d6a8fb3a04feb600096c3b791f936a578c4e664d262e4aa24beed1b7a9a96aa5eb72864d628db247e9293384b74b36ffb52ca8d148d6e1b8b51e279fdf57b583
  [9]=94f108a80e81b5d932d8e8c9e8fd7f46cf32457e31462deeeef37af1b71c2c1b3c71fb0d9b59c654ec266b042735f50311f9fd1d4cadce47ab234ad163157cb5
  [10]=6cfeb8cda92453099d20120bdd0e8a5c4e7706c2da9a8f09ccc157ed2464d921fd0437fb70db42104769efd7d6f3c1f964bcf448c455eab6f6c7d863e88a5849
  [11]=47c282116b892e5ac92ca238578006e31a47e7c7e70f0baa8b687f0a5203e28ea07bbbec765a98dcd654bad618475d4661bfaec3bd9ad2ed12e7abc251d94d33
  [12]=ded2694169b7b08e898f736d5de95af87c3f1a64594013351b1a796dbee393bd825f88f9468c84505ddd11eb0b1465ac9b43b9064aa8ec97f2b73e04758b8a4a
  [13]=58efc8bf2834d04768a3d7ffcd8e1e23d461561729beaac4e3e7a47829a1c9066d5320241e124a1a8e8aa6c75be0ba66f65bc8239a0542ed38e11276f6fdb4d9
  [14]=eeefbcf7c3803b523c94112023c7ff89558f9b8e0cf5d6cdcba3ade60f168af4a181c9c21774b94fbae6c90411995f7d854d02ebd93fb66043dbb06f17a831c1
  [15]=982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e
  [16]=6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125
  [17]=6247a3433948b35fbfae414fa5a9355bfb45f56efa7ab4929e669264a0258976741dfbe3288bfb49828e5df02c2e633df38d2245e30162ae7e3bcca5b8b49345
  [18]=7e6a9c2e5f05179ddfc923f38f917c9e6831d16922a902b0b4758b8e79c2ab8a81bb5f29952e16ee6c5067ed044d7857b5de120a90704c1d3b637fd94b95b13e
  [19]=bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff6648600eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887
  [20]=89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c7556a52b323178269d64af325d8fdddb33da3a27c34409b821de82aa2bf1a27b
)
# Mirrors, tried in order. Both serve the same files; the hash pin is what we trust, not the host.
# PTAU_MIRRORS (space-separated base URLs) overrides them, e.g. for an internal cache.
HERMEZ_URLS=(
  "https://storage.googleapis.com/zkevm/ptau"
  "https://hermez.s3-eu-west-1.amazonaws.com"
)
if [ -n "${PTAU_MIRRORS:-}" ]; then read -r -a HERMEZ_URLS <<< "$PTAU_MIRRORS"; fi

# --- PSE provenance ------------------------------------------------------------------------------
# Source: https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_<NN>.ptau,
# over HTTPS from PSE's official bucket (the maintained successor of the Hermez files, which are no
# longer downloadable). PSE's README: the 0080 files are prepared for phase 2 from contribution 0080
# with a beacon (Ethereum beacon chain slot 7,325,000 randao_reveal, 31 iterations).
# Power 15 file as checked on 2026-11-08 (accepted by the Orchestrator, G2-S1-CIRC-040a):
#   - header: power 15, ceremonyPower 28, prepared for phase 2 (sections 12-15 present),
#     62 contributions recorded in section 7;
#   - transcript linkage to PSE's published attestation for contribution 0080 (perpetualpowersoftau
#     repo, 0080_carter_response/README.md): section 7 contains the published challenge_0080 hash
#     (prefix d9ec6fad4a7a7e3358a0c4bed7171622) at byte offset 90185 and the published
#     challenge_0081 / new_challenge hash (prefix 4bf672f3ba1de1bb6105e1ab88359612) at offset 91706;
#   - NOT done: a full `snarkjs powersoftau verify` (its initial hash runs over 2^28 points;
#     infeasible in the sandbox). PTAU_FULL_VERIFY=1 runs it after a download.
# PSE publishes NO hash for the prepared files, so the blake2b-512 below was PINNED ON FIRST
# DOWNLOAD 2026-11-08 (37,842,066 bytes); its provenance is the checks above + the 0080
# attestation, not a published value. Only power 15 is pinned; other powers fail closed.
PSE_PTAU_URL="${PSE_PTAU_URL:-https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080}"
declare -A PSE_B2=(
  [15]=a6dd3adcf80f6716c4d082be2626e790af1f5ed3d760814dc439a07d91e93421382c91d4f705abe8cd90ef1956e4b7eaf58db29d81be5abe624dab4dae827f24
)
PSE_SOURCE_LABEL="pse-ppot-0080"
PSE_PROVENANCE="PSE Perpetual Powers of Tau contribution 0080, prepared for phase 2 with a beacon (Ethereum beacon chain slot 7,325,000 randao_reveal, 31 iterations); downloaded over HTTPS from PSE's official bucket ($PSE_PTAU_URL); header power 15, ceremonyPower 28, sections 12-15 present, 62 contributions in section 7; section 7 contains the published challenge_0080 hash (d9ec6fad4a7a7e3358a0c4bed7171622...) at offset 90185 and challenge_0081 hash (4bf672f3ba1de1bb6105e1ab88359612...) at offset 91706, matching 0080_carter_response/README.md; blake2b-512 pinned on first download 2026-11-08 (PSE publishes no hash for prepared files); full snarkjs powersoftau verify not run (2^28-point initial hash infeasible in the sandbox)"

if [ "${1:-}" = "--print-pins" ]; then
  for n in $(printf '%s\n' "${!HERMEZ_B2[@]}" | sort -n); do echo "$n ${HERMEZ_B2[$n]}"; done
  exit 0
fi
if [ "${1:-}" = "--print-pse-pins" ]; then
  for n in $(printf '%s\n' "${!PSE_B2[@]}" | sort -n); do echo "$n ${PSE_B2[$n]}"; done
  exit 0
fi

N="${PTAU_POWER:-15}"
SOURCE="${PTAU_SOURCE:-auto}"
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 8 ] && [ "$N" -le 28 ] || die "PTAU_POWER must be 8..28, got '$N'"
mkdir -p "$PTAU_DIR"
NN="$(printf '%02d' "$N")"

# Sidecar <file>.info.json: what setup.sh copies into the manifest.
write_info() { # file source
  local f="$1" src="$2"
  node -e '
    const [f, src, n, b2] = process.argv.slice(1);
    const fs = require("fs"), path = require("path");
    const info = { file: path.basename(f), source: src, power: Number(n),
      blake2b: b2, created: new Date().toISOString() };
    if (src === "dev") info.warning = "DEV-ONLY: single-machine ceremony, toxic waste not provably destroyed; never use in production";
    if (process.env.PTAU_INFO_PROVENANCE) info.provenance = process.env.PTAU_INFO_PROVENANCE;
    fs.writeFileSync(f + ".info.json", JSON.stringify(info, null, 2) + "\n");
  ' "$f" "$src" "$N" "$(blake2b_of "$f")"
}

# True if <file>.info.json exists and records <source> and the file's current blake2b.
info_matches() { # file source
  [ -f "$1.info.json" ] && node -e '
    const i = require(process.argv[1]);
    process.exit(i.source === process.argv[2] && i.blake2b === process.argv[3] ? 0 : 1);
  ' "$1.info.json" "$2" "$(blake2b_of "$1")" 2>/dev/null
}

pse() {
  local name="ppot_0080_${NN}.ptau" want="${PSE_B2[$N]:-}"
  local out="$PTAU_DIR/$name"
  [ -n "$want" ] || { log "no pinned PSE ppot 0080 hash for power $N (only 15 is pinned)"; return 1; }
  if [ -f "$out" ]; then
    local have; have="$(blake2b_of "$out")"
    if [ "$have" = "$want" ]; then
      info_matches "$out" "$PSE_SOURCE_LABEL" ||
        PTAU_INFO_PROVENANCE="$PSE_PROVENANCE" write_info "$out" "$PSE_SOURCE_LABEL"
      log "using cached PSE ptau $name (blake2b matches pin)"; echo "$out"; return 0
    fi
    die "cached $name blake2b $have != pinned $want — refusing to use it (delete it to re-download)"
  fi
  log "downloading $PSE_PTAU_URL/$name"
  if curl -fsSL --retry 2 --connect-timeout 20 -o "$out.part" "$PSE_PTAU_URL/$name"; then
    local got; got="$(blake2b_of "$out.part")"
    if [ "$got" = "$want" ]; then
      mv "$out.part" "$out"; PTAU_INFO_PROVENANCE="$PSE_PROVENANCE" write_info "$out" "$PSE_SOURCE_LABEL"
      log "PSE ptau $name verified (blake2b-512 $want)"
      if [ "${PTAU_FULL_VERIFY:-0}" = "1" ]; then
        log "PTAU_FULL_VERIFY=1: running snarkjs powersoftau verify (very slow: ceremonyPower 28)"
        snarkjs powersoftau verify "$out"
      fi
      echo "$out"; return 0
    fi
    rm -f "$out.part"
    die "blake2b mismatch for $name from $PSE_PTAU_URL: got $got, pinned $want — refusing to use it"
  fi
  rm -f "$out.part"
  log "PSE download failed"
  return 1
}

info_blake2b() { node -p 'require(process.argv[1]).blake2b' "$1" 2>/dev/null || true; }

hermez() {
  local name="powersOfTau28_hez_final_${NN}.ptau" want="${HERMEZ_B2[$N]:-}"
  local out="$PTAU_DIR/$name"
  [ -n "$want" ] || { log "no pinned Hermez hash for power $N"; return 1; }
  if [ -f "$out" ] && [ "$(blake2b_of "$out")" = "$want" ]; then
    [ -f "$out.info.json" ] || write_info "$out" hermez
    log "using cached Hermez ptau $name (blake2b matches pin)"; echo "$out"; return 0
  fi
  local base
  for base in "${HERMEZ_URLS[@]}"; do
    log "downloading $base/$name"
    if curl -fsSL --retry 2 --connect-timeout 20 -o "$out.part" "$base/$name"; then
      local got; got="$(blake2b_of "$out.part")"
      if [ "$got" = "$want" ]; then
        mv "$out.part" "$out"; write_info "$out" hermez
        log "Hermez ptau $name verified (blake2b-512 $want)"
        if [ "${PTAU_FULL_VERIFY:-0}" = "1" ]; then
          log "PTAU_FULL_VERIFY=1: running snarkjs powersoftau verify (slow)"
          snarkjs powersoftau verify "$out"
        fi
        echo "$out"; return 0
      fi
      rm -f "$out.part"
      die "blake2b mismatch for $name from $base: got $got, pinned $want — refusing to use it"
    fi
    rm -f "$out.part"
  done
  log "Hermez download failed from all mirrors"
  return 1
}

dev() {
  local final="$PTAU_DIR/pot${NN}_DEV-ONLY_final.ptau"
  if [ -f "$final" ] && [ -f "$final.info.json" ] &&
     [ "$(info_blake2b "$final.info.json")" = "$(blake2b_of "$final")" ]; then
    log "using cached DEV-ONLY ptau $(basename "$final") (blake2b matches its .info.json)"; echo "$final"; return 0
  fi
  [ -f "$final" ] && log "cached $(basename "$final") does not match its .info.json; regenerating"
  local w; w="$(mktemp -d "$PTAU_DIR/dev-XXXXXX")"
  trap 'rm -rf "$w"' EXIT
  log "=== DEV-ONLY Powers of Tau ceremony, power $N — NOT FOR PRODUCTION ==="
  snarkjs powersoftau new bn128 "$N" "$w/pot_0000.ptau"
  snarkjs_contribute powersoftau contribute "$w/pot_0000.ptau" "$w/pot_0001.ptau" --name="DEV-ONLY contribution 1"
  snarkjs_contribute powersoftau contribute "$w/pot_0001.ptau" "$w/pot_0002.ptau" --name="DEV-ONLY contribution 2"
  # A real beacon is public randomness fixed in advance (e.g. a future block hash); here it is
  # fresh urandom, recorded in the logs, which is adequate for a DEV-ONLY file.
  local beacon; beacon="$(urandom_hex 32)"
  log "beacon hash $beacon"
  snarkjs powersoftau beacon "$w/pot_0002.ptau" "$w/pot_beacon.ptau" "$beacon" 10 --name="DEV-ONLY beacon"
  snarkjs powersoftau prepare phase2 "$w/pot_beacon.ptau" "$w/pot_final.ptau"
  snarkjs powersoftau verify "$w/pot_final.ptau"
  mv "$w/pot_final.ptau" "$final"
  write_info "$final" dev
  log "DEV-ONLY ptau ready: $(basename "$final")"
  echo "$final"
}

case "$SOURCE" in
  pse) pse || die "PSE ptau unavailable and PTAU_SOURCE=pse forbids any fallback" ;;
  hermez) hermez || die "Hermez ptau unavailable and PTAU_SOURCE=hermez forbids the dev fallback" ;;
  dev) dev ;;
  auto)
    if ! pse && ! hermez; then
      log "WARNING: falling back to a DEV-ONLY ptau (set PTAU_SOURCE=pse to forbid this)"
      dev
    fi
    ;;
  *) die "PTAU_SOURCE must be auto|pse|hermez|dev, got '$SOURCE'" ;;
esac
