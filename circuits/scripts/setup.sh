#!/usr/bin/env bash
# Phase 2 + keys for one circuit:
#
#   circuits/scripts/setup.sh <circuit.circom> <name>
#   e.g. circuits/scripts/setup.sh circuits/integrated_access_v3.circom integrated_access_v3
#
# <circuit.circom> is resolved against the current directory, then against the repo root.
#
# 1. compile at --O2 (r1cs, wasm, sym) into $BUILD_DIR/<name>/  (default build/<name>/)
# 2. get a phase-1 ptau big enough for the circuit (ptau.sh; or PTAU=<file> to force one)
# 3. groth16 setup -> one contribution with /dev/urandom entropy (stdin) -> beacon -> zkey verify
# 4. export the verification key, write the provenance manifest
#
# Outputs
#   $BUILD_DIR/<name>/<name>.{r1cs,sym,wasm,zkey}, verification_key.json   build outputs (gitignored)
#   $SETUP_OUT/<name>.verification_key.json                              committed
#   $SETUP_OUT/<name>.manifest.json                                      committed (provenance)
# The proving pair (<name>.zkey, <name>.wasm) is NOT copied to $SETUP_OUT: committing it is a
# deliberate step (circuits/setup/ARTIFACTS.md), done in the same commit as the vkey + manifest.
#
# Every run uses fresh randomness, so re-running yields a NEW zkey and vkey. Phase 1 should be
# PSE ppot 0080 (PTAU_SOURCE=pse); phase 2 is single-party, so the keys are DEMO-ONLY: whoever ran
# setup could forge proofs (circuits/setup/README.md).
source "$(dirname "${BASH_SOURCE[0]}")/setup-lib.sh"

[ $# -eq 2 ] || die "usage: setup.sh <circuit.circom> <name>"
CIRCUIT="$1"; NAME="$2"
valid_name "$NAME"
case "$CIRCUIT" in /*) ;; *) [ -f "$CIRCUIT" ] || CIRCUIT="$REPO_ROOT/$CIRCUIT" ;; esac
[ -f "$CIRCUIT" ] || die "circuit not found: $1"
CIRCUIT="$(cd "$(dirname "$CIRCUIT")" && pwd)/$(basename "$CIRCUIT")"
BASE="$(basename "$CIRCUIT" .circom)"
OUT="$BUILD_DIR/$NAME"

command -v circom >/dev/null || die "circom not found (cargo install --git https://github.com/iden3/circom.git --tag v2.2.3 circom)"
[ -d "$NODE_MODULES/circomlib" ] || die "circomlib missing: run npm ci at the repo root"

# --- 1. compile --------------------------------------------------------------------------------
rm -rf "$OUT"; mkdir -p "$OUT" "$SETUP_OUT"
log "compiling $CIRCUIT at --O2 (circom $(circom_version))"
# Circuits include circomlib relative to their own file ("../node_modules/circomlib/..." from
# circuits/); -l adds the root node_modules and the repo root as fallbacks for other spellings.
circom "$CIRCUIT" --r1cs --wasm --sym --O2 -l "$NODE_MODULES" -l "$REPO_ROOT" -o "$OUT" >&2
if [ "$BASE" != "$NAME" ]; then
  mv "$OUT/$BASE.r1cs" "$OUT/$NAME.r1cs"
  mv "$OUT/$BASE.sym" "$OUT/$NAME.sym"
fi
cp "$OUT/${BASE}_js/$BASE.wasm" "$OUT/$NAME.wasm"

INFO="$(snarkjs_out r1cs info "$OUT/$NAME.r1cs")"
count() { printf '%s\n' "$INFO" | grep -E "# of $1:" | grep -oE '[0-9]+$'; }
N_CONSTRAINTS="$(count Constraints)"; N_PUB_IN="$(count 'Public Inputs')"; N_OUT="$(count Outputs)"
[ -n "$N_CONSTRAINTS" ] && [ -n "$N_PUB_IN" ] && [ -n "$N_OUT" ] || die "could not parse r1cs info: $INFO"
log "$N_CONSTRAINTS constraints, $N_PUB_IN public inputs, $N_OUT outputs"

# snarkjs groth16 setup needs 2^power >= constraints + public inputs + outputs + 1.
NEED=1; while [ $((1 << NEED)) -lt $((N_CONSTRAINTS + N_PUB_IN + N_OUT + 1)) ]; do NEED=$((NEED + 1)); done
[ "$NEED" -lt 8 ] && NEED=8

# --- 2. phase 1 --------------------------------------------------------------------------------
if [ -n "${PTAU:-}" ]; then
  [ -f "$PTAU" ] || die "PTAU=$PTAU not found"
  log "using PTAU=$PTAU (externally supplied)"
else
  POWER="${PTAU_POWER:-15}"
  if [ "$POWER" -lt "$NEED" ]; then log "circuit needs power $NEED > PTAU_POWER=$POWER; using $NEED"; POWER="$NEED"; fi
  PTAU="$(PTAU_POWER="$POWER" bash "$CIRCUITS_DIR/scripts/ptau.sh" | tail -n1)"
  [ -f "$PTAU" ] || die "ptau.sh did not produce a file"
fi
case "$(basename "$PTAU")" in *DEV-ONLY*) log "WARNING: phase 1 is DEV-ONLY ($(basename "$PTAU")); keys are not production-grade" ;; esac

# --- 3. phase 2 --------------------------------------------------------------------------------
Z="$OUT/$NAME"
log "groth16 setup"
snarkjs groth16 setup "$OUT/$NAME.r1cs" "$PTAU" "${Z}_0000.zkey"
log "phase-2 contribution (entropy: /dev/urandom on stdin)"
snarkjs_contribute zkey contribute "${Z}_0000.zkey" "${Z}_0001.zkey" --name="${NAME} phase-2 contribution 1"
# BEACON_HASH lets a release use public randomness fixed in advance (e.g. a future block hash);
# by default it is fresh urandom. Either way it is recorded in the manifest.
BEACON="${BEACON_HASH:-$(urandom_hex 32)}"
[[ "$BEACON" =~ ^[0-9a-fA-F]{2,128}$ ]] || die "BEACON_HASH must be hex"
log "phase-2 beacon $BEACON (2^10 iterations)"
snarkjs zkey beacon "${Z}_0001.zkey" "${Z}.zkey" "$BEACON" 10 --name="${NAME} final beacon"
rm -f "${Z}_0000.zkey" "${Z}_0001.zkey"

log "zkey verify against r1cs + ptau"
VERIFY_LOG="$(snarkjs_out zkey verify "$OUT/$NAME.r1cs" "$PTAU" "${Z}.zkey" 2>&1)" || { printf '%s\n' "$VERIFY_LOG" >&2; die "zkey verify failed"; }
printf '%s\n' "$VERIFY_LOG" >&2
printf '%s\n' "$VERIFY_LOG" | grep -q "ZKey Ok!" || die "zkey verify did not report ZKey Ok!"

# --- 4. keys + manifest ------------------------------------------------------------------------
snarkjs zkey export verificationkey "${Z}.zkey" "$OUT/verification_key.json"
cp "$OUT/verification_key.json" "$SETUP_OUT/$NAME.verification_key.json"

PTAU_INFO="$PTAU.info.json"
[ -f "$PTAU_INFO" ] || PTAU_INFO=""
CIRCUIT_REL="$(realpath --relative-to="$REPO_ROOT" "$CIRCUIT")"
node "$CIRCUITS_DIR/scripts/setup-manifest.js" \
  --name "$NAME" --circuit "$CIRCUIT_REL" \
  --circom "$(circom_version)" --snarkjs "$(snarkjs_version)" \
  --r1cs "$OUT/$NAME.r1cs" --sym "$OUT/$NAME.sym" --wasm "$OUT/$NAME.wasm" --zkey "${Z}.zkey" \
  --vkey "$SETUP_OUT/$NAME.verification_key.json" \
  --ptau "$PTAU" --ptau-info "$PTAU_INFO" \
  --constraints "$N_CONSTRAINTS" --n-pub-in "$N_PUB_IN" --n-out "$N_OUT" \
  --beacon "$BEACON" > "$SETUP_OUT/$NAME.manifest.json"

log "done: $SETUP_OUT/$NAME.verification_key.json, $SETUP_OUT/$NAME.manifest.json"
log "proving pair: $OUT/$NAME.wasm, $OUT/$NAME.zkey (commit with: cp them to $SETUP_OUT/, see ARTIFACTS.md)"
echo "$SETUP_OUT/$NAME.manifest.json"
