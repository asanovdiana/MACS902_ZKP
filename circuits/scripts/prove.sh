#!/usr/bin/env bash
# Generate a Groth16 proof with the artefacts of one setup:
#
#   circuits/scripts/prove.sh <name> <input.json> <outdir>   ->  <outdir>/proof.json, <outdir>/public.json
#
# Uses $BUILD_DIR/<name>/<name>.wasm and <name>.zkey (default build/<name>/). On a fresh clone,
# `circuits/scripts/artifacts.sh install <name>` puts the committed pair there.
#
# <input.json> holds PRIVATE inputs (secret, salt, signature, Merkle path): keep it outside the
# repo and delete it after use. The client should prefer in-process
# snarkjs.groth16.fullProve(input, wasm, zkey), which writes no input or witness file at all.
# The witness lives only in a temp dir that is deleted on exit. Exits 1, writing nothing, if the
# input does not satisfy the circuit.
source "$(dirname "${BASH_SOURCE[0]}")/setup-lib.sh"

[ $# -eq 3 ] || die "usage: prove.sh <name> <input.json> <outdir>"
NAME="$1"; INPUT="$2"; OUTDIR="$3"
valid_name "$NAME"
WASM="$BUILD_DIR/$NAME/$NAME.wasm"; ZKEY="$BUILD_DIR/$NAME/$NAME.zkey"
[ -f "$WASM" ] && [ -f "$ZKEY" ] || die "missing $WASM or $ZKEY — run circuits/scripts/artifacts.sh install $NAME (or setup.sh)"
[ -f "$INPUT" ] || die "input not found: $INPUT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

snarkjs wtns calculate "$WASM" "$INPUT" "$TMP/witness.wtns" || { log "witness generation failed (input does not satisfy the circuit?)"; exit 1; }
snarkjs groth16 prove "$ZKEY" "$TMP/witness.wtns" "$TMP/proof.json" "$TMP/public.json" || { log "proving failed"; exit 1; }

mkdir -p "$OUTDIR"
mv "$TMP/proof.json" "$OUTDIR/proof.json"
mv "$TMP/public.json" "$OUTDIR/public.json"
log "wrote $OUTDIR/proof.json and $OUTDIR/public.json"
echo "$OUTDIR"
