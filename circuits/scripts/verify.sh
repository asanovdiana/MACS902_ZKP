#!/usr/bin/env bash
# Verify a Groth16 proof:
#
#   circuits/scripts/verify.sh <name | path/to/verification_key.json> <proof.json> <public.json>
#
# <name> resolves to $SETUP_OUT/<name>.verification_key.json (the committed key).
# Exit 0 = valid, 1 = invalid (including malformed proof or non-canonical signals), 2 = usage error.
source "$(dirname "${BASH_SOURCE[0]}")/setup-lib.sh"

[ $# -eq 3 ] || die "usage: verify.sh <name|vkey.json> <proof.json> <public.json>"
if [ -f "$1" ]; then VKEY="$1"; else valid_name "$1"; VKEY="$SETUP_OUT/$1.verification_key.json"; fi
[ -f "$VKEY" ] || die "verification key not found: $VKEY"
[ -f "$2" ] || die "proof not found: $2"
[ -f "$3" ] || die "public signals not found: $3"

exec node "$CIRCUITS_DIR/scripts/verify.js" "$VKEY" "$3" "$2"
