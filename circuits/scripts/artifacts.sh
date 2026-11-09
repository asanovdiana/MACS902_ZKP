#!/usr/bin/env bash
# Committed proving artefacts (decision D7, circuits/setup/ARTIFACTS.md):
#
#   circuits/scripts/artifacts.sh check   <name>    # e.g. integrated_access_v3
#   circuits/scripts/artifacts.sh install <name>
#
# check    $SETUP_OUT/<name>.zkey, <name>.wasm, <name>.verification_key.json and <name>.manifest.json
#          exist; the sha256 of zkey / wasm / vkey equal zkey_sha256 / wasm_sha256 /
#          verification_key_sha256 in the manifest; and the verification key exported from the zkey
#          (snarkjs zkey export verificationkey) equals the committed vkey.
#          Exit 0 ok, 1 mismatch, 2 usage error or missing file. Never modifies anything.
# install  check, then copy them to $BUILD_DIR/<name>/<name>.{zkey,wasm} + verification_key.json,
#          the layout setup.sh leaves and prove.sh expects. Copies nothing if check fails.
#
# Never re-runs setup: a new setup makes a new key that nothing pinned verifies under.
source "$(dirname "${BASH_SOURCE[0]}")/setup-lib.sh"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mfield() { node -e 'const m=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const v=m[process.argv[2]];if(typeof v!=="string")process.exit(1);process.stdout.write(v)' "$1" "$2"; }
fail() { log "FAIL: $*"; exit 1; }

cmd_check() {
  local name="$1" z w v m f want got pair
  z="$SETUP_OUT/$name.zkey"; w="$SETUP_OUT/$name.wasm"
  v="$SETUP_OUT/$name.verification_key.json"; m="$SETUP_OUT/$name.manifest.json"
  for f in "$z" "$w" "$v" "$m"; do [ -f "$f" ] || die "missing $f"; done

  for pair in "zkey_sha256:$z" "wasm_sha256:$w" "verification_key_sha256:$v"; do
    f="${pair#*:}"; want="$(mfield "$m" "${pair%%:*}")" || die "manifest $m has no ${pair%%:*}"
    got="$(sha256_of "$f")"
    [ "$got" = "$want" ] || fail "$(basename "$f") sha256 $got != manifest ${pair%%:*} $want"
    log "ok  $(basename "$f") sha256 = manifest ${pair%%:*} ($got)"
  done

  snarkjs zkey export verificationkey "$z" "$TMP/vk.json" || fail "snarkjs could not export a verification key from $z"
  node -e '
    const fs = require("fs"); const { isDeepStrictEqual } = require("util");
    const a = JSON.parse(fs.readFileSync(process.argv[1], "utf8")), b = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
    process.exit(isDeepStrictEqual(a, b) ? 0 : 1);' "$TMP/vk.json" "$v" ||
    fail "the verification key exported from $(basename "$z") is not $(basename "$v")"
  log "ok  vkey exported from $(basename "$z") equals $(basename "$v")"
}

cmd_install() {
  local name="$1" out="$BUILD_DIR/$1"
  cmd_check "$name"
  mkdir -p "$out"
  cp "$SETUP_OUT/$name.zkey" "$out/$name.zkey"
  cp "$SETUP_OUT/$name.wasm" "$out/$name.wasm"
  cp "$SETUP_OUT/$name.verification_key.json" "$out/verification_key.json"
  log "installed: $out/$name.{zkey,wasm}, $out/verification_key.json"
  echo "$out"
}

[ $# -eq 2 ] || usage
sub="$1"; NAME="$2"
case "$sub" in
  check|install) valid_name "$NAME"; "cmd_$sub" "$NAME" ;;
  *) usage ;;
esac
