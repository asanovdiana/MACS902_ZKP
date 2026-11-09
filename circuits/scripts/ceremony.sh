#!/usr/bin/env bash
# Multi-party Groth16 phase 2 ("trusted setup ceremony"). Each teammate adds one contribution on
# their own machine, in turn; the final key is sound if ANY ONE of them destroyed their randomness.
# Step-by-step guide: circuits/ceremony/README.md. Run from the repo root.
#
#   circuits/scripts/ceremony.sh init       <circuit.circom> <name>           # coordinator, once
#   circuits/scripts/ceremony.sh contribute <name> <in.zkey> "<participant>"  # each teammate, in turn
#   circuits/scripts/ceremony.sh verify     <name> <zkey>                     # anyone, any time
#   circuits/scripts/ceremony.sh finalize   <name> <zkey> [beacon-hex]        # coordinator, after the last
#   circuits/scripts/ceremony.sh install    <name>                            # copy into circuits/setup/
#
# Files live in $CEREMONY_DIR/<name>/ (default circuits/ceremony/<name>/):
#   transcript.json                                committed: circuit/r1cs/ptau hashes + the chain
#   <name>.verification_key.json, .manifest.json   committed after finalize
#   <name>_0000.zkey ... <name>_final.zkey         NOT committed (gitignored); passed between
#                                                  teammates out of band together with transcript.json
#   build/                                         compiled circuit (r1cs, sym, wasm), rebuilt per machine
#
# Entropy: 64 bytes of /dev/urandom per contribution, fed to snarkjs on stdin (never argv, never
# logged, never in the transcript); snarkjs mixes in its own crypto.randomBytes. On a terminal you
# may also type extra text (hidden).
# Environment: PTAU=<file> (phase-1 file; default: the transcript's file in PTAU_DIR, ~/zkp-cache/ptau);
# PTAU_SOURCE for init (default pse: PSE ppot 0080, fail closed); CEREMONY_MIN_CONTRIBUTIONS (can
# only raise the floor of 2); BEACON_SOURCE (free text, recorded); CEREMONY_ENTROPY_FILE (tests only);
# CEREMONY_NO_PROMPT=1 (no extra-entropy prompt); BUILD_DIR, SETUP_OUT as in setup.sh.
source "$(dirname "${BASH_SOURCE[0]}")/setup-lib.sh"

CEREMONY_DIR="${CEREMONY_DIR:-$CIRCUITS_DIR/ceremony}"
MIN_CONTRIB="${CEREMONY_MIN_CONTRIBUTIONS:-2}"
[[ "$MIN_CONTRIB" =~ ^[0-9]+$ ]] || die "CEREMONY_MIN_CONTRIBUTIONS must be a number"
[ "$MIN_CONTRIB" -ge 2 ] || MIN_CONTRIB=2   # one contribution is the single-party setup again
BEACON_EXP=10
tjs() { node "$CIRCUITS_DIR/scripts/ceremony-transcript.js" "$@"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

cdir() { echo "$CEREMONY_DIR/$1"; }
transcript() { echo "$(cdir "$1")/transcript.json"; }
field() { tjs field --transcript "$(transcript "$1")" --key "$2"; }
need_transcript() { [ -f "$(transcript "$1")" ] || die "no ceremony '$1' (missing $(transcript "$1")); run init or copy the transcript you received"; }

# Compile <circuit> into <outdir> as <name>.{r1cs,sym,wasm}, with exactly setup.sh's flags.
compile_into() { # circuit_abs name outdir
  local circuit="$1" name="$2" out="$3" base
  base="$(basename "$circuit" .circom)"
  command -v circom >/dev/null || die "circom not found (cargo install --git https://github.com/iden3/circom.git --tag v2.2.3 circom)"
  [ -d "$NODE_MODULES/circomlib" ] || die "circomlib missing: run npm ci at the repo root"
  rm -rf "$out"; mkdir -p "$out"
  log "compiling $(realpath --relative-to="$REPO_ROOT" "$circuit") at --O2 (circom $(circom_version))"
  circom "$circuit" --r1cs --wasm --sym --O2 -l "$NODE_MODULES" -l "$REPO_ROOT" -o "$out" >&2
  if [ "$base" != "$name" ]; then mv "$out/$base.r1cs" "$out/$name.r1cs"; mv "$out/$base.sym" "$out/$name.sym"; fi
  cp "$out/${base}_js/$base.wasm" "$out/$name.wasm"
  rm -rf "$out/${base}_js"
}

# Make sure this machine has the circuit build the transcript was made for (reproducible compile).
ensure_build() { # name
  local name="$1" b want
  b="$(cdir "$name")/build"; want="$(field "$name" r1cs_sha256)"
  if [ -f "$b/$name.r1cs" ] && [ "$(sha256_of "$b/$name.r1cs")" = "$want" ] && [ -f "$b/$name.wasm" ]; then return; fi
  compile_into "$REPO_ROOT/$(field "$name" circuit)" "$name" "$b"
  [ "$(sha256_of "$b/$name.r1cs")" = "$want" ] ||
    die "r1cs sha256 $(sha256_of "$b/$name.r1cs") != transcript $want: check out the ceremony's commit and use circom $(field "$name" circom_version)"
}

# Path of the phase-1 file the transcript names, checked by blake2b.
locate_ptau() { # name
  local name="$1" file want p
  file="$(field "$name" ptau.file)"; want="$(field "$name" ptau.blake2b)"
  p="${PTAU:-$PTAU_DIR/$file}"
  [ -f "$p" ] || die "phase-1 file $file not found at $p (PTAU_SOURCE=pse circuits/scripts/ptau.sh fetches it; or set PTAU=<path>)"
  [ "$(blake2b_of "$p")" = "$want" ] || die "ptau $p blake2b does not match the transcript ($want)"
  echo "$p"
}

# snarkjs zkey verify against r1cs + ptau, then the transcript chain check. Extra args go to the
# transcript check. Prints the check result (JSON) on stdout.
verify_zkey() { # name zkey [--require-latest 1] ...
  local name="$1" zkey="$2"; shift 2
  local r1cs ptau vlog="$TMP/verify.log"
  r1cs="$(cdir "$name")/build/$name.r1cs"
  [ -f "$zkey" ] || die "zkey not found: $zkey"
  ptau="$(locate_ptau "$name")"
  log "snarkjs zkey verify $(basename "$zkey") against r1cs + $(basename "$ptau")"
  if ! snarkjs_out zkey verify "$r1cs" "$ptau" "$zkey" > "$vlog" 2>&1 || ! grep -q "ZKey Ok!" "$vlog"; then
    cat "$vlog" >&2
    die "snarkjs zkey verify FAILED for $zkey"
  fi
  cat "$vlog" >&2
  tjs check --transcript "$(transcript "$name")" --zkey "$zkey" --verify-log "$vlog" "$@" ||
    die "transcript chain check FAILED for $zkey"
}

entropy_hex() {
  local src="${CEREMONY_ENTROPY_FILE:-/dev/urandom}" hex extra=""
  hex="$(head -c 64 "$src" | od -An -tx1 | tr -d ' \n')"
  [ "${#hex}" -eq 128 ] || die "could not read 64 bytes of entropy from $src"
  if [ -t 0 ] && [ "${CEREMONY_NO_PROMPT:-0}" != "1" ]; then
    read -rs -p "Optional extra entropy: type random text (hidden), Enter to skip: " extra < /dev/tty || true
    echo >&2
    [ -z "$extra" ] || hex="$hex$(printf '%s' "$extra" | sha256sum | cut -d' ' -f1)"
  fi
  printf '%s' "$hex"
}

print_hash() { # label hash
  log "================================================================"
  log "$1"
  log "  ${2:0:32}"; log "  ${2:32:32}"; log "  ${2:64:32}"; log "  ${2:96:32}"
  log "================================================================"
}

# ---------------------------------------------------------------------------------------------
cmd_init() {
  [ $# -eq 2 ] || usage
  local circuit="$1" name="$2" cd b info nconst npub nout need power ptau slog="$TMP/setup.log"
  valid_name "$name"
  case "$circuit" in /*) ;; *) [ -f "$circuit" ] || circuit="$REPO_ROOT/$circuit" ;; esac
  [ -f "$circuit" ] || die "circuit not found: $1"
  circuit="$(cd "$(dirname "$circuit")" && pwd)/$(basename "$circuit")"
  cd="$(cdir "$name")"; b="$cd/build"
  if [ -f "$cd/transcript.json" ]; then
    [ "${CEREMONY_FORCE:-0}" = "1" ] || die "ceremony '$name' already exists ($cd/transcript.json); CEREMONY_FORCE=1 starts over"
    rm -f "$cd"/*.zkey "$cd/transcript.json" "$cd/$name.verification_key.json" "$cd/$name.manifest.json"
  fi
  mkdir -p "$cd"
  compile_into "$circuit" "$name" "$b"

  info="$(snarkjs_out r1cs info "$b/$name.r1cs")"
  count() { printf '%s\n' "$info" | grep -E "# of $1:" | grep -oE '[0-9]+$'; }
  nconst="$(count Constraints)"; npub="$(count 'Public Inputs')"; nout="$(count Outputs)"
  [ -n "$nconst" ] && [ -n "$npub" ] && [ -n "$nout" ] || die "could not parse r1cs info: $info"
  log "$nconst constraints, $npub public inputs, $nout outputs"
  need=1; while [ $((1 << need)) -lt $((nconst + npub + nout + 1)) ]; do need=$((need + 1)); done
  [ "$need" -lt 8 ] && need=8

  if [ -n "${PTAU:-}" ]; then
    [ -f "$PTAU" ] || die "PTAU=$PTAU not found"
    ptau="$PTAU"
    log "using PTAU=$PTAU (externally supplied)"
  else
    power="${PTAU_POWER:-15}"; [ "$power" -ge "$need" ] || power="$need"
    ptau="$(PTAU_SOURCE="${PTAU_SOURCE:-pse}" PTAU_POWER="$power" bash "$CIRCUITS_DIR/scripts/ptau.sh" | tail -n1)"
  fi
  [ -f "$ptau" ] || die "no phase-1 file"
  case "$(basename "$ptau")" in *DEV-ONLY*) log "WARNING: phase 1 is DEV-ONLY ($(basename "$ptau")); use PTAU_SOURCE=pse for a real ceremony" ;; esac

  log "groth16 setup (deterministic: anyone can reproduce ${name}_0000.zkey from the r1cs + ptau)"
  snarkjs_out groth16 setup "$b/$name.r1cs" "$ptau" "$cd/${name}_0000.zkey" > "$slog" 2>&1 || { cat "$slog" >&2; die "groth16 setup failed"; }
  cat "$slog" >&2
  local infoargs=()
  if [ -f "$ptau.info.json" ]; then infoargs=(--ptau-info "$ptau.info.json"); else infoargs=(--ptau "$ptau" --ptau-blake2b "$(blake2b_of "$ptau")"); fi
  tjs init --out "$cd/transcript.json" --name "$name" \
    --circuit "$(realpath --relative-to="$REPO_ROOT" "$circuit")" --circuit-file "$circuit" \
    --circom "$(circom_version)" --snarkjs "$(snarkjs_version)" \
    --constraints "$nconst" --n-pub-in "$npub" --n-out "$nout" \
    --r1cs "$b/$name.r1cs" "${infoargs[@]}" \
    --setup-log "$slog" --zkey "$cd/${name}_0000.zkey"
  log "ceremony '$name' initialised. Contributor 1 runs contribute on ${name}_0000.zkey."
  echo "$cd/${name}_0000.zkey"
}

cmd_contribute() {
  [ $# -eq 3 ] || usage
  local name="$1" in="$2" who="$3" cd idx out ent hash clog="$TMP/contribute.log"
  valid_name "$name"; need_transcript "$name"
  [[ "$who" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._@\'-]{0,63}$ ]] || die "participant name must match [A-Za-z0-9][A-Za-z0-9 ._@'-]{0,63}"
  cd="$(cdir "$name")"
  ensure_build "$name"
  log "step 1/3: verify the zkey you received before building on it"
  verify_zkey "$name" "$in" --require-latest 1 --require-open 1 > "$TMP/check.json"
  idx="$(printf '%04d' $(( $(tjs field --transcript "$(transcript "$name")" --key contributions.length) + 1 )))"
  out="$cd/${name}_${idx}.zkey"
  [ ! -f "$out" ] || die "$out already exists (someone already contributed at this position: refusing to fork)"

  log "step 2/3: contribution #$((10#$idx)) by \"$who\" (entropy: /dev/urandom on stdin)"
  ent="$(entropy_hex)"
  # printf is a bash builtin: the entropy reaches snarkjs through a pipe, never through argv.
  if ! printf '%s\n' "$ent" | snarkjs_out zkey contribute "$in" "$out" --name="$who" > "$clog" 2>&1; then
    ent=""; cat "$clog" >&2; rm -f "$out"; die "snarkjs zkey contribute failed"
  fi
  ent=""; unset ent
  cat "$clog" >&2; echo >&2
  hash="$(tjs hash-from-log --log "$clog")"
  tjs append --transcript "$(transcript "$name")" --participant "$who" --hash "$hash" --zkey "$out" --prev-zkey "$in" ||
    { rm -f "$out"; die "could not record the contribution"; }

  log "step 3/3: done. Publish this contribution hash in the team channel BEFORE passing the zkey on:"
  print_hash "contribution #$((10#$idx)) \"$who\"" "$hash"
  log "Pass $(basename "$out") and $(transcript "$name") to the next participant."
  echo "$out"
}

cmd_verify() {
  [ $# -eq 2 ] || usage
  local name="$1" zkey="$2" cd res
  valid_name "$name"; need_transcript "$name"
  cd="$(cdir "$name")"
  ensure_build "$name"
  res="$(verify_zkey "$name" "$zkey")"
  log "OK: $(basename "$zkey") verifies; chain matches the transcript:"
  if tjs summary --result "$res" && [ -f "$cd/$name.verification_key.json" ]; then
    snarkjs zkey export verificationkey "$zkey" "$TMP/vk.json"
    tjs same-json --a "$TMP/vk.json" --b "$cd/$name.verification_key.json" ||
      die "$cd/$name.verification_key.json is not the key of $zkey"
    log "ceremony verification key matches the final zkey"
  fi
  echo "$res"
}

cmd_finalize() {
  [ $# -eq 2 ] || [ $# -eq 3 ] || usage
  local name="$1" zkey="$2" beacon="${3:-}" cd n public source out blog="$TMP/beacon.log" chash ptau b
  valid_name "$name"; need_transcript "$name"
  cd="$(cdir "$name")"; b="$cd/build"
  n="$(field "$name" contributions.length)"
  [ "$n" -ge "$MIN_CONTRIB" ] || die "only $n contribution(s); need at least $MIN_CONTRIB (one contribution is the single-party setup again)"
  ensure_build "$name"
  verify_zkey "$name" "$zkey" --require-latest 1 --require-open 1 > /dev/null

  if [ -n "$beacon" ]; then
    [[ "$beacon" =~ ^([0-9a-fA-F]{2}){16,64}$ ]] || die "beacon must be 32..128 hex characters (even length)"
    public=1; source="${BEACON_SOURCE:-public value given on the command line (BEACON_SOURCE not set)}"
  else
    beacon="$(urandom_hex 32)"; public=0; source="local /dev/urandom (not publicly verifiable)"
    log "WARNING: no beacon given; using local randomness. For a real ceremony pass a public value"
    log "         announced in advance (a future drand round or Bitcoin block hash)."
  fi
  out="$cd/${name}_final.zkey"
  log "beacon $beacon (2^$BEACON_EXP iterations), source: $source"
  snarkjs_out zkey beacon "$zkey" "$out" "$beacon" "$BEACON_EXP" --name="$name final beacon" > "$blog" 2>&1 ||
    { cat "$blog" >&2; rm -f "$out"; die "snarkjs zkey beacon failed"; }
  cat "$blog" >&2
  chash="$(tjs hash-from-log --log "$blog")"
  tjs set-beacon --transcript "$(transcript "$name")" --label "$name final beacon" --hash "$beacon" \
    --iterations-exp "$BEACON_EXP" --source "$source" --public "$public" --contribution-hash "$chash" \
    --zkey "$out" --prev-zkey "$zkey"

  log "final verify"
  verify_zkey "$name" "$out" --require-final 1 > /dev/null
  snarkjs zkey export verificationkey "$out" "$cd/$name.verification_key.json"

  ptau="$(locate_ptau "$name")"
  tjs ptau-info --transcript "$(transcript "$name")" > "$TMP/ptau.info.json"
  node "$CIRCUITS_DIR/scripts/setup-manifest.js" \
    --name "$name" --circuit "$(field "$name" circuit)" \
    --circom "$(field "$name" circom_version)" --snarkjs "$(field "$name" snarkjs_version)" \
    --r1cs "$b/$name.r1cs" --sym "$b/$name.sym" --wasm "$b/$name.wasm" --zkey "$out" \
    --vkey "$cd/$name.verification_key.json" \
    --ptau "$ptau" --ptau-info "$TMP/ptau.info.json" \
    --constraints "$(field "$name" constraints)" --n-pub-in "$(field "$name" n_pub_in)" --n-out "$(field "$name" n_out)" \
    --beacon "$beacon" > "$TMP/manifest.json"
  tjs manifest-patch --manifest "$TMP/manifest.json" --transcript "$(transcript "$name")" --repo-root "$REPO_ROOT" > "$cd/$name.manifest.json"

  print_hash "beacon contribution hash" "$chash"
  log "done: $cd/$name.verification_key.json, $cd/$name.manifest.json, $(basename "$out")"
  log "next: circuits/scripts/ceremony.sh install $name, then regenerate fixtures (circuits/ceremony/README.md)"
  echo "$cd/$name.manifest.json"
}

# Copy the finalized ceremony into the committed layout (circuits/setup/<name>.{zkey,wasm,
# verification_key.json,manifest.json}) and build/<name>/, after hash checks; then
# artifacts.sh check (exported vkey == committed vkey). Copies nothing if a hash check fails.
cmd_install() {
  [ $# -eq 1 ] || usage
  local name="$1" cd m z v t b
  valid_name "$name"; need_transcript "$name"
  cd="$(cdir "$name")"; m="$cd/$name.manifest.json"; z="$cd/${name}_final.zkey"
  v="$cd/$name.verification_key.json"; t="$(transcript "$name")"; b="$cd/build"
  [ -f "$m" ] && [ -f "$z" ] && [ -f "$v" ] || die "ceremony '$name' is not finalized (missing manifest, vkey or ${name}_final.zkey)"
  mf() { tjs field --file "$m" --key "$1"; }
  ensure_build "$name"
  [ "$(sha256_of "$z")" = "$(mf zkey_sha256)" ] || die "$z does not match zkey_sha256 in $m"
  [ "$(sha256_of "$z")" = "$(field "$name" beacon.zkey_sha256)" ] || die "$z is not the finalized zkey of the transcript"
  [ "$(sha256_of "$v")" = "$(mf verification_key_sha256)" ] || die "$v does not match verification_key_sha256 in $m"
  [ "$(sha256_of "$t")" = "$(mf phase2.transcript_sha256)" ] || die "$t changed after finalize (transcript_sha256 in $m)"
  [ "$(sha256_of "$b/$name.r1cs")" = "$(mf r1cs_sha256)" ] || die "r1cs does not match r1cs_sha256 in $m"
  [ "$(sha256_of "$b/$name.wasm")" = "$(mf wasm_sha256)" ] || die "wasm does not match wasm_sha256 in $m (different circom or tree?)"
  mkdir -p "$BUILD_DIR/$name" "$SETUP_OUT"
  cp "$z" "$SETUP_OUT/$name.zkey"
  cp "$b/$name.wasm" "$SETUP_OUT/$name.wasm"
  cp "$v" "$SETUP_OUT/$name.verification_key.json"
  cp "$m" "$SETUP_OUT/$name.manifest.json"
  cp "$z" "$BUILD_DIR/$name/$name.zkey"
  cp "$b/$name.wasm" "$b/$name.r1cs" "$b/$name.sym" "$BUILD_DIR/$name/"
  cp "$v" "$BUILD_DIR/$name/verification_key.json"
  bash "$CIRCUITS_DIR/scripts/artifacts.sh" check "$name" >&2 || die "artifacts.sh check $name failed after install"
  log "installed: $SETUP_OUT/$name.{zkey,wasm,verification_key.json,manifest.json} and $BUILD_DIR/$name/"
  echo "$SETUP_OUT/$name.manifest.json"
}

[ $# -ge 1 ] || usage
sub="$1"; shift
case "$sub" in
  init) cmd_init "$@" ;;
  contribute) cmd_contribute "$@" ;;
  verify) cmd_verify "$@" ;;
  finalize) cmd_finalize "$@" ;;
  install) cmd_install "$@" ;;
  -h|--help|help) usage ;;
  *) die "unknown subcommand '$sub'" ;;
esac
