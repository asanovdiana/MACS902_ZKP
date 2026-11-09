# shellcheck shell=bash
# Shared helpers for ptau.sh / setup.sh / prove.sh / verify.sh / artifacts.sh. Source it; do not run it.
#
# Layout (paths relative to the repo root; each overridable by environment, which the tests use
# to work in a scratch dir):
#   REPO_ROOT     .                               (derived from this file's location)
#   CIRCUITS_DIR  circuits/
#   BUILD_DIR     build/                          build/<name>/: r1cs, sym, wasm, zkey, vkey (gitignored)
#   SETUP_OUT     circuits/setup/                 committed: <name>.verification_key.json,
#                                                 <name>.manifest.json (+ the D7 proving pair)
#   PTAU_DIR      ~/zkp-cache/ptau                cached Powers of Tau files, shared by every
#                                                 clone/worktree of this machine (never committed)
#   NODE_MODULES  node_modules/                   the root npm package (npm ci at the repo root)
#
# Convention: stdout carries only a script's result (a path); every log line goes to stderr.
set -euo pipefail

CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CIRCUITS_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
SETUP_OUT="${SETUP_OUT:-$CIRCUITS_DIR/setup}"
PTAU_DIR="${PTAU_DIR:-$HOME/zkp-cache/ptau}"
NODE_MODULES="$REPO_ROOT/node_modules"

# circom 2.2.3 is installed by `cargo install` into ~/.cargo/bin.
case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) PATH="$HOME/.cargo/bin:$PATH" ;; esac
export PATH

log() { printf '[%s] %s\n' "$(basename "$0")" "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

SNARKJS_CLI="$NODE_MODULES/snarkjs/build/cli.cjs"
# snarkjs from the root node_modules (pinned by package-lock); its own output goes to stderr.
snarkjs() {
  [ -f "$SNARKJS_CLI" ] || die "snarkjs missing: run npm ci at the repo root"
  node "$SNARKJS_CLI" "$@" >&2
}
# Same, but stdout captured for parsing.
snarkjs_out() {
  [ -f "$SNARKJS_CLI" ] || die "snarkjs missing: run npm ci at the repo root"
  node "$SNARKJS_CLI" "$@"
}

# snarkjs's "exports" map hides package.json from require("snarkjs/package.json"); use the path.
snarkjs_version() { node -p "require(process.argv[1]).version" "$NODE_MODULES/snarkjs/package.json"; }
circom_version() { circom --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; }

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
blake2b_of() { b2sum "$1" | cut -d' ' -f1; }   # blake2b-512, the hash the snarkjs README publishes

# Bytes from the kernel CSPRNG as hex. Fed to snarkjs on stdin (never argv, never a fixed string);
# snarkjs additionally mixes in its own crypto.randomBytes.
urandom_hex() { head -c "${1:-64}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Run a snarkjs contribution command, feeding fresh entropy to its "Enter a random text" prompt.
snarkjs_contribute() { printf '%s\n' "$(urandom_hex 64)" | snarkjs "$@"; }

valid_name() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid name '$1' (use [A-Za-z0-9_-])"; }
