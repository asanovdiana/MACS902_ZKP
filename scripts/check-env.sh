#!/usr/bin/env bash
# Toolchain check for the root Makefile (`make check-env`, `make check-env-demo`).
#
#   scripts/check-env.sh          node >= 20 and circom == 2.2.3 required; docker reported only
#   scripts/check-env.sh --demo   node >= 20 and docker (with the compose plugin) required; circom
#                                 reported only (the demo compiles with p3's circom2 WASM build)
#
# circom is looked up on PATH with ~/.cargo/bin prepended, where
# `cargo install --git https://github.com/iden3/circom.git --tag v2.2.3 circom` puts it
# (the same lookup circuits/test/setup.js and circuits/scripts/setup-lib.sh do).
set -uo pipefail

NODE_MIN=20
CIRCOM_REQUIRED=2.2.3
need_docker=0
[ "${1:-}" = "--demo" ] && need_docker=1

case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) PATH="$HOME/.cargo/bin:$PATH" ;; esac

fail=0
ok() { printf 'ok    %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*" >&2; fail=1; }
info() { printf 'info  %s\n' "$*"; }

if command -v node >/dev/null 2>&1; then
  v="$(node -p 'process.versions.node')"
  if [ "${v%%.*}" -ge "$NODE_MIN" ]; then ok "node $v (>= $NODE_MIN)"; else bad "node $v, need >= $NODE_MIN"; fi
else
  bad "node not found, need >= $NODE_MIN"
fi

if command -v circom >/dev/null 2>&1; then
  v="$(circom --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [ "$v" = "$CIRCOM_REQUIRED" ]; then ok "circom $v"
  elif [ "$need_docker" = 1 ]; then info "circom ${v:-unknown} (not $CIRCOM_REQUIRED; the demo does not use it)"
  else bad "circom ${v:-unknown}, need exactly $CIRCOM_REQUIRED (cargo install --git https://github.com/iden3/circom.git --tag v$CIRCOM_REQUIRED circom)"; fi
elif [ "$need_docker" = 1 ]; then
  info "circom not found (the demo does not need it; the test suites do)"
else
  bad "circom not found, need $CIRCOM_REQUIRED (cargo install --git https://github.com/iden3/circom.git --tag v$CIRCOM_REQUIRED circom)"
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  ok "docker + compose ($(docker compose version --short 2>/dev/null))"
elif [ "$need_docker" = 1 ]; then
  bad "docker with the compose plugin not found (needed by make demo)"
else
  info "docker with the compose plugin not found (only make demo needs it)"
fi

exit "$fail"
