#!/usr/bin/env bash
# Compile the UNMODIFIED P1 circuit (integrated_access_v3) and run a DEVELOPMENT-ONLY
# Groth16 setup. P1 sources are copied into a build directory; nothing in the P1
# folder is modified. The resulting zkey is NOT a production trusted setup.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# P1 lives at the repository root (one level above p3/).
P1_DIR="${P1_DIR:-$(cd "$ROOT/.." && pwd)}"
TOOLS="$ROOT/tools/circom"
BUILD="$ROOT/integration/p1-diagnostics/build"
OUT="$ROOT/artifacts/p1-integrated-v3"
PTAU_POWER="${PTAU_POWER:-14}"

if [ ! -x "$TOOLS/node_modules/.bin/circom2" ]; then
  echo "[p1-build] installing pinned circom2 (circom 2.2.3 WASM build) + snarkjs into tools/circom"
  (cd "$TOOLS" && npm install --no-audit --no-fund)
fi
CIRCOM="$TOOLS/node_modules/.bin/circom2"
SNARKJS="$TOOLS/node_modules/.bin/snarkjs"

mkdir -p "$BUILD/src/node_modules/circomlib" "$OUT"
rm -rf "$BUILD/src/circuits"
cp -R "$P1_DIR/circuits" "$BUILD/src/circuits"
# circom's WASI sandbox cannot follow symlinks, so vendor a copy of circomlib circuits.
cp -R "$TOOLS/node_modules/circomlib/circuits" "$BUILD/src/node_modules/circomlib/"

cd "$BUILD"
echo "[p1-build] compiling integrated_access_v3.circom"
"$CIRCOM" src/circuits/integrated_access_v3.circom --r1cs --wasm --sym -o .
"$SNARKJS" r1cs info integrated_access_v3.r1cs

if [ ! -f "pot${PTAU_POWER}_final.ptau" ]; then
  echo "[p1-build] DEV-ONLY powers of tau (2^${PTAU_POWER}) — NOT the public Hermez ceremony"
  "$SNARKJS" powersoftau new bn128 "$PTAU_POWER" pot_0.ptau
  "$SNARKJS" powersoftau contribute pot_0.ptau pot_1.ptau --name="P3 dev (NOT TRUSTED)" -e="$(openssl rand -hex 32)"
  "$SNARKJS" powersoftau prepare phase2 pot_1.ptau "pot${PTAU_POWER}_final.ptau"
  rm -f pot_0.ptau pot_1.ptau
fi
if [ ! -f integrated_access_v3.zkey ] || [ integrated_access_v3.r1cs -nt integrated_access_v3.zkey ]; then
  "$SNARKJS" groth16 setup integrated_access_v3.r1cs "pot${PTAU_POWER}_final.ptau" v3_0.zkey
  "$SNARKJS" zkey contribute v3_0.zkey integrated_access_v3.zkey --name="P3 dev phase2 (NOT TRUSTED)" -e="$(openssl rand -hex 32)"
  rm -f v3_0.zkey
fi
"$SNARKJS" zkey export verificationkey integrated_access_v3.zkey verification_key.json
"$SNARKJS" zkey verify integrated_access_v3.r1cs "pot${PTAU_POWER}_final.ptau" integrated_access_v3.zkey

cp integrated_access_v3_js/integrated_access_v3.wasm integrated_access_v3.zkey verification_key.json integrated_access_v3.r1cs "$OUT/"
node "$ROOT/scripts/p1-manifest.mjs" "$P1_DIR" "$OUT"
echo "[p1-build] artifacts written to $OUT"
