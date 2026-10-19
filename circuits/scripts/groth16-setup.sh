#!/usr/bin/env bash
# Compiles a circuit and runs the Groth16 setup for it.
#
# Usage: scripts/groth16-setup.sh <circuit-name> [ptau-power]
#   circuit-name  circuit file without .circom, e.g. test_conservation
#   ptau-power    log2 of the Powers of Tau size; must cover the circuit's constraint count.
#                 Without it, the script only compiles and prints the circuit's size.
#
# Outputs, in build/:
#   <name>.r1cs, <name>_js/<name>.wasm   compiled circuit and witness generator
#   <name>_final.zkey                     proving key
#   <name>_vkey.json                      verification key
#
# Powers of Tau: by default this creates a throwaway, single-contributor file for development
# and tests. It is NOT a trusted setup. To use a file from a public ceremony instead (architecture
# decision D3, still open), set PTAU=/path/to/file.ptau.
#
# Large circuits: snarkjs runs on Node, whose default memory limit (~2 GB) is too small for the
# depth-10 conservation circuit. Raise it with e.g. NODE_OPTIONS=--max-old-space-size=8192.
set -euo pipefail

name="$1"
power="${2:-}"

cd "$(dirname "$0")/.."
snarkjs="node_modules/.bin/snarkjs"
build="build"
mkdir -p "$build"

entropy() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

echo "== Compiling $name.circom"
# --O2 removes linear constraints, roughly halving the size of Poseidon-heavy circuits.
# circom prints the circuit's size (constraints, inputs) as it compiles.
circom "$name.circom" --r1cs --wasm --O2 -o "$build"

if [ -z "$power" ]; then
  exit 0
fi

if [ -n "${PTAU:-}" ]; then
  ptau="$PTAU"
  if [ ! -f "$ptau" ]; then
    echo "PTAU file not found: $ptau" >&2
    exit 1
  fi
else
  ptau="$build/ptau/dev_$power.ptau"
  if [ ! -f "$ptau" ]; then
    echo "== Creating a development Powers of Tau file (2^$power). Not for production."
    mkdir -p "$build/ptau"
    "$snarkjs" powersoftau new bn128 "$power" "$build/ptau/dev_${power}_0000.ptau"
    "$snarkjs" powersoftau contribute "$build/ptau/dev_${power}_0000.ptau" "$build/ptau/dev_${power}_0001.ptau" \
      --name="dev" -e="$(entropy)"
    "$snarkjs" powersoftau prepare phase2 "$build/ptau/dev_${power}_0001.ptau" "$ptau"
    rm "$build/ptau/dev_${power}_0000.ptau" "$build/ptau/dev_${power}_0001.ptau"
  fi
fi

echo "== Groth16 setup for $name"
"$snarkjs" groth16 setup "$build/$name.r1cs" "$ptau" "$build/${name}_0000.zkey"
"$snarkjs" zkey contribute "$build/${name}_0000.zkey" "$build/${name}_final.zkey" --name="dev" -e="$(entropy)"
rm "$build/${name}_0000.zkey"
"$snarkjs" zkey export verificationkey "$build/${name}_final.zkey" "$build/${name}_vkey.json"
echo "== Done: $build/${name}_final.zkey, $build/${name}_vkey.json"
