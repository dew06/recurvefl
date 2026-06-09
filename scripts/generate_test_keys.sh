#!/bin/bash
# generate_test_keys.sh — Generate test BLS12-381 keys for Preview testnet testing
#
# Outputs:
#   ../keys/proving_key.bin        — Groth16 proving key (binary)
#   ../keys/verification_key.bin   — Groth16 verification key (binary)
#   ../keys/verification_key.hex   — Verification key as hex (for Aiken datum)
#   ../keys/bls_keypair.json       — BLS12-381 signing keypair (JSON)
#
# WARNING: These keys are for TESTING ONLY. Do not use in production.
#          Production deployment requires a proper Powers of Tau MPC ceremony.
#
# Usage: bash scripts/generate_test_keys.sh [--output-dir <path>]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROVER="${ROOT_DIR}/zk-prover/target/release/zkfl-prover"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

# ── Parse arguments ───────────────────────────────────────────────────────────

OUTPUT_DIR="${ROOT_DIR}/keys"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

mkdir -p "${OUTPUT_DIR}"
echo "Output directory: ${OUTPUT_DIR}"
echo ""

# ── Check prover binary ───────────────────────────────────────────────────────

if [ ! -f "${PROVER}" ]; then
  die "Rust prover binary not found at ${PROVER}.\nBuild it first:\n  cd zk-prover && cargo build --release"
fi
ok "Prover binary found: ${PROVER}"

echo ""
warn "These keys are for TESTING ONLY. Do not use in production."
warn "Production use requires a trusted setup ceremony (Powers of Tau)."
echo ""

# ── Phase 1: Powers of Tau (development) ─────────────────────────────────────

echo "Step 1/4: Running development Powers of Tau setup..."
"${PROVER}" setup \
  --output-dir "${OUTPUT_DIR}" \
  --ceremony dev
ok "Powers of Tau complete"

# ── Phase 2: Circuit-specific setup (Groth16 key generation) ─────────────────

echo "Step 2/4: Generating Groth16 proving and verification keys..."
"${PROVER}" setup-circuit \
  --ptau-path "${OUTPUT_DIR}/ptau.bin" \
  --output-dir "${OUTPUT_DIR}"
ok "Groth16 proving key   → ${OUTPUT_DIR}/proving_key.bin"
ok "Groth16 verif. key    → ${OUTPUT_DIR}/verification_key.bin"

# ── Phase 3: Export verification key as hex ───────────────────────────────────

echo "Step 3/4: Exporting verification key as hex (for Aiken datum)..."
"${PROVER}" export-vk \
  --input "${OUTPUT_DIR}/verification_key.bin" \
  --output "${OUTPUT_DIR}/verification_key.hex"
ok "Verification key hex  → ${OUTPUT_DIR}/verification_key.hex"

# ── Phase 4: Generate BLS12-381 signing keypair ───────────────────────────────

echo "Step 4/4: Generating BLS12-381 signing keypair..."
"${PROVER}" gen-bls-keypair \
  --output "${OUTPUT_DIR}/bls_keypair.json"
ok "BLS keypair           → ${OUTPUT_DIR}/bls_keypair.json"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo -e "${GREEN} Keys generated successfully${NC}"
echo "============================================"
echo ""
echo "Files in ${OUTPUT_DIR}/:"
ls -lh "${OUTPUT_DIR}/" 2>/dev/null || true
echo ""
echo "Next steps:"
echo "  1. Copy the verification key into the Aiken contract datum:"
echo "       cat ${OUTPUT_DIR}/verification_key.hex"
echo "       # Paste into contracts/validators/round_state.ak → vk_hex"
echo ""
echo "  2. Update coordinator/.env:"
echo "       VK_PATH=${OUTPUT_DIR}/verification_key.bin"
echo "       BLS_KEYPAIR_PATH=${OUTPUT_DIR}/bls_keypair.json"
echo ""
echo "  3. Initialize on-chain registry:"
echo "       cd coordinator && npm run dev -- init --initial-model-hash <hash>"
echo ""
