#!/bin/bash
# setup_all.sh — One-shot setup: install all dependencies and build everything
# Usage: bash scripts/setup_all.sh
# Run from the zkfl-cardano root directory.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

echo "==========================================="
echo " Recursive Verifiable FL on Cardano"
echo " One-shot setup script"
echo "==========================================="
echo ""

# ── Prerequisite checks ─────────────────────────────────────────────────────

echo "Checking prerequisites..."

command -v cargo >/dev/null 2>&1 || \
  die "Rust/Cargo not found. Install with:\n  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\nthen restart your shell."

RUST_VERSION=$(rustc --version | awk '{print $2}')
ok "Rust $RUST_VERSION"

command -v python3 >/dev/null 2>&1 || \
  die "Python 3 not found. Install Python 3.10+ from https://python.org or via pyenv."

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
  die "Python 3.10+ required. Found $PYTHON_VERSION."
fi
ok "Python $PYTHON_VERSION"

command -v node >/dev/null 2>&1 || \
  die "Node.js not found. Install Node.js 20+ from https://nodejs.org or via nvm."

NODE_VERSION=$(node --version | sed 's/v//')
NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
if [ "$NODE_MAJOR" -lt 20 ]; then
  die "Node.js 20+ required. Found $NODE_VERSION."
fi
ok "Node.js $NODE_VERSION"

command -v npm >/dev/null 2>&1 || \
  die "npm not found. It should be bundled with Node.js."
ok "npm $(npm --version)"

if command -v aiken >/dev/null 2>&1; then
  ok "Aiken $(aiken --version 2>/dev/null || echo 'installed')"
else
  warn "Aiken not found. Contracts will not be compiled."
  warn "Install with: curl -L https://install.aiken-lang.org | bash"
  warn "Then restart your shell and re-run this script."
  SKIP_AIKEN=1
fi

echo ""

# ── Rust ZK prover ───────────────────────────────────────────────────────────

echo "Building Rust ZK prover (this may take 5-15 minutes on first build)..."
cd "${ROOT_DIR}/zk-prover"
cargo build --release 2>&1 | tail -5
ok "Rust ZK prover built → zk-prover/target/release/zkfl-prover"
cd "${ROOT_DIR}"

echo ""

# ── Python FL core ───────────────────────────────────────────────────────────

echo "Installing Python dependencies..."
cd "${ROOT_DIR}/fl-core"

if command -v pip3 >/dev/null 2>&1; then
  PIP=pip3
elif command -v pip >/dev/null 2>&1; then
  PIP=pip
else
  die "pip not found. Install pip: python3 -m ensurepip --upgrade"
fi

$PIP install -r requirements.txt -q
ok "Python dependencies installed"
cd "${ROOT_DIR}"

echo ""

# ── Aiken contracts ──────────────────────────────────────────────────────────

if [ -z "$SKIP_AIKEN" ]; then
  echo "Building Aiken contracts..."
  cd "${ROOT_DIR}/contracts"
  aiken build
  ok "Aiken contracts built → contracts/plutus.json"
  cd "${ROOT_DIR}"
  echo ""
fi

# ── TypeScript coordinator ───────────────────────────────────────────────────

echo "Installing TypeScript coordinator dependencies..."
cd "${ROOT_DIR}/coordinator"
npm install --silent
ok "npm packages installed"

echo "Building TypeScript coordinator..."
npm run build
ok "TypeScript coordinator built → coordinator/dist/"
cd "${ROOT_DIR}"

echo ""

# ── Environment template ─────────────────────────────────────────────────────

if [ ! -f "${ROOT_DIR}/coordinator/.env" ]; then
  if [ -f "${ROOT_DIR}/coordinator/.env.example" ]; then
    cp "${ROOT_DIR}/coordinator/.env.example" "${ROOT_DIR}/coordinator/.env"
    warn "Created coordinator/.env from template."
    warn "Edit it to add your BLOCKFROST_API_KEY and WALLET_SEED_PHRASE before running on-chain."
  fi
fi

# ── Keys directory ───────────────────────────────────────────────────────────

mkdir -p "${ROOT_DIR}/keys"
ok "Keys directory ready at keys/"

echo ""
echo "==========================================="
echo -e "${GREEN} Setup complete!${NC}"
echo "==========================================="
echo ""
echo "Next steps:"
echo "  1. Run the local demo (no chain required):"
echo "       cd demo && bash run_demo.sh"
echo ""
echo "  2. Generate test BLS keys:"
echo "       bash scripts/generate_test_keys.sh"
echo ""
echo "  3. For on-chain operation:"
echo "       - Edit coordinator/.env with your Blockfrost key and wallet seed"
echo "       - Get testnet tADA: https://docs.cardano.org/cardano-testnets/tools/faucet/"
echo "       - Run: cd coordinator && npm run dev -- init --initial-model-hash <hash>"
echo ""
