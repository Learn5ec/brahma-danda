#!/bin/bash
# Brahma-Danda Setup Script
# Run this once after cloning the repo to initialize the project.
set -euo pipefail

echo "=========================================="
echo " Brahma-Danda Setup"
echo "=========================================="

# ── 1. Check prerequisites ──
echo ""
echo "[1/5] Checking prerequisites..."

for cmd in docker docker compose python3 jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed."
        exit 1
    fi
done
echo "  ✓ All prerequisites found."

# ── 2. Secrets initialization ──
echo ""
echo "[2/5] Setting up secrets..."
mkdir -p secrets

if [ ! -f secrets/slack_bot_token.txt ]; then
    echo "  → Creating secrets/slack_bot_token.txt (empty)"
    touch secrets/slack_bot_token.txt
    echo "  ⚠️  Add your Slack bot token to secrets/slack_bot_token.txt"
    echo "     Get it from: https://api.slack.com/apps → Your App → Bot Token"
else
    echo "  ✓ secrets/slack_bot_token.txt already exists."
fi

if [ ! -f secrets/claude_api_key.txt ]; then
    echo "  → Creating secrets/claude_api_key.txt (empty)"
    touch secrets/claude_api_key.txt
    echo "  ⚠️  Add your Anthropic API key to secrets/claude_api_key.txt (optional — Ollama fallback works without it)"
else
    echo "  ✓ secrets/claude_api_key.txt already exists."
fi

# ── 3. Environment configuration ──
echo ""
echo "[3/5] Checking .env configuration..."
if [ ! -f .env ]; then
    echo "ERROR: .env file not found. Copy .env.example to .env and fill in values."
    exit 1
fi

# Check required variables
required_vars=(SLACK_CHANNEL_ID)
for var in "${required_vars[@]}"; do
    if ! grep -q "^${var}=" .env 2>/dev/null; then
        echo "  ⚠️  $var not set in .env — please update it before running scans."
    fi
done
echo "  ✓ .env found."

# ── 4. Docker build ──
echo ""
echo "[4/5] Building Docker image..."
docker compose build --no-cache brahmadanda
echo "  ✓ Image built: brahma-danda:1.0.0"

# ── 5. Create volumes and start init container ──
echo ""
echo "[5/5] Initializing Docker resources..."
docker compose up -d brahma-danda-init
echo "  ✓ Volumes and networks ready."

# ── Done ──
echo ""
echo "=========================================="
echo " Setup complete!"
echo "=========================================="
echo ""
echo " Next steps:"
echo "  1. Add your Slack bot token:    vim secrets/slack_bot_token.txt"
echo "  2. (Optional) Add Claude API:   vim secrets/claude_api_key.txt"
echo "  3. Set SLACK_CHANNEL_ID in .env"
echo "  4. Run initial scan:            docker exec brahma-danda /app/scripts/run_scan.sh"
echo "  5. Or let cron handle it (default: 03:00 on 1st of month)"
echo ""
echo " Troubleshooting:"
echo "  docker logs -f brahma-danda"
echo "  docker compose logs brahmadanda-init"
