#!/bin/bash
# Brahma-Danda Setup Script
# Run this once after cloning the repo to initialize the project.
set -euo pipefail

echo "=========================================="
echo " Brahma-Danda Setup"
echo "=========================================="

# ── 1. Check prerequisites ──
echo ""
echo "[1/6] Checking prerequisites..."

for cmd in docker docker compose python3 jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed."
        exit 1
    fi
done
echo "  ✓ All prerequisites found."

# ── 2. Secrets initialization ──
echo ""
echo "[2/6] Setting up secrets..."
mkdir -p secrets

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Slack Bot Token Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo " How to generate a Slack bot token:"
echo "  1. Go to https://api.slack.com/apps"
echo "  2. Click 'Create New App' → 'From scratch'"
echo "  3. Name it (e.g., 'Brahma-Danda') and select your workspace"
echo "  4. Go to 'OAuth & Permissions' in the left menu"
echo "  5. Under 'Scopes' → 'Bot Token Scopes', add:"
echo "     - chat:write          (to post messages)"
echo "     - files:write         (to upload attachments)"
echo "     - files:write.external (to upload from external URLs)"
echo "     - channels:read       (to list channels)"
echo "     - groups:read         (to list private channels)"
echo "  6. Go to 'Install App' in the left menu"
echo "  7. Click 'Install to Workspace' and authorize"
echo "  8. Copy the 'Bot User OAuth Token' (starts with xoxb-)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -f secrets/slack_bot_token.txt ]; then
    echo "  → Creating secrets/slack_bot_token.txt"
    read -r -p "Paste your Slack bot token (xoxb-...): " SLACK_TOKEN
    if [ -z "$SLACK_TOKEN" ]; then
        echo "ERROR: Slack bot token is required."
        exit 1
    fi
    echo "$SLACK_TOKEN" > secrets/slack_bot_token.txt
    echo "  ✓ Slack bot token saved."
else
    echo "  ✓ secrets/slack_bot_token.txt already exists."
fi

# ── 3. LLM Backend Selection ──
echo ""
echo "[3/6] Select LLM Backend"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo " Choose how Brahma-Danda powers the Threat Brief:"
echo ""
echo "  1. Anthropic API key (Claude)"
echo "  2. Custom URL + Auth token (Anthropic-compatible gateway)"
echo "  3. Local Ollama instance"
echo "  4. Anthropic API key + Ollama (fallback)"
echo "  5. Custom URL + Auth token + Ollama (fallback)"
echo ""
read -r -p "Select option (1-5): " LLM_OPTION

case $LLM_OPTION in
    1)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo " Anthropic API Setup"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo " Get your API key from: https://console.anthropic.com/"
        echo ""
        if [ ! -f secrets/claude_api_key.txt ]; then
            read -r -p "Paste your Anthropic API key: " API_KEY
            if [ -z "$API_KEY" ]; then
                echo "ERROR: API key is required."
                exit 1
            fi
            echo "$API_KEY" > secrets/claude_api_key.txt
            echo "  ✓ API key saved."
        else
            echo "  ✓ secrets/claude_api_key.txt already exists."
        fi
        # Configure .env
        sed -i 's|^CLAUDE_MODEL=.*|CLAUDE_MODEL=claude-sonnet-5|' .env 2>/dev/null || true
        sed -i 's|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=|' .env 2>/dev/null || true
        sed -i 's|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^OLLAMA_MODEL=.*|OLLAMA_MODEL=|' .env 2>/dev/null || true
        ;;
    2)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo " Custom Gateway Setup"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        read -r -p "Enter Anthropic-compatible base URL: " BASE_URL
        read -r -p "Enter auth token: " AUTH_TOKEN
        if [ -z "$BASE_URL" ] || [ -z "$AUTH_TOKEN" ]; then
            echo "ERROR: Base URL and auth token are required."
            exit 1
        fi
        # Configure .env
        sed -i "s|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=${BASE_URL}|" .env
        sed -i "s|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=${AUTH_TOKEN}|" .env
        sed -i 's|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^OLLAMA_MODEL=.*|OLLAMA_MODEL=|' .env 2>/dev/null || true
        echo "  ✓ Custom gateway configured."
        ;;
    3)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo " Ollama Setup"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        read -r -p "Enter Ollama base URL (default: http://host.docker.internal:11434): " OLLAMA_URL
        OLLAMA_URL=${OLLAMA_URL:-http://host.docker.internal:11434}
        read -r -p "Enter Ollama model name (default: deepseek-coder-v2:16b): " OLLAMA_MODEL_NAME
        OLLAMA_MODEL_NAME=${OLLAMA_MODEL_NAME:-deepseek-coder-v2:16b}
        # Configure .env
        sed -i "s|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=${OLLAMA_URL}|" .env
        sed -i "s|^OLLAMA_MODEL=.*|OLLAMA_MODEL=${OLLAMA_MODEL_NAME}|" .env
        sed -i 's|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=|' .env 2>/dev/null || true
        echo "  ✓ Ollama configured."
        ;;
    4)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo " Anthropic + Ollama Fallback Setup"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        if [ ! -f secrets/claude_api_key.txt ]; then
            read -r -p "Paste your Anthropic API key: " API_KEY
            if [ -z "$API_KEY" ]; then
                echo "ERROR: API key is required."
                exit 1
            fi
            echo "$API_KEY" > secrets/claude_api_key.txt
            echo "  ✓ API key saved."
        else
            echo "  ✓ secrets/claude_api_key.txt already exists."
        fi
        echo ""
        read -r -p "Enter Ollama base URL (default: http://host.docker.internal:11434): " OLLAMA_URL
        OLLAMA_URL=${OLLAMA_URL:-http://host.docker.internal:11434}
        read -r -p "Enter Ollama model name (default: deepseek-coder-v2:16b): " OLLAMA_MODEL_NAME
        OLLAMA_MODEL_NAME=${OLLAMA_MODEL_NAME:-deepseek-coder-v2:16b}
        # Configure .env
        sed -i 's|^CLAUDE_MODEL=.*|CLAUDE_MODEL=claude-sonnet-5|' .env 2>/dev/null || true
        sed -i 's|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=|' .env 2>/dev/null || true
        sed -i "s|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=${OLLAMA_URL}|" .env
        sed -i "s|^OLLAMA_MODEL=.*|OLLAMA_MODEL=${OLLAMA_MODEL_NAME}|" .env
        echo "  ✓ Anthropic + Ollama fallback configured."
        ;;
    5)
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo " Custom Gateway + Ollama Fallback Setup"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        read -r -p "Enter Anthropic-compatible base URL: " BASE_URL
        read -r -p "Enter auth token: " AUTH_TOKEN
        if [ -z "$BASE_URL" ] || [ -z "$AUTH_TOKEN" ]; then
            echo "ERROR: Base URL and auth token are required."
            exit 1
        fi
        echo ""
        read -r -p "Enter Ollama base URL (default: http://host.docker.internal:11434): " OLLAMA_URL
        OLLAMA_URL=${OLLAMA_URL:-http://host.docker.internal:11434}
        read -r -p "Enter Ollama model name (default: deepseek-coder-v2:16b): " OLLAMA_MODEL_NAME
        OLLAMA_MODEL_NAME=${OLLAMA_MODEL_NAME:-deepseek-coder-v2:16b}
        # Configure .env
        sed -i "s|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=${BASE_URL}|" .env
        sed -i "s|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=${AUTH_TOKEN}|" .env
        sed -i "s|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=${OLLAMA_URL}|" .env
        sed -i "s|^OLLAMA_MODEL=.*|OLLAMA_MODEL=${OLLAMA_MODEL_NAME}|" .env
        echo "  ✓ Custom gateway + Ollama fallback configured."
        ;;
    *)
        echo "ERROR: Invalid option. Please run setup.sh again and choose 1-5."
        exit 1
        ;;
esac

# ── 4. Slack Channel ID ──
echo ""
echo "[4/6] Slack Channel Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo " Get your channel ID:"
echo "  1. In Slack, click the channel name → 'Copy link'"
echo "  2. The URL contains the channel ID (e.g., https://your-workspace.slack.com/archives/C0123ABCXYZ)"
echo "  3. Copy the ID part (e.g., C0123ABCXYZ)"
echo ""

if [ ! -f .env ]; then
    cp .env.example .env
    echo "  → Created .env from .env.example"
fi

read -r -p "Enter Slack channel ID: " CHANNEL_ID
if [ -z "$CHANNEL_ID" ]; then
    echo "ERROR: Slack channel ID is required."
    exit 1
fi
sed -i "s|^SLACK_CHANNEL_ID=.*|SLACK_CHANNEL_ID=${CHANNEL_ID}|" .env
echo "  ✓ Slack channel configured."

# ── 5. Docker build ──
echo ""
echo "[5/6] Building Docker image..."
docker compose build --no-cache brahmadanda
echo "  ✓ Image built: brahma-danda:1.0.0"

# ── 6. Create volumes and start init container ──
echo ""
echo "[6/6] Initializing Docker resources..."
docker compose up -d brahma-danda-init
echo "  ✓ Volumes and networks ready."

# ── Done ──
echo ""
echo "=========================================="
echo " Setup complete!"
echo "=========================================="
echo ""
echo " Next steps:"
echo "  1. Run initial scan:  docker exec brahma-danda /app/scripts/run_scan.sh"
echo "  2. Or let cron handle it (default: 03:00 on 1st of month)"
echo ""
echo " Troubleshooting:"
echo "  docker logs -f brahma-danda"
echo "  docker compose logs brahmadanda-init"
echo ""
echo " To reconfigure LLM backend later:"
echo "  vim .env"
echo "  docker compose build --no-cache brahmadanda && docker compose up -d"
