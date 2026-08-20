#!/bin/bash
# Brahma-Danda Setup Script
# Run this once after cloning the repo to initialize the project.
set -euo pipefail

echo "=========================================="
echo " Brahma-Danda Setup"
echo "=========================================="

# ── 0. Initialize .env ──
echo ""
echo "[0/7] Initializing .env..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "  → Created .env from .env.example"
else
    echo "  ✓ .env already exists."
fi

# ── 1. Check prerequisites ──
echo ""
echo "[1/7] Checking prerequisites..."

for cmd in docker docker compose python3 jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed."
        exit 1
    fi
done
echo "  ✓ All prerequisites found."

# ── 2. Secrets initialization ──
echo ""
echo "[2/7] Setting up secrets..."
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
echo "[3/7] Select LLM Backend"
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
        echo ""
        read -r -p "Enter model name (default: claude-sonnet-5): " MODEL_NAME
        MODEL_NAME=${MODEL_NAME:-claude-sonnet-5}
        # Configure .env
        sed -i "s|^CLAUDE_MODEL=.*|CLAUDE_MODEL=${MODEL_NAME}|" .env 2>/dev/null || true
        sed -i 's|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=|' .env 2>/dev/null || true
        sed -i 's|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^OLLAMA_MODEL=.*|OLLAMA_MODEL=|' .env 2>/dev/null || true
        echo "  ✓ Anthropic API + Ollama configured."
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
        echo ""
        read -r -p "Enter model name (default: claude-sonnet-5): " MODEL_NAME
        MODEL_NAME=${MODEL_NAME:-claude-sonnet-5}
        # Configure .env
        sed -i "s|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=${BASE_URL}|" .env
        sed -i "s|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=${AUTH_TOKEN}|" .env
        sed -i "s|^CLAUDE_MODEL=.*|CLAUDE_MODEL=${MODEL_NAME}|" .env 2>/dev/null || true
        sed -i 's|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=|' .env 2>/dev/null || true
        sed -i 's|^OLLAMA_MODEL=.*|OLLAMA_MODEL=|' .env 2>/dev/null || true
        echo "  ✓ Custom gateway + Ollama configured."
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
        read -r -p "Enter Anthropic model name (default: claude-sonnet-5): " MODEL_NAME
        MODEL_NAME=${MODEL_NAME:-claude-sonnet-5}
        echo ""
        read -r -p "Enter Ollama base URL (default: http://host.docker.internal:11434): " OLLAMA_URL
        OLLAMA_URL=${OLLAMA_URL:-http://host.docker.internal:11434}
        read -r -p "Enter Ollama model name (default: deepseek-coder-v2:16b): " OLLAMA_MODEL_NAME
        OLLAMA_MODEL_NAME=${OLLAMA_MODEL_NAME:-deepseek-coder-v2:16b}
        # Configure .env
        sed -i "s|^ANTHROPIC_BASE_URL=.*|ANTHROPIC_BASE_URL=${BASE_URL}|" .env
        sed -i "s|^ANTHROPIC_AUTH_TOKEN=.*|ANTHROPIC_AUTH_TOKEN=${AUTH_TOKEN}|" .env
        sed -i "s|^CLAUDE_MODEL=.*|CLAUDE_MODEL=${MODEL_NAME}|" .env 2>/dev/null || true
        sed -i "s|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=${OLLAMA_URL}|" .env
        sed -i "s|^OLLAMA_MODEL=.*|OLLAMA_MODEL=${OLLAMA_MODEL_NAME}|" .env
        echo "  ✓ Custom gateway + Ollama fallback configured."
        ;;
    *)
        echo "ERROR: Invalid option. Please run setup.sh again and choose 1-5."
        exit 1
        ;;
esac

# ── 4. LLM Health Check ──
echo ""
echo "[4/8] Testing LLM Connection..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

LLM_OK=false

# Function to test connection and handle failures gracefully
test_llm_connection() {
    local backend_name="$1"
    local response="$2"
    local pattern="$3"
    local failure_message="$4"

    if echo "$response" | grep -qi "$pattern"; then
        echo "  ✓ $backend_name connection successful!"
        LLM_OK=true
        return 0
    else
        echo ""
        echo "  ✗ $backend_name connection failed."
        echo ""
        echo "  $failure_message"
        echo ""
        echo "  Options:"
        echo "    1. Press Enter to continue (LLM features will be unavailable)"
        echo "    2. Type 'q' or 'quit' to exit setup and fix the configuration"
        echo ""
        read -r -p "  Continue? (Enter/q): " choice
        if [ "$choice" = "q" ] || [ "$choice" = "Q" ] || [ "$choice" = "quit" ] || [ "$choice" = "QUIT" ]; then
            echo ""
            echo "  Setup aborted. Fix the configuration and run setup.sh again."
            exit 1
        fi
        # Pressing Enter (empty string) or any other input continues
        echo "  Continuing setup without LLM connection..."
        return 1
    fi
}

# Test based on which LLM backend is configured
# Priority: Ollama (if configured as primary) > Anthropic gateway > Anthropic API
if [ -n "$(grep -v '^#' .env | grep '^ANTHROPIC_BASE_URL=' | cut -d= -f2-)" ] && [ -z "$(grep -v '^#' .env | grep '^OLLAMA_BASE_URL=' | cut -d= -f2-)" ]; then
    # Pure Anthropic gateway (option 2)
    BASE_URL=$(grep -v '^#' .env | grep '^ANTHROPIC_BASE_URL=' | cut -d= -f2-)
    AUTH_TOKEN=$(grep -v '^#' .env | grep '^ANTHROPIC_AUTH_TOKEN=' | cut -d= -f2-)
    CLAUDE_MODEL=$(grep -v '^#' .env | grep '^CLAUDE_MODEL=' | cut -d= -f2-)
    echo "  Testing Anthropic-compatible gateway at ${BASE_URL}..."
    RESPONSE=$(curl -v --connect-timeout 10 --max-time 30 \
        -X POST "${BASE_URL}/v1/messages" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        -d "{\"model\":\"${CLAUDE_MODEL}\",\"max_tokens\":50,\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one word.\"}]}" 2>&1)
    echo "  Debug: Full response: ${RESPONSE}"
    test_llm_connection "Anthropic gateway" "$RESPONSE" '"content"' \
        "Check: Base URL is reachable, auth token is valid, gateway accepts connections"

elif [ -n "$(grep -v '^#' .env | grep '^ANTHROPIC_BASE_URL=' | cut -d= -f2-)" ] && [ -n "$(grep -v '^#' .env | grep '^OLLAMA_BASE_URL=' | cut -d= -f2-)" ]; then
    # Custom gateway + Ollama fallback (option 5) - test primary first
    BASE_URL=$(grep -v '^#' .env | grep '^ANTHROPIC_BASE_URL=' | cut -d= -f2-)
    AUTH_TOKEN=$(grep -v '^#' .env | grep '^ANTHROPIC_AUTH_TOKEN=' | cut -d= -f2-)
    CLAUDE_MODEL=$(grep -v '^#' .env | grep '^CLAUDE_MODEL=' | cut -d= -f2-)
    echo "  Testing Anthropic-compatible gateway (primary) at ${BASE_URL}..."
    RESPONSE=$(curl -v --connect-timeout 10 --max-time 30 \
        -X POST "${BASE_URL}/v1/messages" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AUTH_TOKEN}" \
        -d "{\"model\":\"${CLAUDE_MODEL}\",\"max_tokens\":50,\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one word.\"}]}" 2>&1)
    echo "  Debug: Full response: ${RESPONSE}"
    test_llm_connection "Anthropic gateway" "$RESPONSE" '"content"' \
        "Gateway failed. Testing Ollama fallback..."
    if [ "$LLM_OK" = false ]; then
        OLLAMA_URL=$(grep -v '^#' .env | grep '^OLLAMA_BASE_URL=' | cut -d= -f2-)
        OLLAMA_MODEL=$(grep -v '^#' .env | grep '^OLLAMA_MODEL=' | cut -d= -f2-)
        echo "  Testing Ollama fallback at ${OLLAMA_URL}..."
        RESPONSE=$(curl -s --connect-timeout 10 --max-time 30 "${OLLAMA_URL}/api/chat" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one word.\"}],\"stream\":false}" 2>&1)
        test_llm_connection "Ollama fallback" "$RESPONSE" '"message"' \
            "Check: Ollama URL is correct, model is pulled, Ollama is running (ollama ls)"
    fi

elif [ -n "$(grep -v '^#' .env | grep '^OLLAMA_BASE_URL=' | cut -d= -f2-)" ] && [ ! -f secrets/claude_api_key.txt ]; then
    # Pure Ollama (option 3)
    OLLAMA_URL=$(grep -v '^#' .env | grep '^OLLAMA_BASE_URL=' | cut -d= -f2-)
    OLLAMA_MODEL=$(grep -v '^#' .env | grep '^OLLAMA_MODEL=' | cut -d= -f2-)
    echo "  Testing Ollama at ${OLLAMA_URL}..."
    RESPONSE=$(curl -s --connect-timeout 10 --max-time 30 "${OLLAMA_URL}/api/chat" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one word.\"}],\"stream\":false}" 2>&1)
    test_llm_connection "Ollama" "$RESPONSE" '"message"' \
        "Check: Ollama URL is reachable, model is pulled (ollama pull ${OLLAMA_MODEL}), Ollama is running (ollama ls)"

elif [ -f secrets/claude_api_key.txt ] && [ -n "$(grep -v '^#' .env | grep '^OLLAMA_BASE_URL=' | cut -d= -f2-)" ]; then
    # API key + Ollama fallback (option 4) - test primary first
    API_KEY=$(cat secrets/claude_api_key.txt)
    CLAUDE_MODEL=$(grep -v '^#' .env | grep '^CLAUDE_MODEL=' | cut -d= -f2-)
    echo "  Testing Anthropic API (primary)..."
    RESPONSE=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST "https://api.anthropic.com/v1/messages" \
        -H "Content-Type: application/json" \
        -H "x-api-key: ${API_KEY}" \
        -H "anthropic-version: 2023-06-01" \
        -d "{\"model\":\"${CLAUDE_MODEL}\",\"max_tokens\":50,\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one word.\"}]}" 2>&1)
    test_llm_connection "Anthropic API" "$RESPONSE" '"content"' \
        "Check: API key is valid, account has credits. Testing Ollama fallback..."
    if [ "$LLM_OK" = false ]; then
        OLLAMA_URL=$(grep -v '^#' .env | grep '^OLLAMA_BASE_URL=' | cut -d= -f2-)
        OLLAMA_MODEL=$(grep -v '^#' .env | grep '^OLLAMA_MODEL=' | cut -d= -f2-)
        echo "  Testing Ollama fallback at ${OLLAMA_URL}..."
        RESPONSE=$(curl -s --connect-timeout 10 --max-time 30 "${OLLAMA_URL}/api/chat" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one word.\"}],\"stream\":false}" 2>&1)
        test_llm_connection "Ollama fallback" "$RESPONSE" '"message"' \
            "Check: Ollama URL is correct, model is pulled, Ollama is running (ollama ls)"
    fi

elif [ -f secrets/claude_api_key.txt ]; then
    # Pure Anthropic API (option 1)
    API_KEY=$(cat secrets/claude_api_key.txt)
    CLAUDE_MODEL=$(grep -v '^#' .env | grep '^CLAUDE_MODEL=' | cut -d= -f2-)
    echo "  Testing Anthropic API..."
    RESPONSE=$(curl -s --connect-timeout 10 --max-time 30 \
        -X POST "https://api.anthropic.com/v1/messages" \
        -H "Content-Type: application/json" \
        -H "x-api-key: ${API_KEY}" \
        -H "anthropic-version: 2023-06-01" \
        -d "{\"model\":\"${CLAUDE_MODEL}\",\"max_tokens\":50,\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one word.\"}]}" 2>&1)
    test_llm_connection "Anthropic API" "$RESPONSE" '"content"' \
        "Check: API key is valid, account has credits. Consider using options 3-5 with Ollama if Anthropic is unavailable."

else
    echo "  ⚠ No LLM backend configured — skipping LLM check."
    echo "  You can re-run setup.sh later to configure an LLM backend."
    LLM_OK=true
fi

# ── 5. Slack Channel ID ──
echo ""
echo "[4/7] Slack Channel Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo " Get your channel ID:"
echo "  1. In Slack, click the channel name → 'Copy link'"
echo "  2. The URL contains the channel ID (e.g., https://your-workspace.slack.com/archives/C0123ABCXYZ)"
echo "  3. Copy the ID part (e.g., C0123ABCXYZ)"
echo ""

read -r -p "Enter Slack channel ID: " CHANNEL_ID
if [ -z "$CHANNEL_ID" ]; then
    echo "ERROR: Slack channel ID is required."
    exit 1
fi
sed -i "s|^SLACK_CHANNEL_ID=.*|SLACK_CHANNEL_ID=${CHANNEL_ID}|" .env
echo "  ✓ Slack channel configured."

# ── 5. Docker build ──
echo ""
echo "[6/8] Building Docker image..."
docker compose build --no-cache brahmadanda
echo "  ✓ Image built: brahma-danda:1.0.0"

# ── 6. Create volumes and start init container ──
echo ""
echo "[7/8] Initializing Docker resources..."
docker compose up -d brahma-danda-init
echo "  ✓ Volumes and networks ready."

# ── 8. Slack Onboarding Check (last step) ──
echo ""
echo "[8/8] Verifying Slack Connection & Onboarding..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SLACK_TOKEN=$(cat secrets/slack_bot_token.txt)
MACHINE_NAME=$(hostname)

# Determine the Slack message format (bold + italic in Slack uses *_text_*)
SLACK_TEXT="*${MACHINE_NAME} _onboarded_*"

echo "  Sending onboarding message to Slack channel: ${CHANNEL_ID}"
echo "  Message: ${SLACK_TEXT}"

SLACK_RESPONSE=$(curl -s --connect-timeout 10 --max-time 30 \
    -X POST "https://slack.com/api/chat.postMessage" \
    -H "Authorization: Bearer ${SLACK_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"channel\":\"${CHANNEL_ID}\",\"text\":\"${SLACK_TEXT}\"}" 2>&1)

if echo "$SLACK_RESPONSE" | grep -q '"ok":true'; then
    echo "  ✓ Slack connection successful!"
    echo "  ✓ Onboarding message posted: ${SLACK_TEXT}"
else
    echo "  ✗ Slack connection failed."
    echo "  Response: ${SLACK_RESPONSE}"
    echo ""
    echo "  Please check:"
    echo "    - The Slack bot token is valid (secrets/slack_bot_token.txt)"
    echo "    - The channel ID is correct"
    echo "    - The bot has been added to the channel"
    exit 1
fi

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
