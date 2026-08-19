#!/usr/bin/env bash
# docker_checks.sh
# Gathers Docker security configuration into JSON.

OUTPUT_FILE="${1:-docker_checks.json}"
# Initialize empty findings array
echo '{"config_found": true, "findings": []}' > "$OUTPUT_FILE"

# Check if Docker is installed
if ! command -v docker &>/dev/null && ! systemctl is-active --quiet docker 2>/dev/null; then
    echo '{"config_found": false, "findings": []}' > "$OUTPUT_FILE"
    exit 0
fi

add_finding() {
    local rule=$1
    local status=$2
    local details=$3
    # Use jq to append to the JSON file
    jq --arg r "$rule" --arg s "$status" --arg d "$details" \
       '.findings += [{"id": $r, "status": $s, "detail": $d}]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
}

# 1. Check socket permissions
sock_path="/var/run/docker.sock"
if [ -e "$sock_path" ]; then
    sock_perms=$(stat -c "%a" "$sock_path" 2>/dev/null)
    if [[ "$sock_perms" == *666* ]] || [[ "$sock_perms" == *777* ]]; then
        add_finding "docker-socket-perms" "FAIL" "Docker socket $sock_path is world-writable (perms: $sock_perms)."
    else
        add_finding "docker-socket-perms" "PASS" "Docker socket $sock_path has restrictive permissions (perms: $sock_perms)."
    fi
else
    add_finding "docker-socket-perms" "PASS" "Docker socket $sock_path not found."
fi

# 2. Check docker group membership
group_members=$(getent group docker | cut -d: -f4)
if [ -n "$group_members" ]; then
    add_finding "docker-group-members" "FAIL" "Users in docker group (root equivalent): $group_members"
else
    add_finding "docker-group-members" "PASS" "No additional users in docker group."
fi

# 3. Check for TCP exposure without TLS
# We check systemd service and daemon.json
tcp_exposed=0
tcp_details=""

# Check daemon.json
daemon_json="/etc/docker/daemon.json"
if [ -f "$daemon_json" ]; then
    hosts=$(jq -r '.hosts[]?' "$daemon_json" 2>/dev/null)
    for h in $hosts; do
        if [[ "$h" == tcp://* ]] && [[ "$h" != *":2376"* ]]; then # 2376 is default TLS port, 2375 is unencrypted
            tcp_exposed=1
            tcp_details+="Exposed in daemon.json: $h. "
        fi
    done
fi

# Check systemd drop-ins / service config
systemctl_out=$(systemctl show --property=ExecStart docker 2>/dev/null)
if [[ "$systemctl_out" == *"-H tcp://"* ]] || [[ "$systemctl_out" == *"-H=tcp://"* ]]; then
     if [[ "$systemctl_out" != *"--tlsverify"* ]]; then
         tcp_exposed=1
         tcp_details+="Exposed in systemd without --tlsverify. "
     fi
fi

if [ "$tcp_exposed" -eq 1 ]; then
    add_finding "docker-tcp-exposure" "FAIL" "Docker daemon exposed on TCP without TLS verification. $tcp_details"
else
    add_finding "docker-tcp-exposure" "PASS" "Docker daemon not exposed insecurely on TCP."
fi
