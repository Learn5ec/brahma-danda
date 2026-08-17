#!/bin/bash
# Usage: nginx_checks.sh <host_mount_root>
# Reads the REAL host's nginx config tree (via the read-only /host mount)
# and reports on the org's HTTP/TLS security-header baseline.
set -uo pipefail

HOST_ROOT="${1:?usage: nginx_checks.sh <host_mount_root>}"
NGINX_DIR="${HOST_ROOT}/etc/nginx"

findings="[]"
add_finding() {
  local id="$1" severity="$2" status="$3" detail="$4"
  findings=$(echo "${findings}" | jq \
    --arg id "$id" --arg sev "$severity" --arg status "$status" --arg detail "$detail" \
    '. += [{"id":$id,"severity":$sev,"status":$status,"detail":$detail}]')
}

if [ ! -d "${NGINX_DIR}" ]; then
  echo '{"config_found": false, "findings": []}'
  exit 0
fi

# Concatenate all config files (main + conf.d + sites-enabled) for grep-based checks.
ALL_CONF=$(find "${NGINX_DIR}" -type f -name "*.conf" -o -type f -path "*/sites-enabled/*" 2>/dev/null)
CONCAT="$(cat ${ALL_CONF} 2>/dev/null)"

check_present() {
  local pattern="$1" id="$2" severity="$3" msg_fail="$4" msg_pass="$5"
  if echo "${CONCAT}" | grep -qiE "${pattern}"; then
    add_finding "${id}" "${severity}" "pass" "${msg_pass}"
  else
    add_finding "${id}" "${severity}" "fail" "${msg_fail}"
  fi
}

check_absent() {
  local pattern="$1" id="$2" severity="$3" msg_fail="$4" msg_pass="$5"
  if echo "${CONCAT}" | grep -qiE "${pattern}"; then
    add_finding "${id}" "${severity}" "fail" "${msg_fail}"
  else
    add_finding "${id}" "${severity}" "pass" "${msg_pass}"
  fi
}

check_present 'strict-transport-security' "nginx_hsts" "High" \
  "Strict-Transport-Security header not found. Add: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;" \
  "HSTS header present."

check_present 'x-content-type-options' "nginx_nosniff" "Medium" \
  "X-Content-Type-Options header not found. Add: add_header X-Content-Type-Options nosniff always;" \
  "X-Content-Type-Options present."

check_present 'x-frame-options' "nginx_frame_options" "Medium" \
  "X-Frame-Options header not found. Add: add_header X-Frame-Options DENY always;" \
  "X-Frame-Options present."

check_present 'content-security-policy' "nginx_csp" "High" \
  "Content-Security-Policy header not found. Define a restrictive CSP for this app." \
  "CSP header present (verify it isn't 'default-src *' or unsafe-eval)."

check_present 'server_tokens\s+off' "nginx_server_tokens" "High" \
  "server_tokens is not set to off — nginx version is disclosed in responses. Add: server_tokens off;" \
  "server_tokens off is set."

check_present 'ssl_protocols[^;]*tlsv1\.3' "nginx_tls13" "High" \
  "TLSv1.3 not found in ssl_protocols. Set: ssl_protocols TLSv1.3;" \
  "TLSv1.3 is enabled."

check_absent 'ssl_protocols[^;]*(tlsv1\.0|tlsv1\.1|sslv3|sslv2)' "nginx_legacy_tls" "Critical" \
  "Legacy TLS/SSL protocol (TLSv1.0/1.1/SSLv2/3) found in ssl_protocols — disable immediately." \
  "No legacy TLS/SSL protocols enabled."

check_present 'limit_req' "nginx_rate_limit" "High" \
  "No limit_req directive found anywhere — no rate limiting configured on any endpoint." \
  "limit_req rate limiting is configured somewhere in the config."

check_present 'client_max_body_size' "nginx_body_size" "Medium" \
  "client_max_body_size not set — using nginx default (1m), confirm this is intentional." \
  "client_max_body_size is explicitly set."

jq -n --argjson findings "${findings}" '{config_found: true, findings: $findings}'
