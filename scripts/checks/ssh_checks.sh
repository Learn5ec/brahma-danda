#!/bin/bash
# Usage: ssh_checks.sh <host_mount_root>
# Reads the REAL host's sshd_config (via the read-only /host mount) and
# reports on the checks from the org's SSH hardening baseline.
set -uo pipefail

HOST_ROOT="${1:?usage: ssh_checks.sh <host_mount_root>}"
CFG="${HOST_ROOT}/etc/ssh/sshd_config"

get_effective_value() {
  # sshd_config: last matching directive wins, case-insensitive keyword,
  # ignore comments/blank lines. Falls back to "(not set / default)".
  local key="$1"
  if [ -f "${CFG}" ]; then
    grep -iE "^\s*${key}\s+" "${CFG}" 2>/dev/null | tail -n1 | awk '{print $2}'
  fi
}

findings="[]"
add_finding() {
  local id="$1" severity="$2" status="$3" detail="$4"
  findings=$(echo "${findings}" | jq \
    --arg id "$id" --arg sev "$severity" --arg status "$status" --arg detail "$detail" \
    '. += [{"id":$id,"severity":$sev,"status":$status,"detail":$detail}]')
}

if [ ! -f "${CFG}" ]; then
  echo '{"config_found": false, "findings": []}'
  exit 0
fi

PERMIT_ROOT_LOGIN=$(get_effective_value "PermitRootLogin")
PASSWORD_AUTH=$(get_effective_value "PasswordAuthentication")
LOGIN_GRACE_TIME=$(get_effective_value "LoginGraceTime")
MAX_AUTH_TRIES=$(get_effective_value "MaxAuthTries")
X11_FORWARDING=$(get_effective_value "X11Forwarding")

if [ -z "${PERMIT_ROOT_LOGIN}" ] || [ "${PERMIT_ROOT_LOGIN}" = "yes" ]; then
  add_finding "ssh_permit_root_login" "High" "fail" \
    "PermitRootLogin is '${PERMIT_ROOT_LOGIN:-yes (default)}'. Set 'PermitRootLogin no' in sshd_config."
else
  add_finding "ssh_permit_root_login" "High" "pass" "PermitRootLogin=${PERMIT_ROOT_LOGIN}"
fi

if [ -z "${PASSWORD_AUTH}" ] || [ "${PASSWORD_AUTH}" = "yes" ]; then
  add_finding "ssh_password_auth" "High" "fail" \
    "PasswordAuthentication is '${PASSWORD_AUTH:-yes (default)}'. Set 'PasswordAuthentication no' and use key-based auth only."
else
  add_finding "ssh_password_auth" "High" "pass" "PasswordAuthentication=${PASSWORD_AUTH}"
fi

if [ -n "${LOGIN_GRACE_TIME}" ] && [ "${LOGIN_GRACE_TIME}" != "0" ]; then
  grace_num=$(echo "${LOGIN_GRACE_TIME}" | tr -dc '0-9')
  if [ -n "${grace_num}" ] && [ "${grace_num}" -gt 60 ]; then
    add_finding "ssh_login_grace_time" "Medium" "fail" \
      "LoginGraceTime is ${LOGIN_GRACE_TIME}, longer than recommended 60s. Also relevant to CVE-2024-6387 exposure window — confirm patch level separately."
  else
    add_finding "ssh_login_grace_time" "Medium" "pass" "LoginGraceTime=${LOGIN_GRACE_TIME}"
  fi
fi

if [ -z "${MAX_AUTH_TRIES}" ] || [ "${MAX_AUTH_TRIES}" -gt 4 ] 2>/dev/null; then
  add_finding "ssh_max_auth_tries" "Low" "fail" \
    "MaxAuthTries is '${MAX_AUTH_TRIES:-6 (default)}'. Recommend 3-4 to slow brute force."
else
  add_finding "ssh_max_auth_tries" "Low" "pass" "MaxAuthTries=${MAX_AUTH_TRIES}"
fi

if [ -z "${X11_FORWARDING}" ] || [ "${X11_FORWARDING}" = "yes" ]; then
  add_finding "ssh_x11_forwarding" "Low" "fail" \
    "X11Forwarding is '${X11_FORWARDING:-yes (default)}'. Disable unless explicitly needed."
else
  add_finding "ssh_x11_forwarding" "Low" "pass" "X11Forwarding=${X11_FORWARDING}"
fi

jq -n --argjson findings "${findings}" '{config_found: true, findings: $findings}'
