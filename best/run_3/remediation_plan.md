

*Threat Brief — webh034*
This host exposes two vulnerable services (SSH and host-based network filtering) across four High-severity findings. The highest-risk issue is SSH configured to permit root login with password authentication, enabling an attacker to brute-force credentials and gain immediate full system control.

*High*
• *Risk:* SSH root login permitted
  _Evidence:_ combined_meta.json — ssh_checks.findings[0].detail — PermitRootLogin is 'yes (default)'
  _Impact:_ Compromised root credentials or successful brute-force grants immediate full system control, bypassing least-privilege enforcement and standard user audit trails.

• *Risk:* SSH password authentication enabled
  _Evidence:_ combined_meta.json — ssh_checks.findings[1].detail — PasswordAuthentication is 'yes (default)'
  _Impact:_ Host remains exposed to online/offline brute-force attacks, credential stuffing, and weak password exploitation without cryptographic verification barriers.

• *Risk:* UFW host-based firewall is inactive
  _Evidence:_ ufw_status.txt — Status — inactive
  _Impact:_ The host lacks local network filtering, leaving all bound services exposed to unauthorized access, port enumeration, and direct network-based attacks.

• *Risk:* Default INPUT chain policy set to ACCEPT with no filtering rules
  _Evidence:_ iptables.txt — *filter :INPUT — :INPUT ACCEPT [0:0]
  _Impact:_ All inbound traffic to the host is permitted by default, potentially exposing internal services, management ports, and user-facing applications to unauthorized access or exploitation without any network-level restrictions.

*Note to reviewer*
This brief is addressed to you, the reviewer. It covers Critical and High findings only. Medium, Low and informational findings are in the raw scan files attached in this thread. Remediation decisions are yours — this brief provides risk context only. Please review the attached files — especially `lynis.log` and `trivy.json` — before closing this ticket.