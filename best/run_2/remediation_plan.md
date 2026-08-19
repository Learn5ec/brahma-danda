

*Threat Brief — webh034*
Two vulnerable services were identified across internal and external attack surfaces on host webh034, with the highest-risk finding being unrestricted SSH root access. An attacker who obtains valid root credentials can log in directly as root without privilege escalation, immediately granting full system control.

*High*
• *Risk:* Root login permitted via SSH
  _Evidence:_ combined_meta.json — ssh_checks.findings[0].detail — "PermitRootLogin is 'yes (default)'"
  _Impact:_ Attackers who obtain root credentials can log in directly as root without privilege escalation, granting immediate full system access
• *Risk:* Password-based SSH authentication enabled
  _Evidence:_ combined_meta.json — ssh_checks.findings[1].detail — "PasswordAuthentication is 'yes (default)'"
  _Impact:_ Brute-force attacks against the SSH daemon are viable since passwords can be guessed online, increasing risk of unauthorized system access
• *Risk:* UFW firewall is inactive on host webh034
  _Evidence:_ ufw_status.txt — Status — inactive
  _Impact:_ Host lacks network-level traffic filtering and access control, exposing it to unauthorized connections, port scanning, and potential lateral movement

*Note to reviewer*
This brief is addressed to you, the reviewer. It covers Critical and High findings only. Medium, Low and informational findings are in the raw scan files attached in this thread. Remediation decisions are yours — this brief provides risk context only. Please review the attached files — especially `lynis.log` and `trivy.json` — before closing this ticket.