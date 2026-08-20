<div align="center">

# 🛡️ Brahma-Danda

### Defensive Security Intelligence for Linux Hosts

**Brahma-Danda** is a containerized, defensive security assessment agent that continuously inspects a Linux host, correlates findings from multiple security and configuration tools, uses an LLM to turn raw telemetry into a prioritized remediation brief, and delivers the result directly to Slack.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Nmap](https://img.shields.io/badge/Nmap-network%20assessment-4682B4)](https://nmap.org/)
[![Trivy](https://img.shields.io/badge/Trivy-vulnerability%20scanning-1904DA)](https://trivy.dev/)
[![Slack](https://img.shields.io/badge/Slack-alerting-4A154B?logo=slack&logoColor=white)](https://slack.com/)
[![Anthropic](https://img.shields.io/badge/Anthropic-Claude-D97757)](https://www.anthropic.com/)
[![Ollama](https://img.shields.io/badge/Ollama-local%20LLM-000000)](https://ollama.com/)

</div>

---

## ✨ Overview

Brahma-Danda is designed around a simple principle:

> **Observe → Correlate → Analyze → Prioritize → Report**

It does not patch systems, deploy agents, exploit vulnerabilities, or intentionally modify the host being assessed. Instead, it collects security-relevant evidence from the host and produces an actionable security brief for human review.

The name is inspired by the **Brahmadanda**, a defensive divine staff from Hindu tradition — a symbol of protection, authority, and the ability to neutralize threats without relying on offensive force.

### What Brahma-Danda brings together

- 🔎 OS vulnerability intelligence
- 🌐 Local network exposure and service discovery
- 🔐 SSH hardening checks
- 🧱 nginx security configuration checks
- 🐳 Docker configuration checks
- 🛡️ Host hardening assessment with Lynis
- 🔥 Firewall and packet-filter visibility
- 🔒 TLS configuration assessment with testssl.sh
- 🤖 LLM-assisted finding correlation and remediation planning
- 💬 Slack-based security reporting
- ⏱️ First-boot, scheduled, and manual scans
- 📦 Persistent scan artifacts and vulnerability databases

---

## 🧭 How It Works

```text
┌─────────────────────── Linux Host ───────────────────────┐
│                                                           │
│  Packages  Configs  Services  Network  Firewall  TLS     │
│      │         │        │         │        │       │      │
└──────┼─────────┼────────┼─────────┼────────┼───────┼──────┘
       │         │        │         │        │       │
       └─────────┴────────┴─────────┴────────┴───────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Scan Pipeline   │
                    │                  │
                    │ Trivy            │
                    │ debsecan         │
                    │ Nmap             │
                    │ Lynis            │
                    │ testssl.sh       │
                    │ SSH / nginx      │
                    │ Docker / firewall│
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Evidence / JSON  │
                    │ Raw Scan Reports │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ LLM Correlation  │
                    │                  │
                    │ Ollama → Claude  │
                    │ Recursive chunking│
                    │ Finding merge    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  Threat Brief    │
                    │  + Remediation   │
                    └────────┬─────────┘
                             │
                             ▼
                       ┌───────────┐
                       │   Slack   │
                       └───────────┘
```

---

## 🔍 Security Coverage

| Component | Purpose |
|---|---|
| **Trivy** | Root filesystem vulnerability scanning using installed OS package metadata |
| **debsecan** | Debian security-tracker cross-check against the host package database |
| **Nmap** | Full-port local service discovery and configurable NSE-based behavioral checks |
| **testssl.sh** | TLS configuration and cryptographic exposure checks for discovered TLS services |
| **Lynis** | Host hardening and security configuration assessment |
| **SSH checks** | Authentication and SSH daemon hardening controls |
| **nginx checks** | Security headers, TLS configuration, server disclosure and rate-limit controls |
| **Docker checks** | Container/runtime configuration checks |
| **ss** | Listening socket and local service visibility |
| **UFW / iptables / nftables** | Firewall and packet-filter state collection |
| **LLM layer** | Finding analysis, correlation, prioritization and remediation guidance |
| **Slack** | Threat Brief delivery and raw report attachment |

---

## 🤖 LLM-Assisted Analysis

The LLM layer is intentionally separated from the scanning layer.

Brahma-Danda first produces raw security artifacts. `remediate.py` then consumes those artifacts and performs:

1. Per-artifact analysis
2. Structured finding extraction
3. Recursive chunking for large inputs
4. Finding aggregation
5. Cross-artifact correlation
6. Final Threat Brief generation
7. Slack delivery

### Supported backends

#### Ollama

Use a locally hosted model when you want local processing or reduced API dependency.

```env
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=deepseek-coder-v2:16b
```

#### Claude / Anthropic-compatible endpoints

The project also supports the Anthropic SDK, including custom Anthropic-compatible gateways.

```env
ANTHROPIC_BASE_URL=https://your-gateway.example.com/anthropic
ANTHROPIC_AUTH_TOKEN=your-auth-token
ANTHROPIC_MODEL=your-model
```

If a custom gateway is not configured, the project can use the mounted Claude API key secret.

### Backend selection

The implementation attempts **Ollama first when Ollama is configured**, then falls back to Claude if the Ollama request fails. If Ollama is not configured, Claude is used directly when available.

This behavior is implemented in `scripts/remediate.py`.

---

## 🧩 Dynamic Recursive Chunking

Large scanner outputs can exceed the context window of an LLM.

Instead of silently truncating reports, Brahma-Danda recursively splits large inputs at newline boundaries and processes each portion independently.

```text
Large report
     │
     ▼
Within supported size?
   ┌─┴─┐
  YES  NO
   │    │
   │    ▼
   │  Split near newline
   │    │
   │    ├──────────────┐
   │    ▼              ▼
   │  Chunk A        Chunk B
   │    │              │
   │    ▼              ▼
   │  Analyze        Analyze
   │    │              │
   └────┴──────┬───────┘
               ▼
        Merge findings
```

This preserves more of the original evidence than fixed-size truncation and allows very large reports to remain analyzable.

---

## 🛡️ Defensive-by-Default Nmap Design

Nmap is one of the most powerful components in the pipeline, so Brahma-Danda deliberately treats its script selection as a security boundary.

The default configuration is intended for **detection rather than active exploitation**.

Typical configured categories include:

```text
default
safe
vuln
auth
version
malware
```

Additional behavioral probes can be configured through:

```env
NMAP_EXTRA_SCRIPTS=
```

### Intrusive scripts

Nmap also provides categories such as:

```text
exploit
dos
brute
fuzzer
```

These can actively attack or disrupt services.

They are therefore **not enabled by default**.

If explicitly enabled:

```env
NMAP_ALLOW_INTRUSIVE=true
```

the scan adds those categories and should only be run against systems where the operator has authorization and an appropriate maintenance window.

To disable local port scanning completely:

```env
NMAP_SELF_SCAN=false
```

---

## 🔐 Container Security Model

Brahma-Danda is designed to minimize unnecessary host modification and container privileges.

### Host filesystem

The host filesystem is mounted read-only:

```yaml
- /:/host:ro
```

Although the container currently runs as `root` because several host-level security checks require elevated visibility, the host filesystem exposed to the container is **read-only**. Brahma-Danda therefore cannot modify files on the mounted host filesystem through `/host`.

The elevated container user should be understood as a visibility requirement for the assessment tooling, not as permission to alter the audited host. The deployment is intentionally designed around read-only host access.

### Container filesystem

The container filesystem is configured as read-only:

```yaml
read_only: true
```

Temporary writable locations are provided through `tmpfs` where required.

### Linux capabilities

Capabilities are dropped broadly and only the capabilities required by the network scanning configuration are added back:

```yaml
cap_drop:
  - ALL

cap_add:
  - NET_RAW
  - NET_ADMIN
  - DAC_READ_SEARCH
  - DAC_OVERRIDE
```

### Network namespace

The Nmap self-scan uses:

```yaml
network_mode: host
```

This is required to observe the host's real listening ports rather than the container's isolated network namespace.

This is also the most important security trade-off in the deployment model: host networking increases network visibility, even though the host filesystem remains mounted read-only.

If local port scanning is not required, disable it with:

```env
NMAP_SELF_SCAN=false
```

### Secrets

Secrets are mounted as files under `/run/secrets/` rather than being baked into the image.

For example:

```text
/run/secrets/slack_bot_token
/run/secrets/claude_api_key
```

Do not place real credentials in `.env`, the Dockerfile, or committed source files.

---

## ⚡ Quick Start

### Prerequisites

- Linux host
- Docker Engine
- Docker Compose
- Slack workspace/channel
- Slack bot token with the required permissions
- At least one supported LLM backend:
  - Ollama
  - Claude / Anthropic
  - Anthropic-compatible gateway

### 1. Clone

```bash
git clone https://github.com/Learn5ec/brahma-danda.git
cd brahma-danda
```

### 2. Create configuration

```bash
cp .env.example .env
```

Configure at minimum:

```env
SLACK_CHANNEL_ID=C0123456789
```

### 3. Configure secrets

Create the secret files from the supplied examples:

```bash
cp secrets/slack_bot_token.txt.example secrets/slack_bot_token.txt
cp secrets/claude_api_key.txt.example secrets/claude_api_key.txt
```

Add the appropriate credentials and protect them:

```bash
chmod 600 secrets/*.txt
```

Only configure the credentials required by your selected LLM backend.

### 4. Build and start

```bash
docker compose up -d --build
```

The container performs an initial scan and then remains available for scheduled or manual scans.

### 5. Follow logs

```bash
docker compose logs -f brahmadanda
```

### 6. Trigger a manual scan

```bash
docker compose exec brahmadanda /app/scripts/run_scan.sh
```

---

## ⏱️ Scan Scheduling

Brahma-Danda supports three primary execution paths:

| Trigger | Behavior |
|---|---|
| **First boot** | Initial scan after the container is initialized |
| **Scheduled** | Cron-driven recurring scan |
| **Manual** | Execute `run_scan.sh` on demand |

The default scheduled scan is configured for:

```text
03:00 on the 1st day of every month
```

Change it through:

```env
SCAN_SCHEDULE_CRON=0 3 1 * *
```

Use standard cron syntax.

---

## ♻️ Vulnerability Database Refresh

The project maintains a persistent Trivy cache using a Docker volume.

The bundled cron workflow includes:

- Java vulnerability database cache cleanup
- Cache refresh
- A refresh scan/notification workflow
- Report retention cleanup

The persistent volume prevents the vulnerability database from being downloaded unnecessarily on every container restart.

---

## 📦 Persistent Data

Two named Docker volumes are used:

```text
scan_reports
└── Timestamped scan artifacts

trivy_cache
└── Persistent Trivy vulnerability database
```

A typical report directory contains artifacts such as:

```text
trivy.json
debsecan.txt
combined_meta.json
nmap.xml
nmap.txt
ssh_checks.json
nginx_checks.json
docker_checks.json
ss_listeners.txt
ufw_status.txt
iptables.txt
nftables.txt
lynis-report.dat
testssl_<port>.json
```

Raw reports are retained for reviewer reference and can also be attached to the corresponding Slack thread.

---

## 💬 Slack Reporting

The final workflow is designed around a concise security brief rather than dumping raw scanner output into a channel.

A successful run produces:

```text
Security scan complete for <host>

┌────────────────────────────────────┐
│ Prioritized Threat Brief           │
│                                    │
│ Critical / High findings           │
│ Key evidence                       │
│ Risk context                       │
│ Recommended remediation            │
└────────────────────────────────────┘

Thread
├── Raw Trivy report
├── Raw Nmap report
├── debsecan output
├── Lynis report
├── Firewall state
└── Other scan artifacts
```

This keeps the main Slack channel readable while preserving the underlying evidence for investigation.

---

## ⚙️ Important Configuration

| Variable | Purpose |
|---|---|
| `SLACK_CHANNEL_ID` | Destination Slack channel |
| `SCAN_SCHEDULE_CRON` | Scheduled scan expression |
| `HOSTNAME_OVERRIDE` | Optional hostname shown in reports |
| `NMAP_SELF_SCAN` | Enable/disable local Nmap scan |
| `NMAP_SCRIPT_CATEGORIES` | Nmap NSE categories |
| `NMAP_EXTRA_SCRIPTS` | Additional Nmap probes |
| `NMAP_ALLOW_INTRUSIVE` | Explicitly enable intrusive NSE categories |
| `ANTHROPIC_BASE_URL` | Optional Anthropic-compatible gateway |
| `ANTHROPIC_AUTH_TOKEN` | Gateway authentication token |
| `ANTHROPIC_MODEL` | Anthropic-compatible model override |
| `CLAUDE_MODEL` | Claude model selection |
| `OLLAMA_BASE_URL` | Ollama API endpoint |
| `OLLAMA_MODEL` | Ollama model |
| `LLM_TEMPERATURE` | LLM sampling temperature |
| `LLM_TOP_P` | Nucleus sampling threshold |

For the complete configuration surface, use `.env.example` as the source of truth.

---

## 🗂️ Repository Structure

```text
brahma-danda/
├── scripts/
│   ├── checks/
│   │   ├── nginx_checks.sh
│   │   └── ssh_checks.sh
│   ├── docker_checks.sh
│   ├── entrypoint.sh
│   ├── prompts.py
│   ├── remediate.py
│   └── run_scan.sh
│
├── secrets/
│   ├── claude_api_key.txt.example
│   └── slack_bot_token.txt.example
│
├── .env.example
├── .dockerignore
├── .gitignore
├── Dockerfile
├── command-guide.md
├── crontab
├── docker-compose.yml
├── requirements.txt
├── setup.sh
└── README.md
```

---

## 🧱 Architecture

The project is intentionally split into three logical layers.

### 1. Collection

`run_scan.sh` orchestrates the scanners and host-state checks.

```text
Host
 │
 ├── Trivy
 ├── debsecan
 ├── Nmap
 ├── testssl.sh
 ├── Lynis
 ├── SSH checks
 ├── nginx checks
 ├── Docker checks
 └── Firewall / sockets
```

### 2. Intelligence

`remediate.py` transforms scanner output into structured findings and then generates a consolidated Threat Brief.

```text
Raw artifacts
     │
     ▼
Per-file analysis
     │
     ▼
Finding extraction
     │
     ▼
Cross-file aggregation
     │
     ▼
Threat Brief
```

### 3. Delivery

The final report and raw evidence are delivered through Slack.

```text
Threat Brief ───────────────► Slack channel
Raw artifacts ──────────────► Slack thread
Local artifacts ────────────► scan_reports volume
```

---

## 🧪 Manual Testing & Operations

### Run the scanner immediately

```bash
docker compose exec brahmadanda /app/scripts/run_scan.sh
```

### Inspect logs

```bash
docker compose logs -f brahmadanda
```

### Inspect persistent reports

```bash
docker run --rm \
  -v scan_reports:/reports \
  alpine ls -la /reports
```

If the volume name differs in your Docker Compose environment, obtain it with:

```bash
docker volume ls
```

### Rebuild after configuration or code changes

```bash
docker compose down
docker compose up -d --build
```

---

## 🩺 Troubleshooting

### No Slack message

Check:

```bash
docker compose logs -f brahmadanda
```

Verify:

- The Slack bot is installed in the workspace.
- The bot has been invited to the destination channel.
- `SLACK_CHANNEL_ID` contains the channel ID, not the channel name.
- The bot token has the permissions required by the project.
- The secret file exists and is readable inside the container.

### Nmap reports `Operation not permitted`

Check the Compose capability configuration and host security policy.

If Nmap is not required:

```env
NMAP_SELF_SCAN=false
```

### Nmap takes a long time

Brahma-Danda scans all TCP ports:

```text
-p-
```

and can run multiple NSE scripts. A complete local scan can therefore take several minutes depending on the host and exposed services.

### Trivy is slow on the first run

The initial vulnerability database download can be large. Subsequent scans use the persistent `trivy_cache` volume.

### debsecan reports a suite mismatch on Ubuntu

This can occur because debsecan is based on Debian security-tracker semantics. Treat it as a secondary cross-check rather than the authoritative source for Ubuntu package patch state.

### LLM analysis fails

Check the selected backend configuration and inspect the container logs.

For Ollama:

```bash
curl http://host.docker.internal:11434/api/tags
```

For an Anthropic-compatible gateway, verify that the configured endpoint is reachable from the container.

---

## ⚠️ Security & Operational Considerations

Brahma-Danda is a defensive assessment tool, but it still requires careful deployment because it operates with visibility into the host it audits.

### Understand the trust boundary

The container:

- Reads the host filesystem through a read-only mount.
- Uses host networking when Nmap self-scanning is enabled.
- Collects security-sensitive host configuration.
- Sends the generated Threat Brief to Slack.
- May send scan-derived data to the configured LLM backend.

Before deploying it on sensitive infrastructure, review your organization's requirements for:

- Data residency
- External LLM processing
- Slack retention
- Secrets management
- Network egress
- Container isolation
- Administrative authorization

### Intrusive Nmap mode

Do not enable:

```env
NMAP_ALLOW_INTRUSIVE=true
```

unless the target host is explicitly authorized for intrusive testing and an appropriate maintenance window has been established.

---

## 🧑‍💻 Development

Python dependencies are pinned in:

```text
requirements.txt
```

Current application dependencies include:

```text
anthropic==0.40.0
requests==2.32.3
```

The container image also pins the Debian base image and bundled tool versions where applicable.

For local development, review:

```text
command-guide.md
```

and the scripts under:

```text
scripts/
```

---

## 🤝 Contributing

Contributions are welcome.

Before opening a pull request:

1. Explain the security problem or operational improvement.
2. Keep changes focused.
3. Avoid introducing new host privileges without documenting the security impact.
4. Do not commit secrets, tokens, private keys, or real scan artifacts.
5. Update the documentation when configuration or behavior changes.
6. Preserve safe defaults where possible.
7. Clearly document any change that can make a scan intrusive.

For scanner integrations, include:

- What evidence the tool produces
- Why it improves coverage
- Whether it can actively interact with services
- Required container capabilities
- Required network access
- Expected runtime impact
- Failure behavior

---

## 📜 Responsible Use

Brahma-Danda is intended for defensive security assessment of systems you own or are explicitly authorized to assess.

The maintainers do not encourage unauthorized scanning, exploitation, credential attacks, denial-of-service activity, or intrusive testing against third-party infrastructure.

Always obtain appropriate authorization before enabling intrusive scanning capabilities.

---

## ❤️ Credits & Thanks

Brahma-Danda would not be possible without the work of the security, infrastructure, and open-source communities.

Special thanks to the creators and maintainers of the tools and projects integrated into the pipeline:

- **Aqua Security / Trivy** — vulnerability and security scanning
- **Nmap Project** — network discovery and security auditing
- **Debian Security Team / debsecan** — Debian security-tracker tooling
- **CISOFY / Lynis contributors** — host security auditing and hardening
- **Dr. William Brower and testssl.sh contributors** — TLS/SSL security testing
- **Docker contributors** — containerization and runtime isolation
- **Anthropic** — Claude and the Anthropic API ecosystem
- **Ollama contributors** — local LLM inference
- **Slack** — messaging and security-report delivery infrastructure
- **Python and the Python community** — application runtime and ecosystem
- **Supercronic / Aptible contributors** — container-friendly cron scheduling

And, most importantly, thanks to every open-source maintainer, contributor, researcher, and security practitioner whose work makes defensive automation possible.

> **Brahma-Danda is built on the shoulders of the open-source security community.**

---

<div align="center">

**🛡️ Observe. Analyze. Prioritize. Defend.**

Made for defenders.

</div>
