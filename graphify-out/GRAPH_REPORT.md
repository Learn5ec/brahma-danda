# Graph Report - /home/web-h-034/Downloads/secscan  (2026-08-13)

## Corpus Check
- Corpus is ~3,711 words - fits in a single context window. You may not need a graph.

## Summary
- 57 nodes · 84 edges · 10 communities (6 shown, 4 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 7 edges (avg confidence: 0.5)
- Token cost: 30,907 input · 0 output

## Community Hubs (Navigation)
- Vulnerability Detection
- Remediation Engine
- Security Configuration
- Container Runtime
- Network Scanning
- Nginx Checks
- SSH Checks
- Python Dependencies
- Entrypoint
- Run Scan

## God Nodes (most connected - your core abstractions)
1. `secscan-agent` - 19 edges
2. `nmap` - 7 edges
3. `Claude (Sonnet)` - 6 edges
4. `build_user_prompt()` - 5 edges
5. `main()` - 5 edges
6. `read_secret()` - 4 edges
7. `summarize_nmap_xml()` - 4 edges
8. `post_to_slack()` - 4 edges
9. `Trivy` - 4 edges
10. `nginx_checks.sh script` - 3 edges

## Surprising Connections (you probably didn't know these)
- `anthropic SDK` ----> `secscan-agent`  [INFERRED]
  requirements.txt → docker-compose.yml
- `secscan-agent` ----> `Claude API key`  [EXTRACTED]
  docker-compose.yml → README.md
- `secscan-agent` ----> `.env`  [INFERRED]
  docker-compose.yml → README.md
- `secscan-agent` ----> `Slack bot token`  [EXTRACTED]
  docker-compose.yml → README.md
- `secscan-agent` ----> `Slack`  [EXTRACTED]
  docker-compose.yml → README.md

## Import Cycles
- None detected.

## Communities (10 total, 4 thin omitted)

### Community 0 - "Vulnerability Detection"
Cohesion: 0.20
Nodes (11): Claude (Sonnet), debsecan, Network exposure, Nginx configuration hardening check, OS package CVEs, Slack, SSH configuration hardening check, SSH misconfigurations (+3 more)

### Community 1 - "Remediation Engine"
Cohesion: 0.47
Nodes (9): Path, build_user_prompt(), call_claude(), main(), post_to_slack(), Compact text summary of nmap's XML — bounded size, keeps the CVE     script outp, read_secret(), read_truncated() (+1 more)

### Community 2 - "Security Configuration"
Cohesion: 0.29
Nodes (6): Claude API key, CLAUDE_MODEL, no-new-privileges:true, Container read-only filesystem, SCAN_SCHEDULE_CRON, Slack bot token

### Community 3 - "Container Runtime"
Cohesion: 0.29
Nodes (7): .env, Host filesystem (read-only), Least privilege security model, network_mode: host, run_scan.sh, scan_reports named volume, secscan-agent

### Community 4 - "Network Scanning"
Cohesion: 0.33
Nodes (6): NET_ADMIN capability, NET_RAW capability, NMAP_ALLOW_INTRUSIVE, NMAP_SCRIPT_CATEGORIES, NMAP_SELF_SCAN, nmap

### Community 5 - "Nginx Checks"
Cohesion: 0.80
Nodes (4): add_finding(), check_absent(), check_present(), nginx_checks.sh script

## Knowledge Gaps
- **14 isolated node(s):** `entrypoint.sh script`, `run_scan.sh script`, `network_mode: host`, `no-new-privileges:true`, `SCAN_SCHEDULE_CRON` (+9 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `secscan-agent` connect `Container Runtime` to `Vulnerability Detection`, `Security Configuration`, `Network Scanning`, `Python Dependencies`?**
  _High betweenness centrality (0.262) - this node is a cross-community bridge._
- **Why does `anthropic SDK` connect `Python Dependencies` to `Container Runtime`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Why does `nmap` connect `Network Scanning` to `Vulnerability Detection`, `Container Runtime`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `secscan-agent` (e.g. with `anthropic SDK` and `.env`) actually correct?**
  _`secscan-agent` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `Claude (Sonnet)` (e.g. with `Network exposure` and `Nginx configuration hardening check`) actually correct?**
  _`Claude (Sonnet)` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `entrypoint.sh script`, `run_scan.sh script`, `network_mode: host` to the rest of the system?**
  _14 weakly-connected nodes found - possible documentation gaps or missing edges._