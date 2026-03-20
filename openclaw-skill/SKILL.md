---
name: threathunter
description: Run autonomous AI-powered threat investigations on Linux systems. Use this skill when the user asks to scan for threats, investigate suspicious activity, hunt for malware, check for intrusions, inspect processes or network connections, or generate a security report. Also use for querying past hunt findings from the database.
version: 1.0.0
metadata:
  openclaw:
    emoji: "🔴"
    homepage: https://github.com/your-handle/threathunter
    os:
      - linux
      - darwin
    requires:
      bins:
        - threathunter
      anyBins:
        - threathunter
    primaryEnv: ANTHROPIC_API_KEY
    always: false
---

# ThreatHunter Skill

ThreatHunter is an autonomous AI-powered threat hunting CLI. It scans filesystems, inspects processes, analyses network connections, and maps findings to MITRE ATT&CK techniques.

---

## When to use this skill

Activate when the user says anything like:
- "scan /tmp for threats" / "hunt for malware on this system"
- "investigate suspicious activity" / "check if this system is compromised"
- "show me recent findings" / "what did the last hunt find?"
- "run a threat hunt on /home" / "check running processes for malware"
- "generate a security report"
- "scan with GPT" / "use Groq for the hunt" / "run locally with Ollama"

---

## Core commands

### 1. Autonomous AI investigation (primary command)

```bash
threathunter agent --target <path> [--provider <provider>] [--verbose] [--save <file>]
```

**Providers available:**
| Provider | Flag | Env var needed |
|---|---|---|
| Claude (default) | `--provider claude` | `ANTHROPIC_API_KEY` |
| OpenAI GPT-4o | `--provider openai` | `OPENAI_API_KEY` |
| Groq (fast/free) | `--provider groq` | `GROQ_API_KEY` |
| Ollama (local) | `--provider ollama` | none |

**Examples:**
```bash
# Default — Claude investigates /tmp
threathunter agent --target /tmp

# User wants OpenAI
threathunter agent --target /home --provider openai --model gpt-4o

# User wants fast/free — use Groq
threathunter agent --target /var --provider groq

# User wants fully local — Ollama
threathunter agent --target /tmp --provider ollama --model llama3.2

# Verbose — show every tool call the AI makes
threathunter agent --target /tmp --verbose

# Save report to file
threathunter agent --target /tmp --save /tmp/report.md

# Custom max iterations (deeper investigation)
threathunter agent --target / --max-iterations 20
```

**What happens during an agent run:**
1. AI decides what to scan first (filesystem, processes, or network)
2. AI calls tools and follows up on suspicious findings
3. AI maps every finding to a MITRE ATT&CK technique
4. AI writes a structured report with risk level + remediation

**Risk levels returned:** `CLEAN` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`

---

### 2. Query past findings from the database

```bash
threathunter findings [--severity HIGH] [--since 7d] [--hunt <id>] [--json]
```

**Examples:**
```bash
# Show all findings from the last 7 days (default)
threathunter findings

# Only HIGH and CRITICAL
threathunter findings --severity HIGH

# Last 24 hours
threathunter findings --since 24h

# Last 30 days
threathunter findings --since 30d

# All time
threathunter findings --since all

# JSON output (for piping / further analysis)
threathunter findings --json
```

---

### 3. List past hunt sessions

```bash
threathunter hunts [--limit 20] [--json]
```

---

### 4. Quick scans (non-AI, deterministic)

```bash
# Filesystem scan only
threathunter scan --path /tmp

# Running processes
threathunter process

# Network connections
threathunter network

# MITRE ATT&CK mapping for a specific finding
threathunter mitre --finding "reverse shell script in /tmp"

# Full report (all engines, no AI)
threathunter report --target /tmp
```

---

## How to present results to the user

### After an agent run

Extract and highlight:
1. **Risk level** — state it prominently (CLEAN / LOW / MEDIUM / HIGH / CRITICAL)
2. **Finding count** — how many findings were discovered
3. **Critical/High findings** — list each one with: severity, description, file/PID/connection, MITRE ID
4. **Attack chain** — if the AI found a chain, summarise it in plain English
5. **Top remediation step** — the most important action to take first

**Format for chat delivery:**
```
🔴 ThreatHunter Report — /tmp
Risk: HIGH | 3 findings

Critical:
• Reverse shell script: /tmp/update.sh → T1059 (Command Scripting)

High:
• Deleted executable running: PID 1842 (bash) → T1055 (Process Injection)

Recommendation: Kill PID 1842 immediately. Remove /tmp/update.sh.
Full report saved → /tmp/report.md
```

### After a findings query

Present as a clean list:
```
📋 Findings (last 7d) — 5 results

CRITICAL  filesystem  T1059  Reverse shell in /tmp/update.sh
HIGH      process     T1055  Deleted exe running as PID 1842
MEDIUM    network     T1071  Connection to suspicious IP 45.33.32.156
```

---

## Decision logic

Follow this logic when the user asks for a hunt:

1. **Which path?**
   - User specified path → use it
   - User said "this system" / "here" / no path → use `/`
   - User said "temp" / "tmp" → use `/tmp`
   - User said "home" → use `/home`

2. **Which provider?**
   - User specified provider → use it
   - `ANTHROPIC_API_KEY` is set → use `claude` (default)
   - `OPENAI_API_KEY` is set → use `openai`
   - `GROQ_API_KEY` is set → use `groq`
   - None set → use `ollama` (no key needed)
   - Cannot find any → ask user to set an API key

3. **How deep?**
   - "quick scan" / "fast" → `--max-iterations 5`
   - Default → `--max-iterations 10`
   - "deep" / "thorough" / "full" → `--max-iterations 20`

4. **Save the report?**
   - "save report" / user asks for a file → add `--save /tmp/threathunter-report-<timestamp>.md`
   - Otherwise → terminal output only

---

## Environment variable check

Before running, verify the required API key exists for the chosen provider.
If missing, tell the user exactly which variable to set:

```
To use Claude:  export ANTHROPIC_API_KEY=sk-ant-...
To use OpenAI:  export OPENAI_API_KEY=sk-...
To use Groq:    export GROQ_API_KEY=gsk_...
To use Ollama:  ollama pull llama3.2   (no key needed)
```

---

## Error handling

| Error | What to tell the user |
|---|---|
| `No API key found` | Tell them which env var to set for their chosen provider |
| `command not found: threathunter` | "ThreatHunter is not installed. Build it with: `cargo build --release` then add target/release to PATH" |
| `Permission denied reading /proc` | "Run with sudo for full process/network visibility: `sudo threathunter agent --target /tmp`" |
| `Claude API error 529` | "Claude is overloaded. Try `--provider groq` for a fast free alternative" |
| `Claude API error 401` | "Invalid API key. Check your ANTHROPIC_API_KEY value" |

---

## Example full interaction

**User:** "scan /tmp for threats and send me a summary"

**Agent actions:**
```bash
threathunter agent --target /tmp --verbose --save /tmp/th-report.md
```

**Agent response (after run):**
```
🔴 ThreatHunter — /tmp scan complete

Risk Level: HIGH
Findings: 2

🚨 HIGH — Executable script with reverse shell pattern
   File: /tmp/update.sh
   MITRE: T1059.004 (Unix Shell)

⚠️  MEDIUM — World-writable executable in /tmp
   File: /tmp/.hidden_bin
   MITRE: T1027 (Obfuscated Files)

Attack chain: A script was dropped to /tmp (likely via web exploit or
phishing) and configured to call back to a remote host. The world-writable
binary suggests an attempt to maintain persistence.

Next step: Remove /tmp/update.sh and /tmp/.hidden_bin immediately.
Check /var/log/auth.log for the initial access vector.

Full report: /tmp/th-report.md
```
