# ThreatHunter — Complete Command Reference

Quick lookup for the OpenClaw agent.

## agent — AI investigation

```
threathunter agent
  --target <path>           path to investigate (default: .)
  --provider <name>         claude | openai | groq | ollama (default: claude)
  --model <model>           override model (e.g. gpt-4o, llama3.2)
  --api-url <url>           custom endpoint (Azure, local proxy, etc.)
  --api-key <key>           override env var
  --max-iterations <n>      tool-call rounds before forced report (default: 10)
  --verbose                 show each tool call live
  --save <file>             save report as Markdown
  --campaign <id>           tag hunt to a campaign
  --no-persist              skip database write
```

## findings — query database

```
threathunter findings
  --severity <level>        CRITICAL | HIGH | MEDIUM | LOW (default: LOW)
  --since <window>          24h | 7d | 30d | all (default: 7d)
  --hunt <id>               filter to one hunt session
  --limit <n>               max results (default: 100)
  --json                    output JSON
```

## hunts — list sessions

```
threathunter hunts
  --limit <n>               sessions to show (default: 20)
  --json                    output JSON
```

## scan — filesystem only (no AI)

```
threathunter scan
  --path <path>             path to scan
  --recursive               scan subdirectories
  --json                    output JSON
```

## process — running processes

```
threathunter process
  --suspicious-only         show only flagged processes
  --json                    output JSON
```

## network — live connections

```
threathunter network
  --suspicious-only         show only flagged connections
  --json                    output JSON
```

## mitre — ATT&CK mapping

```
threathunter mitre
  --finding <text>          describe the finding to map
```

## report — full static report

```
threathunter report
  --target <path>           path to scan
  --output <file>           save as JSON
  --format json|text        output format (default: text)
```

## Risk levels

| Level    | Score  | Meaning                                      |
|----------|--------|----------------------------------------------|
| CLEAN    | 0      | Nothing found                                |
| LOW      | 1–15   | Minor anomalies, likely benign               |
| MEDIUM   | 16–55  | Suspicious activity, investigate further     |
| HIGH     | 56–120 | Strong indicators of compromise              |
| CRITICAL | 120+   | Active threat — immediate action required    |

## MITRE ATT&CK examples

| Finding type              | Technique ID | Tactic              |
|---------------------------|-------------|---------------------|
| Reverse shell script      | T1059.004   | Execution           |
| Deleted exe in /proc      | T1055       | Defence Evasion     |
| Connection to C2 port     | T1071       | Command & Control   |
| Executable in /tmp        | T1027       | Defence Evasion     |
| Root interpreter process  | T1548       | Privilege Escalation|
| IOC hash match            | T1204       | Execution           |
