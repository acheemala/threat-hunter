# Contributing to ThreatHunter

ThreatHunter is open source and we welcome contributors of every level.

**No prior experience required. Just bring curiosity.**

---

## Quick start (5 minutes)

```bash
# 1. Fork and clone
git clone https://github.com/acheemala/threat-hunter
cd threat-hunter

# 2. Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 3. Build
cargo build

# 4. Run the tests
cargo test

# 5. Try the tool
./target/debug/threathunter --help
./target/debug/threathunter scan --path /tmp
```

---

## Development setup

### Requirements
- Rust 1.75+ (`rustup update stable`)
- Linux or macOS (Windows via WSL2)
- Optional: `ANTHROPIC_API_KEY` for testing the `agent` subcommand

### Useful commands

```bash
cargo build              # debug build
cargo build --release    # optimised release build
cargo test               # run all tests
cargo clippy             # linter — fix all warnings before submitting a PR
cargo fmt                # auto-format code
```

### Project structure

```
src/
├── main.rs              CLI definition and routing
├── scanner.rs           Filesystem scanning engine
├── process.rs           Process inspection engine
├── network.rs           Network connection analysis
├── ioc.rs               IOC database (hashes, IPs, domains)
├── report.rs            Finding and ThreatReport types
├── db/                  SQLite persistence layer
├── agent/               Agentic AI engine
│   ├── provider.rs      AiProvider trait + neutral message types
│   ├── providers/       One file per AI backend
│   │   ├── claude.rs    Anthropic
│   │   └── openai.rs    OpenAI / Groq / Ollama / Azure
│   ├── loop.rs          Investigation loop
│   └── tools.rs         Security tools the AI can call
└── commands/            One file per CLI subcommand
```

---

## Submitting a PR

1. **Open an issue first** for anything beyond a small fix
2. **One thing per PR** — smaller PRs get reviewed faster
3. **Tests required** for new detection logic, tools, and database functions
4. **No warnings** — `cargo clippy` must pass clean
5. **Formatted** — run `cargo fmt` before pushing

### PR title format

```
feat: add check_crontab tool to agent
fix: handle permission denied when reading /proc/net
docs: add MITRE T1059 examples to README
test: add unit tests for network connection parsing
refactor: replace manual severity match with typed enum
```

---

## Code style

- Follow the pattern of the file you're editing
- Comments explain **why**, not what
- Error messages should tell the user what to do next, not just what failed
- Severity levels: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO` — be conservative
- Every new detection rule needs a MITRE ATT&CK technique ID

---

## Issue labels

| Label | Meaning |
|---|---|
| `good-first-issue` | Safe starting point |
| `security-logic` | Changes to detection rules — extra scrutiny |
| `ai-agent` | Changes to the agentic AI layer |
| `help-wanted` | Open to anyone |

---

## Questions?

Open a **Discussions → Stuck** post. PRs and issues are not the right place for questions.

→ [Open a Discussion](../../discussions)
