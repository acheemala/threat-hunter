# Contributing to ThreatHunter

ThreatHunter is an open source threat hunting CLI and we welcome contributors of every level — from people writing their first Rust to experienced security engineers.

**No prior experience required. Just bring curiosity.**

---

## Two ways to contribute

### 1. Learning Program (structured, guided)
A 6 or 12-month curriculum where you learn Rust, security engineering, and agentic AI by building real features. See the full program → [LEARNING_PROGRAM.md](LEARNING_PROGRAM.md)

### 2. Open Contribution (unstructured, anytime)
Pick any open issue, submit a PR. No commitment required.

---

## Quick start (5 minutes)

```bash
# 1. Fork and clone
git clone https://github.com/your-handle/threathunter
cd threathunter

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
│   └── tools.rs         Security tools Claude/AI can call
└── commands/            One file per CLI subcommand
```

---

## Submitting a PR

1. **Open an issue first** for anything beyond a small fix — discuss the approach before writing code
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

### What gets reviewed

- Does it work? (correctness)
- Is it safe? (no panics on malformed input, no unsafe unless necessary)
- Is it readable? (a new contributor should understand it in 5 minutes)
- Does it have tests?

---

## Code style

- Follow the pattern of the file you're editing
- Comments explain **why**, not what — the code shows what
- Error messages should tell the user what to do next, not just what failed
- Severity levels: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO` — be conservative
- Every new detection rule needs a MITRE ATT&CK technique ID

---

## Issue labels

| Label | Meaning |
|---|---|
| `good-first-issue` | Safe starting point, mentor available |
| `learning-track` | Part of the structured curriculum |
| `mentor-review` | PR needs guidance, not just approval |
| `security-logic` | Changes to detection rules — extra scrutiny |
| `ai-agent` | Changes to the agentic AI layer |
| `help-wanted` | Stuck, open to anyone |

---

## Community

**GitHub Discussions** is the main community space:

| Category | Purpose |
|---|---|
| Introductions | Say hello when you join |
| Daily Log | "Today I learned..." — post anything |
| Stuck | Ask for help, no judgment |
| Showcase | Share your merged PRs |
| Ideas | Features you want to build |

→ [Open a Discussion](../../discussions)

---

## Learning Program quick join

If you want structured guidance:

1. Open a Discussion in **Introductions** — say hi and pick your track
2. Track A (Rust + CLI) / Track B (Security) / Track C (Agentic AI)
3. Claim an issue labelled `good-first-issue` or `learning-track`
4. Submit your first PR

Full curriculum → [LEARNING_PROGRAM.md](LEARNING_PROGRAM.md)

---

## Questions?

Open a **Discussions → Stuck** post. PRs and issues are not the right place for questions — Discussions keeps the help searchable for everyone who comes after you.
