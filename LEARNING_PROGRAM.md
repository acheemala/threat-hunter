# ThreatHunter Learning Program

> Learn Rust, Security Engineering, and Agentic AI by building a real open source threat hunting tool — one PR at a time.

**No experience required. No application. No cost. Just show up.**

---

## Join in 3 steps

```
1. Star this repo
2. Open a Discussion → Introductions → say which track you're joining
3. Claim your first issue labelled [learning-track]
```

---

## Pick your track

| Track | Focus | Background needed |
|---|---|---|
| **A — Rust + CLI** | Systems programming, CLI tools | None |
| **B — Security Engineering** | Detection logic, MITRE ATT&CK, IOCs | Curiosity about security |
| **C — Agentic AI** | LLM tool use, multi-provider AI | Any programming background |

You can switch tracks anytime. Most people start on A or B and move into C by Month 4.

---

## Pick your pace

| | 6-Month Fast Track | 12-Month Deep Track |
|---|---|---|
| PR cadence | 1 per week | 1 per 2 weeks |
| Daily time | 1–2 hours | 30–60 minutes |
| Best for | Career switchers, focused learners | Students, working professionals |

Both tracks cover the same content. The 12-month track just breathes more.

---

## Curriculum

### Month 1 — Read the codebase, feel the tool

**Goal:** Understand what ThreatHunter does and where things live.

| Week | What to do | PR to submit |
|---|---|---|
| 1 | Build the project, run every subcommand, read `main.rs` | Fix a comment or typo anywhere |
| 2 | Read `scanner.rs`, run `threathunter scan --path /tmp` | Add one new suspicious file extension to the scanner |
| 3 | Read `process.rs`, run `threathunter process` | Add one new process anomaly detection rule |
| 4 | Read `network.rs`, run `threathunter network` | Add one new known-bad port to network detection |

**Daily habit (15 min):** Run ThreatHunter on your own machine. Notice something. Find where it comes from in the code.

---

### Month 2 — MITRE ATT&CK in real code

**Goal:** Connect real-world attack techniques to detection logic.

| Week | What to do | PR to submit |
|---|---|---|
| 5 | Read https://attack.mitre.org — pick 5 techniques | Add 5 new technique mappings to `commands/mitre.rs` |
| 6 | Find a public CVE, understand the attack chain | Add IOC signatures for it to `ioc.rs` |
| 7 | Study T1055 (Process Injection) deeply | Add 2 new process injection detection patterns |
| 8 | Study T1071 (C2 over HTTP/DNS) | Add 3 new C2 IP ranges or suspicious domain patterns |

**Daily habit (15 min):** Read one MITRE technique page. Ask: does ThreatHunter detect this? If not, can it?

---

### Month 3 — Write real Rust

**Goal:** Go from reading Rust to writing it confidently.

| Week | What to do | PR to submit |
|---|---|---|
| 9  | Learn Rust enums + pattern matching (rust-by-example) | Refactor severity string comparisons into a typed `Severity` enum |
| 10 | Learn Rust error handling (anyhow, thiserror) | Improve one error message to tell the user what to do next |
| 11 | Learn Rust iterators + closures | Refactor one `for` loop to use iterator chains |
| 12 | Learn Rust tests (`#[cfg(test)]`) | Add 3 unit tests to any module |

**Daily habit (20 min):** One [Rustlings](https://github.com/rust-lang/rustlings) exercise OR one page of [Rust by Example](https://doc.rust-lang.org/rust-by-example/).

---

### Month 4 — Agentic AI engine

**Goal:** Understand how autonomous AI agents actually work — and extend them.

| Week | What to do | PR to submit |
|---|---|---|
| 13 | Read `agent/loop.rs` end-to-end, trace one full investigation | Improve the system prompt with a new investigation instruction |
| 14 | Read `agent/tools.rs`, understand all 6 tools | Add a new agent tool: `check_crontab` (reads /etc/cron.d and crontabs) |
| 15 | Run `threathunter agent --verbose`, trace the AI's decisions | Add timing logs — show how long each tool call takes |
| 16 | Read `agent/providers/`, understand the multi-provider design | Add a 4th provider: Together AI (OpenAI-compatible endpoint) |

**Daily habit (20 min):** Run `threathunter agent --verbose` on a different path each day. Read the tool calls. Ask: why did the AI choose that tool?

---

### Month 5 — Own a feature

**Goal:** Design and ship something end-to-end, independently.

Pick one feature from the list below, open an issue, design it in the comments, get feedback, then build and ship it.

| Feature | What it does | Difficulty |
|---|---|---|
| `--dry-run` flag for agent | Show what the AI would investigate without executing | Medium |
| YARA rule support | Load `.yar` files and scan files against them | Medium |
| Slack / webhook alert | POST to a webhook on CRITICAL findings | Medium |
| `threathunter diff` | Compare two hunt reports, show what changed | Hard |
| Log file analysis tool | New agent tool: scan syslog/auth.log for attack patterns | Hard |
| STIX 2.1 export | Export findings as a STIX bundle for SIEM ingestion | Hard |
| Live watch mode | Re-run scan every N minutes, alert on new findings | Hard |

**Process:**
1. Open a GitHub Issue — describe the feature and your design approach
2. Get one approval in the comments before writing code
3. Submit a draft PR early — get feedback while building
4. Final PR with tests

---

### Month 6 — Teach someone else

**Goal:** You understand something when you can explain it clearly.

| Week | Task |
|---|---|
| 21 | Write a blog post or LinkedIn post about what you built this program |
| 22 | Review a PR from a Month 1 learner — leave specific, actionable feedback |
| 23 | Record a 5-minute screen recording demo of your Month 5 feature |
| 24 | Open an issue for the next feature you want to build — become a mentor |

---

## Daily rhythm (realistic)

```
Monday     Read    one source file or one MITRE page        20 min
Tuesday    Code    work on your current PR                  45 min
Wednesday  Run     use the tool, find something to improve  20 min
Thursday   Code    continue PR or review someone else's     45 min
Friday     Share   post one thing in GitHub Discussions     10 min
Weekend    Optional — explore, break things, ask questions
```

**Total: ~2.5 hours/week.** Designed to fit alongside a job or degree.

---

## What you'll have after 6 months

- Merged PRs on a real, live open source security tool
- Working knowledge of Rust (systems-level)
- MITRE ATT&CK applied in production detection code
- Hands-on experience with agentic AI (tool calling, multi-provider)
- A network of people learning the same stack

---

## Mentor structure

Every learner gets:
- **Issue support** — maintainers respond to questions on `learning-track` issues within 48 hours
- **PR feedback** — every PR tagged `mentor-review` gets line-by-line feedback
- **Discussions** — `#stuck` channel, no judgment, answer within 24 hours

You become a mentor automatically when you start reviewing Month 1 PRs in Month 6.

---

## Ground rules

1. **One PR at a time** — finish before starting the next
2. **Ask early** — open a Discussion before spending 3 hours going in the wrong direction
3. **Review others** — the fastest way to learn is to read other people's code
4. **No silent drops** — if life gets busy, just post in `#daily-log` — no pressure, no judgment
5. **Credit your sources** — if you used a reference, link it in the PR description

---

## Ready?

1. **Star the repo**
2. **Open a Discussion → Introductions** — say which track (A/B/C) and pace (6 or 12 month)
3. **Claim your first issue** labelled `good-first-issue`

See you in the PRs.
