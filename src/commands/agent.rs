// ============================================================
// src/commands/agent.rs
// Implements: threathunter agent [flags]
//
// This is the entry point for the agentic AI investigation.
// It reads the API key, calls the async loop, and prints the report.
//
// Usage:
//   export ANTHROPIC_API_KEY=sk-ant-...
//   threathunter agent --target /home
//   threathunter agent --target /tmp --verbose --max-iterations 15
//   threathunter agent --target / --save report.md
// ============================================================

use crate::agent::r#loop::run_investigation;
use anyhow::{anyhow, Result};
use clap::Args;
use colored::*;

// ---- CLI ARGS ----
#[derive(Args)]
pub struct AgentArgs {
    /// Filesystem path to investigate (the AI decides what to scan within it)
    #[arg(short, long, default_value = ".")]
    target: String,

    /// Maximum number of tool-call rounds before forcing a final report
    #[arg(short, long, default_value = "10")]
    max_iterations: usize,

    /// Print each tool call and result preview as the agent works
    #[arg(short, long)]
    verbose: bool,

    /// Save the final report to a file (Markdown)
    #[arg(short, long)]
    save: Option<String>,

    /// Override the API key (default: reads ANTHROPIC_API_KEY env var)
    #[arg(long, env = "ANTHROPIC_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

pub fn run(args: AgentArgs) -> Result<()> {
    // ── API key resolution ────────────────────────────────────────────────────
    // Priority: --api-key flag > ANTHROPIC_API_KEY env var
    // We never hard-code keys. hide_env_values = true prevents the key from
    // appearing in --help output.
    let api_key = args.api_key
        .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
        .ok_or_else(|| anyhow!(
            "No API key found. Set ANTHROPIC_API_KEY or pass --api-key.\n\
             Get your key at: https://console.anthropic.com/"
        ))?;

    println!(
        "{} Agentic threat investigation\n  Target: {}\n  Model:  claude-sonnet-4-6\n  Max iterations: {}\n",
        "[AGENT]".bright_red().bold(),
        args.target.yellow(),
        args.max_iterations,
    );

    // ── Run the async agentic loop ────────────────────────────────────────────
    // We use tokio::runtime::Runtime::block_on to bridge sync main() into async.
    // Only this command needs async — all other commands remain sync.
    // Using block_on instead of #[tokio::main] keeps main.rs clean.
    let runtime = tokio::runtime::Runtime::new()?;

    let report = runtime.block_on(run_investigation(
        &api_key,
        &args.target,
        args.max_iterations,
        args.verbose,
    ))?;

    // ── Print the report ──────────────────────────────────────────────────────
    println!("\n{}", "═".repeat(70).dimmed());
    println!("{}", "  AGENT INVESTIGATION REPORT".bright_red().bold());
    println!("{}\n", "═".repeat(70).dimmed());
    println!("{}", report);

    // ── Optionally save to file ───────────────────────────────────────────────
    if let Some(ref path) = args.save {
        std::fs::write(path, &report)?;
        println!(
            "\n{} Report saved → {}",
            "[✓]".green().bold(),
            path.yellow()
        );
    }

    Ok(())
}
