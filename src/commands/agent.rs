// ============================================================
// src/commands/agent.rs
// Implements: threathunter agent [flags]
//
// Usage:
//   # Claude (default)
//   export ANTHROPIC_API_KEY=sk-ant-...
//   threathunter agent --target /tmp
//
//   # OpenAI
//   export OPENAI_API_KEY=sk-...
//   threathunter agent --target /tmp --provider openai --model gpt-4o
//
//   # Groq (fast, free tier available)
//   export GROQ_API_KEY=gsk_...
//   threathunter agent --target /tmp --provider groq
//
//   # Ollama (fully local, no API key)
//   threathunter agent --target /tmp --provider ollama --model llama3.2
//
//   # Any OpenAI-compatible endpoint
//   threathunter agent --target /tmp --provider openai \
//     --api-url https://my-endpoint/v1/chat/completions \
//     --api-key <key>
// ============================================================

use crate::agent::r#loop::run_investigation;
use crate::agent::providers;
use crate::db;
use anyhow::Result;
use clap::Args;
use colored::*;

#[derive(Args)]
pub struct AgentArgs {
    /// Filesystem path to investigate
    #[arg(short, long, default_value = ".")]
    target: String,

    /// AI provider: claude | openai | groq | ollama
    #[arg(long, default_value = "claude")]
    provider: String,

    /// Model override (each provider has a sensible default)
    ///   Claude default:  claude-sonnet-4-6
    ///   OpenAI default:  gpt-4o
    ///   Groq default:    llama-3.3-70b-versatile
    ///   Ollama default:  llama3.2
    #[arg(long)]
    model: Option<String>,

    /// Custom API endpoint URL (for Ollama, Azure, or any OpenAI-compatible API)
    #[arg(long)]
    api_url: Option<String>,

    /// API key (overrides env var — ANTHROPIC_API_KEY / OPENAI_API_KEY / GROQ_API_KEY)
    #[arg(long, hide_env_values = true)]
    api_key: Option<String>,

    /// Maximum number of tool-call rounds before forcing a final report
    #[arg(short, long, default_value = "10")]
    max_iterations: usize,

    /// Print each tool call and result preview as the agent works
    #[arg(short, long)]
    verbose: bool,

    /// Save the final report to a file (Markdown)
    #[arg(short, long)]
    save: Option<String>,

    /// Associate this hunt with a campaign ID
    #[arg(long)]
    campaign: Option<String>,

    /// Do not save findings to the database
    #[arg(long)]
    no_persist: bool,
}

pub fn run(args: AgentArgs) -> Result<()> {
    // ── Resolve provider config ───────────────────────────────────────────────
    let config = providers::resolve_config(
        &args.provider,
        args.model.as_deref(),
        args.api_key.as_deref(),
        args.api_url.as_deref(),
    )?;

    let provider = providers::build(&config)?;

    println!(
        "{} Agentic threat investigation\n  Target:   {}\n  Provider: {}\n  Max iterations: {}\n",
        "[AGENT]".bright_red().bold(),
        args.target.yellow(),
        provider.display_name().cyan(),
        args.max_iterations,
    );

    let runtime = tokio::runtime::Runtime::new()?;

    runtime.block_on(async {
        let started_at = chrono::Utc::now().to_rfc3339();

        let (report, findings) = run_investigation(
            provider,
            &args.target,
            args.max_iterations,
            args.verbose,
        ).await?;

        // ── Print the report ──────────────────────────────────────────────────
        println!("\n{}", "═".repeat(70).dimmed());
        println!("{}", "  AGENT INVESTIGATION REPORT".bright_red().bold());
        println!("{}\n", "═".repeat(70).dimmed());
        println!("{}", report);

        // ── Optionally save to file ───────────────────────────────────────────
        if let Some(ref path) = args.save {
            std::fs::write(path, &report)?;
            println!(
                "\n{} Report saved → {}",
                "[✓]".green().bold(),
                path.yellow()
            );
        }

        // ── Persist to database ───────────────────────────────────────────────
        if !args.no_persist {
            match db::init().await {
                Err(e) => {
                    eprintln!("{} Could not open database: {}", "[WARN]".yellow().bold(), e);
                }
                Ok(pool) => {
                    let risk_level = derive_risk_level(&findings);
                    let risk_score = derive_risk_score(&findings);

                    let hunt = db::HuntRecord::new(
                        &args.target,
                        args.campaign.clone(),
                        &risk_level,
                        risk_score,
                        findings.len() as i64,
                        started_at,
                        report.clone(),
                    );

                    if let Err(e) = db::save_hunt(&pool, &hunt).await {
                        eprintln!("{} Could not save hunt: {}", "[WARN]".yellow().bold(), e);
                    } else if let Err(e) = db::save_findings(
                        &pool,
                        &hunt.id,
                        args.campaign.as_deref(),
                        &findings,
                    ).await {
                        eprintln!("{} Could not save findings: {}", "[WARN]".yellow().bold(), e);
                    } else {
                        println!(
                            "\n{} {} finding(s) persisted → {}",
                            "[✓]".green().bold(),
                            findings.len(),
                            db::db_path()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|_| "~/.config/threathunter/db.sqlite".into())
                                .yellow()
                        );
                    }
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn derive_risk_level(findings: &[crate::report::Finding]) -> String {
    if findings.iter().any(|f| f.severity == "CRITICAL") { return "CRITICAL".into(); }
    if findings.iter().any(|f| f.severity == "HIGH")     { return "HIGH".into(); }
    if findings.iter().any(|f| f.severity == "MEDIUM")   { return "MEDIUM".into(); }
    if findings.iter().any(|f| f.severity == "LOW")      { return "LOW".into(); }
    "CLEAN".into()
}

fn derive_risk_score(findings: &[crate::report::Finding]) -> i64 {
    findings.iter().map(|f| match f.severity.as_str() {
        "CRITICAL" => 40,
        "HIGH"     => 15,
        "MEDIUM"   =>  5,
        "LOW"      =>  1,
        _          =>  0,
    }).sum()
}
