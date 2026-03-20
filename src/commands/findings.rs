// ============================================================
// src/commands/findings.rs
// Implements: threathunter findings [flags]
//
// Queries the local SQLite database for persisted findings
// from previous agent hunts.
//
// Usage:
//   threathunter findings
//   threathunter findings --severity HIGH
//   threathunter findings --since 7d
//   threathunter findings --hunt <hunt-id>
//   threathunter findings --json
//   threathunter hunts
// ============================================================

use crate::db::{self, FindingFilter};
use anyhow::Result;
use clap::Args;
use colored::*;

#[derive(Args)]
pub struct FindingsArgs {
    /// Minimum severity to show: CRITICAL | HIGH | MEDIUM | LOW
    #[arg(short, long, default_value = "LOW")]
    severity: String,

    /// Time window: 24h | 7d | 30d | all
    #[arg(long, default_value = "7d")]
    since: String,

    /// Filter to a specific hunt ID
    #[arg(long)]
    hunt: Option<String>,

    /// Output as JSON instead of a table
    #[arg(long)]
    json: bool,

    /// Maximum number of findings to return
    #[arg(short, long, default_value = "100")]
    limit: i64,
}

pub fn run(args: FindingsArgs) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: FindingsArgs) -> Result<()> {
    let pool = db::init().await?;

    let since = parse_since(&args.since);

    let filter = FindingFilter {
        min_severity: Some(args.severity.to_uppercase()),
        hunt_id:      args.hunt,
        since:        Some(since),
        limit:        args.limit,
    };

    let findings = db::list_findings(&pool, &filter).await?;

    if findings.is_empty() {
        println!("{} No findings match the filter.", "[INFO]".dimmed());
        return Ok(());
    }

    if args.json {
        // JSON output for piping to jq, SIEM, etc.
        let json: Vec<serde_json::Value> = findings.iter().map(|f| serde_json::json!({
            "id":           f.id,
            "hunt_id":      f.hunt_id,
            "discovered_at":f.discovered_at,
            "severity":     f.severity,
            "category":     f.category,
            "description":  f.description,
            "detail":       f.detail,
            "mitre_id":     f.mitre_id,
            "mitre_name":   f.mitre_name,
        })).collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // ── Table output ─────────────────────────────────────────────────────────
    println!(
        "\n{} {} finding(s)\n",
        "[FINDINGS]".bright_red().bold(),
        findings.len()
    );

    // Header
    println!(
        "  {:<10} {:<12} {:<12} {:<36} {:<12}",
        "SEVERITY".bold(),
        "CATEGORY".bold(),
        "MITRE".bold(),
        "DESCRIPTION".bold(),
        "DETAIL".bold(),
    );
    println!("  {}", "─".repeat(90).dimmed());

    for f in &findings {
        let severity_colored = match f.severity.as_str() {
            "CRITICAL" => f.severity.bright_red().bold(),
            "HIGH"     => f.severity.red().bold(),
            "MEDIUM"   => f.severity.yellow().bold(),
            "LOW"      => f.severity.cyan().normal(),
            _          => f.severity.dimmed(),
        };

        let mitre = f.mitre_id.as_deref().unwrap_or("—");
        let desc  = truncate(&f.description, 36);
        let detail = truncate(&f.detail, 30);

        println!(
            "  {:<10} {:<12} {:<12} {:<36} {}",
            severity_colored,
            f.category.dimmed(),
            mitre.dimmed(),
            desc,
            detail.dimmed(),
        );
    }

    println!("\n  {}", format!("Hunt IDs: use --hunt <id> to filter").dimmed());

    Ok(())
}

// ── Hunts subcommand ──────────────────────────────────────────────────────────

#[derive(Args)]
pub struct HuntsArgs {
    /// Number of recent hunts to show
    #[arg(short, long, default_value = "20")]
    limit: i64,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

pub fn run_hunts(args: HuntsArgs) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_hunts_async(args))
}

async fn run_hunts_async(args: HuntsArgs) -> Result<()> {
    let pool  = db::init().await?;
    let hunts = db::list_hunts(&pool, args.limit).await?;

    if hunts.is_empty() {
        println!("{} No hunts recorded yet. Run: threathunter agent --target /", "[INFO]".dimmed());
        return Ok(());
    }

    if args.json {
        let json: Vec<serde_json::Value> = hunts.iter().map(|h| serde_json::json!({
            "id":            h.id,
            "target":        h.target,
            "started_at":    h.started_at,
            "completed_at":  h.completed_at,
            "risk_level":    h.risk_level,
            "risk_score":    h.risk_score,
            "finding_count": h.finding_count,
        })).collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("\n{} {} hunt(s)\n", "[HUNTS]".bright_red().bold(), hunts.len());
    println!(
        "  {:<38} {:<22} {:<10} {:<8} {}",
        "ID".bold(), "COMPLETED".bold(), "RISK".bold(), "FINDINGS".bold(), "TARGET".bold()
    );
    println!("  {}", "─".repeat(100).dimmed());

    for h in &hunts {
        let risk = h.risk_level.as_deref().unwrap_or("—");
        let risk_colored = match risk {
            "CRITICAL" => risk.bright_red().bold(),
            "HIGH"     => risk.red().bold(),
            "MEDIUM"   => risk.yellow().bold(),
            "LOW"      => risk.cyan().normal(),
            _          => risk.dimmed(),
        };
        let completed = h.completed_at.as_deref().unwrap_or("—");
        let count     = h.finding_count.unwrap_or(0);
        println!(
            "  {:<38} {:<22} {:<10} {:<8} {}",
            h.id.dimmed(),
            truncate(completed, 22).dimmed(),
            risk_colored,
            count,
            truncate(&h.target, 30).dimmed(),
        );
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

/// Parse human-readable time window into an ISO-8601 lower bound.
fn parse_since(s: &str) -> String {
    use chrono::{Duration, Utc};
    let now = Utc::now();
    let dt = match s {
        "24h"  => now - Duration::hours(24),
        "7d"   => now - Duration::days(7),
        "30d"  => now - Duration::days(30),
        "all"  => chrono::DateTime::UNIX_EPOCH.into(),
        _      => now - Duration::days(7),
    };
    dt.to_rfc3339()
}
