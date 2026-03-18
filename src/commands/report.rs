// ============================================================
// src/commands/report.rs
// Implements: threathunter report [flags]
//
// Orchestrates every engine in sequence:
//   1. Scan a path   → filesystem findings
//   2. Scan /proc/   → process findings
//   3. Scan /proc/net → network findings
//   4. Map everything to MITRE ATT&CK via mitre.rs
//   5. Calculate a risk score
//   6. Print or save the report
//
// Usage:
//   threathunter report
//   threathunter report --path /home --output json > report.json
//   threathunter report --no-network --no-process
// ============================================================

use crate::commands::mitre;
use crate::ioc::Severity;
use crate::report::{Finding, ThreatReport};
use crate::{network, process as proc_engine, scanner};
use anyhow::Result;
use clap::Args;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

// ---- CLI ARGS ----
#[derive(Args)]
pub struct ReportArgs {
    /// Root path for filesystem scan
    #[arg(short, long, default_value = ".")]
    path: String,

    /// Skip the filesystem scan
    #[arg(long)]
    no_scan: bool,

    /// Skip the process scan
    #[arg(long)]
    no_process: bool,

    /// Skip the network scan
    #[arg(long)]
    no_network: bool,

    /// Only include Medium severity and above in the report
    #[arg(short = 'S', long)]
    significant_only: bool,

    /// Save report JSON to this file path
    #[arg(long)]
    save: Option<String>,

    /// Output format: summary, json, full
    #[arg(short, long, default_value = "summary")]
    output: String,
}

pub fn run(args: ReportArgs) -> Result<()> {
    println!(
        "{} Starting full threat assessment...\n",
        "[REPORT]".bright_white().on_red().bold()
    );

    // Resolve hostname for the report header
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    // Create an empty report — we'll fill it as each engine runs
    let mut report = ThreatReport::new(hostname.clone());

    // ================================================================
    // PHASE 1 — FILESYSTEM SCAN
    // ================================================================
    if !args.no_scan {
        println!("{} Phase 1/3 — Filesystem scan: {}", "[1]".cyan().bold(), args.path.yellow());

        let path = std::path::Path::new(&args.path);
        if !path.exists() {
            eprintln!("  {} Path not found, skipping: {}", "⚠".yellow(), args.path);
        } else {
            let entries: Vec<_> = WalkDir::new(path)
                .max_depth(15)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .collect();

            let pb = make_progress_bar(entries.len() as u64);

            for entry in &entries {
                let ep = entry.path();
                pb.inc(1);
                pb.set_message(
                    ep.file_name()
                      .unwrap_or_default()
                      .to_string_lossy()
                      .chars()
                      .take(35)
                      .collect::<String>(),
                );

                // Skip large files (>10MB) and uninteresting extensions
                if let Ok(meta) = ep.metadata() {
                    if meta.len() > 10 * 1_048_576 { continue; }
                }
                if !scanner::is_suspicious_extension(ep) { continue; }

                if let Ok(result) = scanner::scan_file(ep) {
                    if result.severity == Severity::Info { continue; }

                    let mut desc_parts = result.anomalies.clone();
                    for (_, _, d) in &result.pattern_hits { desc_parts.push(d.clone()); }
                    if let Some(ref m) = result.ioc_match {
                        desc_parts.push(format!("IOC: {}", m.description));
                    }

                    let description = if desc_parts.is_empty() {
                        "Suspicious file".to_string()
                    } else {
                        desc_parts.join("; ")
                    };

                    let all_text   = desc_parts.join(" ");
                    let techniques = mitre::map_finding(&all_text);
                    let mitre_id   = techniques.first().map(|t| t.id.to_string());
                    let mitre_name = techniques.first().map(|t| t.name.to_string());

                    report.add_finding("Filesystem", Finding {
                        severity:    format!("{}", result.severity),
                        category:    "filesystem".to_string(),
                        description,
                        detail:      result.path.clone(),
                        mitre_id,
                        mitre_name,
                    });
                }
            }

            pb.finish_and_clear();
            println!(
                "  {} Filesystem scan complete — {} findings\n",
                "✓".green(),
                report.sections.iter()
                    .find(|s| s.title == "Filesystem")
                    .map(|s| s.findings.len())
                    .unwrap_or(0)
            );
        }
    }

    // ================================================================
    // PHASE 2 — PROCESS SCAN
    // ================================================================
    if !args.no_process {
        println!("{} Phase 2/3 — Process scan", "[2]".cyan().bold());

        match proc_engine::list_processes() {
            Err(e) => {
                eprintln!("  {} Process scan failed: {} (not Linux?)", "⚠".yellow(), e);
            }
            Ok(procs) => {
                let suspicious: Vec<_> = procs.into_iter().filter(|p| p.suspicious).collect();

                for p in &suspicious {
                    if args.significant_only && p.severity == Severity::Low { continue; }

                    let description = if p.anomalies.is_empty() {
                        format!("Suspicious process: {}", p.name)
                    } else {
                        p.anomalies.join("; ")
                    };

                    let all_text   = p.anomalies.join(" ");
                    let techniques = mitre::map_finding(&all_text);
                    let mitre_id   = techniques.first().map(|t| t.id.to_string());
                    let mitre_name = techniques.first().map(|t| t.name.to_string());

                    report.add_finding("Processes", Finding {
                        severity:    format!("{}", p.severity),
                        category:    "process".to_string(),
                        description,
                        detail: format!(
                            "PID:{} name:{} uid:{} exe:{}",
                            p.pid, p.name, p.uid, p.exe_path
                        ),
                        mitre_id,
                        mitre_name,
                    });
                }

                println!(
                    "  {} Process scan complete — {} findings\n",
                    "✓".green(),
                    report.sections.iter()
                        .find(|s| s.title == "Processes")
                        .map(|s| s.findings.len())
                        .unwrap_or(0)
                );
            }
        }
    }

    // ================================================================
    // PHASE 3 — NETWORK SCAN
    // ================================================================
    if !args.no_network {
        println!("{} Phase 3/3 — Network scan", "[3]".cyan().bold());

        match network::get_connections() {
            Err(e) => {
                eprintln!("  {} Network scan failed: {}", "⚠".yellow(), e);
            }
            Ok(conns) => {
                let suspicious: Vec<_> = conns.into_iter().filter(|c| c.suspicious).collect();

                for c in &suspicious {
                    if args.significant_only && c.severity == Severity::Low { continue; }

                    let description = c.reason
                        .clone()
                        .unwrap_or_else(|| "Suspicious connection".to_string());

                    let techniques = mitre::map_finding(&description);
                    let mitre_id   = techniques.first().map(|t| t.id.to_string());
                    let mitre_name = techniques.first().map(|t| t.name.to_string());

                    report.add_finding("Network", Finding {
                        severity:    format!("{}", c.severity),
                        category:    "network".to_string(),
                        description,
                        detail: format!(
                            "{} {} → {} [{}]",
                            c.protocol, c.local_addr, c.remote_addr, c.state
                        ),
                        mitre_id,
                        mitre_name,
                    });
                }

                println!(
                    "  {} Network scan complete — {} findings\n",
                    "✓".green(),
                    report.sections.iter()
                        .find(|s| s.title == "Network")
                        .map(|s| s.findings.len())
                        .unwrap_or(0)
                );
            }
        }
    }

    // ================================================================
    // CALCULATE FINAL RISK SCORE
    // ================================================================
    report.calculate_risk();

    // ================================================================
    // OUTPUT
    // ================================================================
    match args.output.as_str() {

        "json" => {
            let json = serde_json::to_string_pretty(&report)?;
            if let Some(ref save_path) = args.save {
                std::fs::write(save_path, &json)?;
                println!("{} Report saved to {}", "[✓]".green(), save_path.yellow());
            }
            println!("{}", json);
        }

        "full" => {
            print_banner(&report);
            for section in &report.sections {
                println!("\n{} {}", "▶".bright_cyan(), section.title.white().bold());
                println!("{}", "─".repeat(80).dimmed());
                for f in &section.findings {
                    print_finding_full(f);
                }
            }
            maybe_save_json(&report, &args.save)?;
        }

        _ => {
            // Default: "summary" — banner + per-section counts + top 10 findings
            print_banner(&report);
            print_section_summary(&report);
            print_top_findings(&report, 10);
            maybe_save_json(&report, &args.save)?;
        }
    }

    Ok(())
}

// ================================================================
// PRINT HELPERS
// ================================================================

fn print_banner(r: &ThreatReport) {
    println!();
    println!("{}", "═".repeat(70).dimmed());
    println!("  {}  —  Threat Report", "ThreatHunter".bright_red().bold());
    println!("  Host: {}   Generated: {}", r.hostname.cyan(), r.generated_at.dimmed());
    println!("{}", "═".repeat(70).dimmed());

    let risk_colored = match r.risk_level.as_str() {
        "CRITICAL" => r.risk_level.red().bold().to_string(),
        "HIGH"     => r.risk_level.truecolor(255, 140, 0).bold().to_string(),
        "MEDIUM"   => r.risk_level.yellow().bold().to_string(),
        "LOW"      => r.risk_level.blue().to_string(),
        _          => r.risk_level.green().to_string(),
    };

    println!(
        "\n  Risk Level: {}   Score: {}   Total Findings: {}\n",
        risk_colored,
        r.risk_score.to_string().white().bold(),
        r.total_findings.to_string().white().bold(),
    );
    println!(
        "  {} Critical   {} High   {} Medium   {} Low",
        r.critical_count.to_string().red().bold(),
        r.high_count.to_string().truecolor(255, 140, 0).bold(),
        r.medium_count.to_string().yellow().bold(),
        r.low_count.to_string().blue(),
    );
    println!("\n{}", "─".repeat(70).dimmed());
}

fn print_section_summary(r: &ThreatReport) {
    println!("\n{}\n", "Section Summary".white().bold());
    for section in &r.sections {
        let critical = section.findings.iter().filter(|f| f.severity == "CRITICAL").count();
        let high     = section.findings.iter().filter(|f| f.severity == "HIGH").count();
        println!(
            "  {:15}  {} findings   ({} critical, {} high)",
            section.title.cyan().bold(),
            section.findings.len().to_string().white(),
            critical.to_string().red(),
            high.to_string().truecolor(255, 140, 0),
        );
    }
    println!();
}

fn print_top_findings(r: &ThreatReport, n: usize) {
    let mut all: Vec<&Finding> = r.sections
        .iter()
        .flat_map(|s| s.findings.iter())
        .collect();

    all.sort_by_key(|f| match f.severity.as_str() {
        "CRITICAL" => 0u8,
        "HIGH"     => 1,
        "MEDIUM"   => 2,
        "LOW"      => 3,
        _          => 4,
    });

    let top: Vec<_> = all.into_iter().take(n).collect();
    if top.is_empty() { return; }

    println!("{}\n", format!("Top {} Findings", top.len()).white().bold());
    for f in &top { print_finding_full(f); }
}

fn print_finding_full(f: &Finding) {
    let sev = match f.severity.as_str() {
        "CRITICAL" => format!("[{}]", f.severity).red().bold().to_string(),
        "HIGH"     => format!("[{}]", f.severity).truecolor(255, 140, 0).bold().to_string(),
        "MEDIUM"   => format!("[{}]", f.severity).yellow().to_string(),
        "LOW"      => format!("[{}]", f.severity).blue().to_string(),
        _          => format!("[{}]", f.severity).dimmed().to_string(),
    };
    println!("  {}  {}", sev, f.description.white());
    println!("      Detail:   {}", f.detail.dimmed());
    if let (Some(ref id), Some(ref name)) = (&f.mitre_id, &f.mitre_name) {
        println!("      MITRE:    {} — {}", id.bright_red(), name.yellow());
    }
    println!();
}

fn maybe_save_json(r: &ThreatReport, save_path: &Option<String>) -> Result<()> {
    if let Some(ref path) = save_path {
        let json = serde_json::to_string_pretty(r)?;
        std::fs::write(path, &json)?;
        println!("\n{} Report saved → {}", "[✓]".green().bold(), path.yellow());
    }
    Ok(())
}

fn make_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.cyan} [{bar:40.cyan/gray}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    pb
}
