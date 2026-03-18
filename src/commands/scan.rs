// ============================================================
// src/commands/scan.rs
// Implements: threathunter scan [path] [flags]
// Calls scanner.rs to analyse files, then formats + prints results
// ============================================================

use crate::ioc::Severity;
use crate::scanner;
use anyhow::Result;
use clap::Args;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use tabled::{Table, Tabled};
use walkdir::WalkDir;

// clap's #[derive(Args)] turns these fields into CLI flags automatically
// Run `threathunter scan --help` to see them
#[derive(Args)]
pub struct ScanArgs {
    /// Directory or file to scan
    #[arg(default_value = ".")]
    path: String,

    /// Walk subdirectories
    #[arg(short, long)]
    recursive: bool,

    /// Only print findings with Medium severity or above
    #[arg(short = 'S', long)]
    suspicious_only: bool,

    /// Scan ALL file types, not just executables and scripts
    #[arg(short, long)]
    all: bool,

    /// Max file size to hash in MB (skip huge files)
    #[arg(short, long, default_value = "10")]
    max_size: u64,

    /// Output format: table, json, plain
    #[arg(short, long, default_value = "table")]
    output: String,
}

// #[derive(Tabled)] makes tabled::Table print this struct as a table row
#[derive(Tabled)]
struct ScanRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "SHA-256 (16)")]
    hash: String,
    #[tabled(rename = "Finding")]
    finding: String,
}

// This is called from main.rs when the user runs `threathunter scan`
pub fn run(args: ScanArgs) -> Result<()> {
    println!(
        "{} {}",
        "[SCAN]".bright_cyan().bold(),
        args.path.yellow()
    );

    let path = std::path::Path::new(&args.path);
    if !path.exists() {
        return Err(anyhow::anyhow!("Path not found: {}", args.path));
    }

    let max_bytes = args.max_size * 1_048_576;
    let max_depth = if args.recursive { 20 } else { 1 };

    // WalkDir gives us every file under the path
    let entries: Vec<_> = WalkDir::new(path)
        .max_depth(max_depth)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())               // skip unreadable dirs
        .filter(|e| e.file_type().is_file())   // directories don't have hashes
        .collect();

    // Show a progress bar — scanning 10,000 files takes a while
    let pb = ProgressBar::new(entries.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.red} [{bar:40.red/gray}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );

    let mut results = Vec::new();
    let mut skipped = 0usize;

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

        // Skip if file is too large
        if let Ok(meta) = ep.metadata() {
            if meta.len() > max_bytes { skipped += 1; continue; }
        }

        // Skip boring extensions unless --all is set
        if !args.all && !scanner::is_suspicious_extension(ep) {
            skipped += 1;
            continue;
        }

        match scanner::scan_file(ep) {
            Ok(result) => {
                if !args.suspicious_only || result.severity != Severity::Info {
                    results.push(result);
                }
            }
            Err(_) => { skipped += 1; }
        }
    }

    pb.finish_and_clear();

    // ---- SUMMARY LINE ----
    let critical = results.iter().filter(|r| r.severity == Severity::Critical).count();
    let high     = results.iter().filter(|r| r.severity == Severity::High).count();
    let medium   = results.iter().filter(|r| r.severity == Severity::Medium).count();

    println!(
        "\n{} scanned {} files | skipped {} | {} critical  {} high  {} medium\n",
        "[DONE]".bright_cyan().bold(),
        results.len() + skipped,
        skipped,
        critical.to_string().red().bold(),
        high.to_string().truecolor(255, 140, 0).bold(),
        medium.to_string().yellow().bold(),
    );

    if results.is_empty() {
        println!("{} No suspicious files found.", "[✓]".green().bold());
        return Ok(());
    }

    // ---- OUTPUT ----
    match args.output.as_str() {
        "json" => {
            // serde_json turns your Vec<FileScanResult> into pretty-printed JSON
            // Useful for piping into jq or saving to a file
            let json: Vec<_> = results.iter().map(|r| {
                serde_json::json!({
                    "severity": format!("{}", r.severity),
                    "path":     r.path,
                    "size":     r.size,
                    "sha256":   r.sha256,
                    "md5":      r.md5,
                    "anomalies": r.anomalies,
                    "patterns": r.pattern_hits.iter()
                        .map(|(_, _, d)| d)
                        .collect::<Vec<_>>(),
                    "ioc_match": r.ioc_match.as_ref()
                        .map(|m| &m.description),
                })
            }).collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }

        "plain" => {
            for r in &results {
                println!("[{}] {}  ({})",
                    colorize_severity(&r.severity),
                    r.path,
                    format_bytes(r.size),
                );
                for a in &r.anomalies            { println!("  ⚠  {}", a.yellow()); }
                for (_, _, d) in &r.pattern_hits { println!("  ⚑  {}", d.dimmed()); }
                println!();
            }
        }

        _ => {
            // Default: ASCII table using tabled
            let rows: Vec<ScanRow> = results.iter().map(|r| {
                let mut reasons = r.anomalies.clone();
                for (_, _, d) in &r.pattern_hits { reasons.push(d.clone()); }
                if let Some(m) = &r.ioc_match    { reasons.push(m.description.clone()); }

                ScanRow {
                    severity: format!("{}", r.severity),
                    file:     trunc_left(&r.path, 50),
                    size:     format_bytes(r.size),
                    hash:     format!("{}…", &r.sha256[..16]),
                    finding:  trunc(&reasons.join("; "), 40),
                }
            }).collect();

            // Print with severity coloring per line
            for line in Table::new(rows).to_string().lines() {
                if      line.contains("CRITICAL") { println!("{}", line.red().bold()); }
                else if line.contains("HIGH")     { println!("{}", line.truecolor(255, 140, 0)); }
                else if line.contains("MEDIUM")   { println!("{}", line.yellow()); }
                else                              { println!("{}", line.dimmed()); }
            }
        }
    }

    Ok(())
}

// ---- HELPERS ----

fn format_bytes(b: u64) -> String {
    if b < 1024            { format!("{} B",    b) }
    else if b < 1_048_576 { format!("{:.1} KB", b as f64 / 1024.0) }
    else                   { format!("{:.1} MB", b as f64 / 1_048_576.0) }
}

// Truncate from left — keeps the filename visible at the end of the path
fn trunc_left(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("…{}", &s[s.len() - max + 1..]) }
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max]) }
}

fn colorize_severity(s: &Severity) -> ColoredString {
    match s {
        Severity::Critical => "CRITICAL".red().bold(),
        Severity::High     => "HIGH    ".truecolor(255, 140, 0).bold(),
        Severity::Medium   => "MEDIUM  ".yellow(),
        Severity::Low      => "LOW     ".blue(),
        Severity::Info     => "INFO    ".dimmed(),
    }
}
