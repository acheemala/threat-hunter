// ============================================================
// src/commands/siem.rs
// Implements: threathunter siem --file /var/log/auth.log --match "Failed"
//             threathunter siem --dir /var/log --ioc --last 1h
//
// This is the mini-SIEM. It reads log files line by line,
// filters by keyword/regex/time, and flags IOC matches.
// ============================================================

use crate::ioc::{self, Severity};
use anyhow::Result;
use chrono::{DateTime, Duration, Local};
use clap::Args;
use colored::*;
use regex::Regex;
use std::fs;
use std::io::{BufRead, BufReader};
use walkdir::WalkDir;

#[derive(Args)]
pub struct SiemArgs {
    /// Single log file to query
    #[arg(short, long)]
    file: Option<String>,

    /// Directory — scans all .log files recursively
    #[arg(short, long)]
    dir: Option<String>,

    /// Keyword or regex to match
    #[arg(short, long)]
    pattern: Option<String>,

    /// Only show lines that contain IOC matches (IPs, hashes, domains)
    #[arg(long)]
    ioc: bool,

    /// Only show lines matching MITRE ATT&CK patterns
    #[arg(long)]
    mitre: bool,

    /// Show logs from the last N hours (e.g. --last 2)
    #[arg(long)]
    last: Option<u32>,

    /// Show logs after this timestamp (RFC3339 or YYYY-MM-DD)
    #[arg(long)]
    since: Option<String>,

    /// Max lines to read per file
    #[arg(long, default_value = "50000")]
    limit: usize,

    /// Output format: table, json, plain
    #[arg(short, long, default_value = "plain")]
    output: String,
}

// One log line that matched our filters
#[derive(Debug, serde::Serialize)]
pub struct LogHit {
    pub file:     String,
    pub line_num: usize,
    pub line:     String,
    pub severity: Severity,
    pub reason:   String,
}

pub fn run(args: SiemArgs) -> Result<()> {
    println!("{} Starting log analysis...\n", "[SIEM]".bright_yellow().bold());

    // Collect all log files to query
    let mut log_files: Vec<String> = Vec::new();

    if let Some(ref f) = args.file {
        log_files.push(f.clone());
    }

    if let Some(ref dir) = args.dir {
        // Walk the directory looking for .log, .txt, syslog, auth.log, etc.
        for entry in WalkDir::new(dir)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            // Include common log file patterns
            if name.ends_with(".log")
                || name.ends_with(".txt")
                || name == "syslog"
                || name == "auth"
                || name == "messages"
            {
                log_files.push(entry.path().to_string_lossy().to_string());
            }
        }
    }

    if log_files.is_empty() {
        return Err(anyhow::anyhow!("No log files specified. Use --file or --dir"));
    }

    // Build a time filter if --last or --since was given
    let since_time: Option<DateTime<Local>> = if let Some(hours) = args.last {
        Some(Local::now() - Duration::hours(hours as i64))
    } else if let Some(ref since_str) = args.since {
        // Try to parse "2024-01-15" or full RFC3339
        parse_timestamp(since_str)
    } else {
        None
    };

    // Compile user pattern once — reused for every line in every file
    let user_regex: Option<Regex> = args.pattern
        .as_ref()
        .map(|p| Regex::new(p))
        .transpose()  // Option<Result<T>> → Result<Option<T>>
        .map_err(|e| anyhow::anyhow!("Invalid regex pattern: {}", e))?;

    let mut all_hits: Vec<LogHit> = Vec::new();
    let mut total_lines = 0usize;

    for log_path in &log_files {
        let file = match fs::File::open(log_path) {
            Ok(f)  => f,
            Err(_) => { continue; } // skip unreadable files silently
        };

        // BufReader reads line by line — memory efficient for huge logs
        // Never loads the entire file into memory
        let reader = BufReader::new(file);

        for (line_num, line_result) in reader.lines().enumerate().take(args.limit) {
            let line = match line_result {
                Ok(l)  => l,
                Err(_) => continue,
            };
            total_lines += 1;

            // ---- FILTERS ----

            // Time filter: try to extract a timestamp from the log line
            if let Some(cutoff) = since_time {
                if let Some(ts) = extract_timestamp(&line) {
                    if ts < cutoff { continue; } // too old, skip
                }
            }

            // User keyword/regex filter
            if let Some(ref re) = user_regex {
                if !re.is_match(&line) { continue; }
            }

            // ---- DETECTION ----
            let mut severity = Severity::Info;
            let mut reasons  = Vec::new();

            // IOC check: extract tokens from the line, check each as a potential IOC
            if args.ioc || args.mitre || user_regex.is_none() {
                for token in line.split_whitespace() {
                    // Strip common punctuation that appears around IPs in logs
                    let clean = token.trim_matches(|c: char| "[]()\"',;".contains(c));
                    if let Some(ioc_match) = ioc::check_ioc(clean) {
                        reasons.push(format!("IOC: {}", ioc_match.description));
                        if ioc_match.severity > severity {
                            severity = ioc_match.severity;
                        }
                    }
                }
            }

            // Pattern scan on the whole line (suspicious strings, tool names, etc.)
            let hits = ioc::scan_text_for_patterns(&line);
            for (_, sev, desc) in &hits {
                reasons.push(desc.clone());
                if *sev > severity {
                    severity = sev.clone();
                }
            }

            // If --ioc or --mitre was set, skip lines with no detections
            if (args.ioc || args.mitre) && reasons.is_empty() { continue; }

            // If no user filter and no detections, skip
            if user_regex.is_none() && reasons.is_empty() { continue; }

            all_hits.push(LogHit {
                file:     log_path.clone(),
                line_num: line_num + 1,
                line:     line.chars().take(200).collect(),
                severity,
                reason:   reasons.join(" | "),
            });
        }
    }

    // ---- OUTPUT ----
    println!(
        "{} Scanned {} lines across {} files | {} hits\n",
        "[SIEM]".bright_yellow().bold(),
        total_lines,
        log_files.len(),
        all_hits.len().to_string().yellow().bold(),
    );

    if all_hits.is_empty() {
        println!("{} No matching log entries found.", "[✓]".green());
        return Ok(());
    }

    match args.output.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&all_hits)?);
        }
        _ => {
            for hit in &all_hits {
                let sev_str = match hit.severity {
                    Severity::Critical => "[CRITICAL]".red().bold(),
                    Severity::High     => "[HIGH]    ".truecolor(255, 140, 0).bold(),
                    Severity::Medium   => "[MEDIUM]  ".yellow().bold(),
                    Severity::Low      => "[LOW]     ".blue(),
                    Severity::Info     => "[INFO]    ".dimmed(),
                };
                println!(
                    "{} {}:{} {}",
                    sev_str,
                    hit.file.split('/').last().unwrap_or(&hit.file).dimmed(),
                    hit.line_num.to_string().dimmed(),
                    hit.line,
                );
                if !hit.reason.is_empty() {
                    println!("  ↳ {}", hit.reason.yellow());
                }
            }
        }
    }

    Ok(())
}

// ---- HELPERS ----

// Try to parse common timestamp string inputs for --since
// Supports RFC3339 ("2024-01-15T14:32:01+00:00") and date-only ("2024-01-15")
fn parse_timestamp(s: &str) -> Option<DateTime<Local>> {
    // Try RFC3339 first (most precise)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Local));
    }
    // Try date-only: treat as midnight local time
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let dt = d.and_hms_opt(0, 0, 0)?;
        return Some(DateTime::from_naive_utc_and_offset(dt, *Local::now().offset()));
    }
    None
}

// Try to extract an ISO-style timestamp from within a log line
// Best-effort — log formats vary wildly (syslog, journald, nginx, apache...)
fn extract_timestamp(line: &str) -> Option<DateTime<Local>> {
    // Match ISO-like prefix: "2024-01-15T14:32:01"
    let iso_re = Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}").ok()?;
    if let Some(m) = iso_re.find(line) {
        if let Ok(dt) = DateTime::parse_from_rfc3339(m.as_str()) {
            return Some(dt.with_timezone(&Local));
        }
    }
    None
}
