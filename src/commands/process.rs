// ============================================================
// src/commands/process.rs
// Implements: threathunter process [flags]
//
// Calls the process engine (src/process.rs) to read /proc/,
// then filters and displays results.
//
// Usage examples:
//   threathunter process
//   threathunter process --suspicious-only
//   threathunter process --root
//   threathunter process --name python --output json
//   threathunter process --pid 1337
// ============================================================

use crate::ioc::Severity;
use crate::process as proc_engine;   // rename to avoid clash with this module's name
use anyhow::Result;
use clap::Args;
use colored::*;
use tabled::{Table, Tabled};

// ---- CLI ARGS ----
#[derive(Args)]
pub struct ProcessArgs {
    /// Only show suspicious processes
    #[arg(short = 'S', long)]
    suspicious_only: bool,

    /// Filter by process name (partial, case-insensitive)
    #[arg(short, long)]
    name: Option<String>,

    /// Filter by exact PID
    #[arg(short, long)]
    pid: Option<u32>,

    /// Only show root-owned processes (UID 0)
    #[arg(short, long)]
    root: bool,

    /// Show full command line (default: truncated)
    #[arg(short, long)]
    full: bool,

    /// Output format: table, json, plain
    #[arg(short, long, default_value = "table")]
    output: String,
}

// ---- TABLE ROW ----
#[derive(Tabled)]
struct ProcRow {
    #[tabled(rename = "PID")]
    pid: String,

    #[tabled(rename = "PPID")]
    ppid: String,

    #[tabled(rename = "UID")]
    uid: String,

    #[tabled(rename = "State")]
    state: String,

    #[tabled(rename = "Name")]
    name: String,

    #[tabled(rename = "Severity")]
    severity: String,

    #[tabled(rename = "Anomaly")]
    anomaly: String,

    #[tabled(rename = "Cmdline")]
    cmdline: String,
}

pub fn run(args: ProcessArgs) -> Result<()> {
    println!(
        "{} Reading /proc/ for running processes...\n",
        "[PROCESS]".bright_magenta().bold()
    );

    // Call the engine — iterates /proc/<PID>/ for every running process
    let mut procs = proc_engine::list_processes()?;

    // ---- FILTERS ----

    // --suspicious-only: only show what the engine flagged
    if args.suspicious_only {
        procs.retain(|p| p.suspicious);
    }

    // --root: only show processes running as UID 0
    if args.root {
        procs.retain(|p| p.uid == 0);
    }

    // --pid 1234: show exactly that one PID
    if let Some(target_pid) = args.pid {
        procs.retain(|p| p.pid == target_pid);
    }

    // --name python: partial match on name OR cmdline
    if let Some(ref name_filter) = args.name {
        let f = name_filter.to_lowercase();
        procs.retain(|p| {
            p.name.to_lowercase().contains(&f)
                || p.cmdline.to_lowercase().contains(&f)
        });
    }

    // ---- SUMMARY ----
    let total      = procs.len();
    let suspicious = procs.iter().filter(|p| p.suspicious).count();
    let critical   = procs.iter().filter(|p| p.severity == Severity::Critical).count();
    let high       = procs.iter().filter(|p| p.severity == Severity::High).count();
    let as_root    = procs.iter().filter(|p| p.uid == 0).count();

    println!(
        "{} {} processes | {} flagged | {} critical  {} high | {} running as root\n",
        "[DONE]".bright_magenta().bold(),
        total.to_string().white().bold(),
        suspicious.to_string().yellow().bold(),
        critical.to_string().red().bold(),
        high.to_string().truecolor(255, 140, 0).bold(),
        as_root.to_string().cyan().bold(),
    );

    if procs.is_empty() {
        println!("{} No processes match your filters.", "[✓]".green());
        return Ok(());
    }

    // ---- OUTPUT ----
    match args.output.as_str() {

        "json" => {
            println!("{}", serde_json::to_string_pretty(&procs)?);
        }

        "plain" => {
            for p in &procs {
                let sev_tag = severity_tag(&p.severity);
                let uid_str = if p.uid == 0 {
                    "root".red().bold().to_string()
                } else {
                    p.uid.to_string()
                };

                println!(
                    "{} PID:{} PPID:{} UID:{} [{}] {}",
                    sev_tag,
                    p.pid.to_string().cyan(),
                    p.ppid.to_string().dimmed(),
                    uid_str,
                    p.state.dimmed(),
                    p.name.white().bold(),
                );

                // Show exe path — highlight if deleted or from /tmp
                let exe_display = if p.exe_path.contains("(deleted)") {
                    p.exe_path.red().bold().to_string()
                } else if p.exe_path.starts_with("/tmp") || p.exe_path.starts_with("/dev/shm") {
                    p.exe_path.yellow().to_string()
                } else {
                    p.exe_path.dimmed().to_string()
                };
                println!("  exe: {}", exe_display);

                // Show cmdline — full if --full, truncated otherwise
                let cmd_display = if args.full {
                    p.cmdline.clone()
                } else {
                    trunc(&p.cmdline, 100)
                };
                println!("  cmd: {}", cmd_display.dimmed());

                // Print every anomaly on its own indented line
                for anomaly in &p.anomalies {
                    println!("  ⚠  {}", anomaly.yellow());
                }
                println!();
            }
        }

        _ => {
            // Default: ASCII table
            // How long to show the cmdline depends on --full
            let cmd_width = if args.full { 80 } else { 40 };

            let rows: Vec<ProcRow> = procs.iter().map(|p| {
                // Collapse anomalies into one semicolon-separated string for the table
                let anomaly_str = if p.anomalies.is_empty() {
                    "—".to_string()
                } else {
                    trunc(&p.anomalies.join("; "), 45)
                };

                // Highlight root in the UID column
                let uid_display = if p.uid == 0 {
                    "root(0)".to_string()
                } else {
                    p.uid.to_string()
                };

                ProcRow {
                    pid:      p.pid.to_string(),
                    ppid:     p.ppid.to_string(),
                    uid:      uid_display,
                    state:    p.state.clone(),
                    name:     p.name.clone(),
                    severity: format!("{}", p.severity),
                    anomaly:  anomaly_str,
                    cmdline:  trunc(&p.cmdline, cmd_width),
                }
            }).collect();

            // Color each table line by severity
            for line in Table::new(rows).to_string().lines() {
                if      line.contains("CRITICAL") { println!("{}", line.red().bold()); }
                else if line.contains("HIGH")     { println!("{}", line.truecolor(255, 140, 0)); }
                else if line.contains("MEDIUM")   { println!("{}", line.yellow()); }
                else if line.contains("LOW")      { println!("{}", line.blue()); }
                else                              { println!("{}", line.dimmed()); }
            }

            // After the table — print full anomaly details for flagged procs
            // because they get cut off in the table column width
            let flagged: Vec<_> = procs.iter().filter(|p| p.suspicious).collect();
            if !flagged.is_empty() {
                println!("\n{} Anomaly Details:\n", "[!]".yellow().bold());
                for p in flagged {
                    println!(
                        "  PID {} ({}) — exe: {}",
                        p.pid.to_string().cyan(),
                        p.name.white().bold(),
                        p.exe_path.dimmed(),
                    );
                    for a in &p.anomalies {
                        println!("    ⚠  {}", a.yellow());
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

// ---- HELPERS ----

fn severity_tag(s: &Severity) -> ColoredString {
    match s {
        Severity::Critical => "[CRITICAL]".red().bold(),
        Severity::High     => "[HIGH]    ".truecolor(255, 140, 0).bold(),
        Severity::Medium   => "[MEDIUM]  ".yellow(),
        Severity::Low      => "[LOW]     ".blue(),
        Severity::Info     => "[INFO]    ".dimmed(),
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}
