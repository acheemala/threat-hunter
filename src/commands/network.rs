// ============================================================
// src/commands/network.rs
// Implements: threathunter network [flags]
//
// Calls the network engine (src/network.rs) to get all live
// connections, then filters and displays them.
//
// Usage examples:
//   threathunter network
//   threathunter network --suspicious-only
//   threathunter network --state ESTABLISHED --output json
//   threathunter network --proto TCP
// ============================================================

use crate::ioc::Severity;
use crate::network;          // the engine in src/network.rs
use anyhow::Result;
use clap::Args;
use colored::*;
use tabled::{Table, Tabled};

// ---- CLI ARGS ----
// Every field here becomes a flag: --suspicious-only, --state, etc.
#[derive(Args)]
pub struct NetworkArgs {
    /// Only show flagged connections
    #[arg(short = 'S', long)]
    suspicious_only: bool,

    /// Filter by TCP state: ESTABLISHED, LISTEN, SYN_SENT, etc.
    #[arg(long)]
    state: Option<String>,

    /// Filter by protocol: TCP, TCP6, UDP
    #[arg(long)]
    proto: Option<String>,

    /// Output format: table, json, plain
    #[arg(short, long, default_value = "table")]
    output: String,
}

// ---- TABLE ROW ----
// tabled prints one of these per connection
// #[tabled(rename = "...")] sets the column header
#[derive(Tabled)]
struct NetRow {
    #[tabled(rename = "Proto")]
    proto: String,

    #[tabled(rename = "Local Address")]
    local: String,

    #[tabled(rename = "Remote Address")]
    remote: String,

    #[tabled(rename = "State")]
    state: String,

    #[tabled(rename = "Process")]
    process: String,   // PID + name if we could read it

    #[tabled(rename = "Severity")]
    severity: String,

    #[tabled(rename = "Reason")]
    reason: String,
}

pub fn run(args: NetworkArgs) -> Result<()> {
    println!(
        "{} Reading live network connections...\n",
        "[NETWORK]".bright_blue().bold()
    );

    // Call the engine — reads /proc/net/tcp, /proc/net/tcp6, /proc/net/udp
    let mut connections = network::get_connections()?;

    // ---- FILTERS ----

    // --suspicious-only: drop anything the engine didn't flag
    if args.suspicious_only {
        connections.retain(|c| c.suspicious);
    }

    // --state ESTABLISHED: keep only connections in that TCP state
    if let Some(ref state_filter) = args.state {
        let f = state_filter.to_uppercase();
        connections.retain(|c| c.state.to_uppercase().contains(&f));
    }

    // --proto TCP: keep only that protocol
    if let Some(ref proto_filter) = args.proto {
        let f = proto_filter.to_uppercase();
        connections.retain(|c| c.protocol.to_uppercase() == f);
    }

    // ---- SUMMARY ----
    let total      = connections.len();
    let suspicious = connections.iter().filter(|c| c.suspicious).count();
    let critical   = connections.iter().filter(|c| c.severity == Severity::Critical).count();
    let high       = connections.iter().filter(|c| c.severity == Severity::High).count();

    println!(
        "{} {} connections | {} flagged | {} critical  {} high\n",
        "[DONE]".bright_blue().bold(),
        total.to_string().white().bold(),
        suspicious.to_string().yellow().bold(),
        critical.to_string().red().bold(),
        high.to_string().truecolor(255, 140, 0).bold(),
    );

    if connections.is_empty() {
        println!("{} No connections match your filters.", "[✓]".green());
        return Ok(());
    }

    // ---- OUTPUT ----
    match args.output.as_str() {

        "json" => {
            // serde_json serializes the whole Vec in one shot
            // NetConnection has #[derive(Serialize)] so this just works
            println!("{}", serde_json::to_string_pretty(&connections)?);
        }

        "plain" => {
            for c in &connections {
                // Build process label — show "PID/name" or "?" if unknown
                let proc_label = match (&c.pid, &c.process_name) {
                    (Some(pid), Some(name)) => format!("{}/{}", pid, name),
                    (Some(pid), None)       => format!("{}", pid),
                    _                       => "?".to_string(),
                };

                let sev_tag = severity_tag(&c.severity);

                println!(
                    "{} {} {} → {}  [{}]  {}",
                    sev_tag,
                    c.protocol.dimmed(),
                    c.local_addr.white(),
                    c.remote_addr.yellow(),
                    c.state.dimmed(),
                    proc_label.cyan(),
                );

                if let Some(ref reason) = c.reason {
                    println!("  ↳ {}", reason.red());
                }
            }
        }

        _ => {
            // Default: ASCII table
            let rows: Vec<NetRow> = connections.iter().map(|c| {
                let proc_label = match (&c.pid, &c.process_name) {
                    (Some(pid), Some(name)) => format!("{}/{}", pid, name),
                    (Some(pid), None)       => format!("{}", pid),
                    _                       => "—".to_string(),
                };

                NetRow {
                    proto:    c.protocol.clone(),
                    local:    trunc(&c.local_addr,  22),
                    remote:   trunc(&c.remote_addr, 22),
                    state:    c.state.clone(),
                    process:  proc_label,
                    severity: format!("{}", c.severity),
                    reason:   trunc(
                        c.reason.as_deref().unwrap_or("—"),
                        35,
                    ),
                }
            }).collect();

            // Print with severity coloring per line
            for line in Table::new(rows).to_string().lines() {
                if      line.contains("CRITICAL") { println!("{}", line.red().bold()); }
                else if line.contains("HIGH")     { println!("{}", line.truecolor(255, 140, 0)); }
                else if line.contains("MEDIUM")   { println!("{}", line.yellow()); }
                else if line.contains("LOW")      { println!("{}", line.blue()); }
                else                              { println!("{}", line.dimmed()); }
            }
        }
    }

    Ok(())
}

// ---- HELPERS ----

// Colorized severity tag for plain output
fn severity_tag(s: &Severity) -> ColoredString {
    match s {
        Severity::Critical => "[CRITICAL]".red().bold(),
        Severity::High     => "[HIGH]    ".truecolor(255, 140, 0).bold(),
        Severity::Medium   => "[MEDIUM]  ".yellow(),
        Severity::Low      => "[LOW]     ".blue(),
        Severity::Info     => "[INFO]    ".dimmed(),
    }
}

// Truncate a string to max chars, add … if cut
fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}
