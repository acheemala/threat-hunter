// ============================================================
// src/main.rs
// This file has ONE job: define the CLI structure and route
// each subcommand to the right handler in commands/
// No business logic lives here.
// ============================================================

// Declare our modules — Rust needs to know these files exist
mod agent;
mod commands;
mod ioc;
mod network;
mod process;
mod report;
mod scanner;

use clap::{Parser, Subcommand};
use colored::*;

const BANNER: &str = r#"
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
    ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██║   ███████║██████╔╝█████╗  ███████║   ██║
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"#;

// #[derive(Parser)] makes this struct the top-level CLI definition
// clap reads the field names and doc comments to generate --help
#[derive(Parser)]
#[command(
    name    = "threathunter",
    version = "0.1.0",
    about   = "Rust-based threat hunting CLI | Mini-SIEM | MITRE ATT&CK",
)]
struct Cli {
    /// Suppress the banner (useful in scripts)
    #[arg(short, long, global = true)]
    quiet: bool,

    // Subcommand routing — clap dispatches to the right Commands variant
    #[command(subcommand)]
    command: Commands,
}

// Each variant here becomes a subcommand: `threathunter scan`, `threathunter siem`, etc.
// The inner struct (ScanArgs, SiemArgs...) defines that subcommand's specific flags.
#[derive(Subcommand)]
enum Commands {
    /// Scan filesystem for malware, IOCs, and anomalies
    Scan(commands::scan::ScanArgs),

    /// Query log files — mini-SIEM with IOC correlation
    Siem(commands::siem::SiemArgs),

    /// Inspect running processes for suspicious activity
    Process(commands::process::ProcessArgs),

    /// Analyze live network connections
    Network(commands::network::NetworkArgs),

    /// Map findings to MITRE ATT&CK techniques
    Mitre(commands::mitre::MitreArgs),

    /// Generate a full threat report
    Report(commands::report::ReportArgs),

    /// Run an autonomous AI-powered threat investigation (requires ANTHROPIC_API_KEY)
    Agent(commands::agent::AgentArgs),
}

fn main() {
    // Cli::parse() reads argv, matches against our struct, and panics with --help on error
    let cli = Cli::parse();

    if !cli.quiet {
        println!("{}", BANNER.red().bold());
        println!(
            "  {} v0.1.0   {}\n",
            "ThreatHunter".bright_red().bold(),
            chrono::Local::now()
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
                .dimmed(),
        );
    }

    // Route to the correct subcommand handler
    // Each run() returns Result<()> — we handle errors here centrally
    let result = match cli.command {
        Commands::Scan(args)    => commands::scan::run(args),
        Commands::Siem(args)    => commands::siem::run(args),
        Commands::Process(args) => commands::process::run(args),
        Commands::Network(args) => commands::network::run(args),
        Commands::Mitre(args)   => commands::mitre::run(args),
        Commands::Report(args)  => commands::report::run(args),
        Commands::Agent(args)   => commands::agent::run(args),
    };

    // If any subcommand returned an error, print it and exit with code 1
    if let Err(e) = result {
        eprintln!("{} {}", "[ERROR]".red().bold(), e);
        std::process::exit(1);
    }
}
