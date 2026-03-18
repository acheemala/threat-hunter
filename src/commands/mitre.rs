// ============================================================
// src/commands/mitre.rs
// Implements: threathunter mitre map
//
// Maps findings from other engines to MITRE ATT&CK technique IDs.
// MITRE ATT&CK is the industry-standard taxonomy for attacker behavior.
// Tactic = the goal (e.g. Persistence, Exfiltration)
// Technique = how they do it (e.g. T1053 Scheduled Task)
// ============================================================

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use clap::Args;
use colored::*;

#[derive(Args)]
pub struct MitreArgs {
    /// Finding text to map (e.g. "process running from /tmp")
    #[arg(short, long)]
    finding: Option<String>,

    /// List all techniques in our mapping database
    #[arg(short, long)]
    list: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id:          &'static str, // "T1055"
    pub name:        &'static str, // "Process Injection"
    pub tactic:      &'static str, // "Defense Evasion"
    pub description: &'static str, // short description
}

// Mapping table: (keyword/phrase in finding text) → AttackTechnique
// This is how we connect raw anomalies to structured ATT&CK entries
static TECHNIQUE_MAP: Lazy<Vec<(&'static str, AttackTechnique)>> = Lazy::new(|| {
    vec![
        ("deleted from disk", AttackTechnique {
            id: "T1055", name: "Process Injection",
            tactic: "Defense Evasion",
            description: "Injecting into another process to hide execution",
        }),
        ("running from /tmp", AttackTechnique {
            id: "T1036", name: "Masquerading",
            tactic: "Defense Evasion",
            description: "Disguising malicious artifacts as legitimate ones",
        }),
        ("encoded command", AttackTechnique {
            id: "T1059.001", name: "PowerShell",
            tactic: "Execution",
            description: "Using PowerShell for execution, often with encoding",
        }),
        ("reverse shell", AttackTechnique {
            id: "T1059.004", name: "Unix Shell",
            tactic: "Execution",
            description: "Attacker-controlled shell on victim",
        }),
        ("lsass", AttackTechnique {
            id: "T1003.001", name: "LSASS Memory",
            tactic: "Credential Access",
            description: "Dumping credentials from LSASS process memory",
        }),
        ("authorized_keys", AttackTechnique {
            id: "T1098.004", name: "SSH Authorized Keys",
            tactic: "Persistence",
            description: "Adding SSH keys for persistent access",
        }),
        ("cron", AttackTechnique {
            id: "T1053.003", name: "Cron",
            tactic: "Persistence",
            description: "Scheduled task via cron for persistent execution",
        }),
        ("download to temp", AttackTechnique {
            id: "T1105", name: "Ingress Tool Transfer",
            tactic: "Command and Control",
            description: "Transferring tools from external to victim",
        }),
        ("known c2", AttackTechnique {
            id: "T1071", name: "Application Layer Protocol",
            tactic: "Command and Control",
            description: "C2 communication over standard protocols",
        }),
        ("c2/backdoor port", AttackTechnique {
            id: "T1571", name: "Non-Standard Port",
            tactic: "Command and Control",
            description: "Using unusual port numbers for C2 traffic",
        }),
        ("double extension", AttackTechnique {
            id: "T1036.007", name: "Double File Extension",
            tactic: "Defense Evasion",
            description: "Using double extensions to disguise executable type",
        }),
        ("process memory", AttackTechnique {
            id: "T1055", name: "Process Injection",
            tactic: "Defense Evasion",
            description: "Accessing /proc memory for injection or credential theft",
        }),
        ("cryptominer", AttackTechnique {
            id: "T1496", name: "Resource Hijacking",
            tactic: "Impact",
            description: "Using victim resources for cryptocurrency mining",
        }),
        ("interpreter running as root", AttackTechnique {
            id: "T1059", name: "Command & Scripting Interpreter",
            tactic: "Execution",
            description: "Using interpreter for execution with elevated privileges",
        }),
    ]
});

// Map a finding string to zero or more ATT&CK techniques.
// Called by report.rs to enrich findings with technique IDs.
pub fn map_finding(finding: &str) -> Vec<AttackTechnique> {
    let lower = finding.to_lowercase();
    TECHNIQUE_MAP
        .iter()
        .filter(|(keyword, _)| lower.contains(keyword))
        .map(|(_, tech)| tech.clone())
        .collect()
}

// CLI entry point — called from main.rs
pub fn run(args: MitreArgs) -> anyhow::Result<()> {
    if args.list {
        print_all_techniques();
        return Ok(());
    }

    if let Some(ref finding) = args.finding {
        let techs = map_finding(finding);
        if techs.is_empty() {
            println!("{} No MITRE ATT&CK techniques mapped for: {}", "[?]".yellow(), finding);
        } else {
            println!(
                "{} Mapped '{}' to {} technique(s):\n",
                "[MITRE]".bright_red().bold(),
                finding.yellow(),
                techs.len()
            );
            for t in &techs {
                print_technique(t);
            }
        }
    } else {
        println!("Use --finding <text> to map a finding, or --list to see all techniques.");
    }

    Ok(())
}

fn print_technique(t: &AttackTechnique) {
    println!(
        "  {} {}  [{}]",
        t.id.bright_red().bold(),
        t.name.white().bold(),
        t.tactic.yellow(),
    );
    println!("  {}\n", t.description.dimmed());
}

fn print_all_techniques() {
    println!("{} MITRE ATT&CK Technique Database\n", "[MITRE]".bright_red().bold());
    println!("{:<12} {:<35} {:<25} {}",
        "ID".cyan().bold(),
        "Technique".cyan().bold(),
        "Tactic".cyan().bold(),
        "Description".cyan().bold(),
    );
    println!("{}", "-".repeat(100).dimmed());
    for (_, t) in TECHNIQUE_MAP.iter() {
        println!("{:<12} {:<35} {:<25} {}",
            t.id.bright_red(),
            t.name.white(),
            t.tactic.yellow(),
            t.description.dimmed(),
        );
    }
}
