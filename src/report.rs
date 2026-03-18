// ============================================================
// src/report.rs
// Accumulates findings from all engines into one struct
// Calculates a risk score (0–∞) and risk level (CLEAN → CRITICAL)
// The report command serializes this to JSON or prints it as text
// ============================================================

use serde::{Deserialize, Serialize};

// A single finding that goes into the report
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub severity:    String,
    pub category:    String,         // "filesystem", "network", "process", "log"
    pub description: String,
    pub detail:      String,         // the specific file/IP/process that triggered it
    pub mitre_id:    Option<String>, // e.g. "T1055" — filled in by mitre.rs
    pub mitre_name:  Option<String>, // e.g. "Process Injection"
}

// A named group of findings (one per scan category)
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSection {
    pub title:    String,
    pub findings: Vec<Finding>,
}

// The full threat report
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatReport {
    pub generated_at:   String,
    pub hostname:       String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count:     usize,
    pub medium_count:   usize,
    pub low_count:      usize,
    pub risk_score:     u32,
    pub risk_level:     String,
    pub sections:       Vec<ReportSection>,
}

impl ThreatReport {
    // Create a new empty report
    pub fn new(hostname: String) -> Self {
        ThreatReport {
            generated_at:   chrono::Local::now().to_rfc3339(),
            hostname,
            total_findings: 0,
            critical_count: 0,
            high_count:     0,
            medium_count:   0,
            low_count:      0,
            risk_score:     0,
            risk_level:     "CLEAN".to_string(),
            sections:       Vec::new(),
        }
    }

    // Add one finding to the right section, update counters
    pub fn add_finding(&mut self, section_title: &str, finding: Finding) {
        // Update severity counters
        match finding.severity.as_str() {
            "CRITICAL" => self.critical_count += 1,
            "HIGH"     => self.high_count     += 1,
            "MEDIUM"   => self.medium_count   += 1,
            "LOW"      => self.low_count      += 1,
            _          => {}
        }
        self.total_findings += 1;

        // Find or create the section
        if let Some(sec) = self.sections.iter_mut().find(|s| s.title == section_title) {
            sec.findings.push(finding);
        } else {
            self.sections.push(ReportSection {
                title:    section_title.to_string(),
                findings: vec![finding],
            });
        }
    }

    // Call this after adding all findings.
    // Risk score = weighted sum of findings by severity.
    pub fn calculate_risk(&mut self) {
        // Weights: CRITICAL is 40x worse than LOW
        // Rationale: one Critical finding outweighs 40 Low findings
        let score = (self.critical_count * 40)
                  + (self.high_count     * 15)
                  + (self.medium_count   *  5)
                  + (self.low_count      *  1);

        self.risk_score = score as u32;
        self.risk_level = match score {
            0        => "CLEAN",
            1..=15   => "LOW",
            16..=55  => "MEDIUM",
            56..=120 => "HIGH",
            _        => "CRITICAL",
        }.to_string();
    }
}
