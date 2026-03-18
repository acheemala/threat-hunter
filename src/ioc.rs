// ============================================================
// src/ioc.rs
// IOC = Indicator of Compromise
// This file answers ONE question: "Is this thing known to be evil?"
// It checks: file hashes, IP addresses, domains, and text patterns
// ============================================================

// once_cell::sync::Lazy lets us define global HashSets that are built ONCE
// when first accessed, not at program startup. Safe for multithreaded use.
use once_cell::sync::Lazy;

// Regex is the compiled regex type. We pre-compile patterns once here.
use regex::Regex;

// Serde lets us serialize these structs to JSON with #[derive(Serialize)]
use serde::{Deserialize, Serialize};

// HashSet = O(1) lookup. Perfect for "is this IP in the bad list?"
use std::collections::HashSet;

// ============================================================
// TYPES
// ============================================================

// What kind of thing are we looking at?
// #[derive(Debug)] = lets you print it with {:?} for debugging
// Clone = lets you copy it cheaply
// PartialEq = lets you compare with ==
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IocType {
    Hash,        // MD5 or SHA-256 file hash
    Ip,          // IPv4 address
    Domain,      // hostname like evil.com
    FilePath,    // /tmp/backdoor.sh
    RegistryKey, // HKEY_LOCAL_MACHINE\... (Windows)
    Pattern,     // regex match in file content
    Unknown,     // couldn't determine type
}

// Display trait lets us print IocType as a string: format!("{}", ioc_type)
impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::Hash        => write!(f, "Hash"),
            IocType::Ip          => write!(f, "IP Address"),
            IocType::Domain      => write!(f, "Domain"),
            IocType::FilePath    => write!(f, "File Path"),
            IocType::RegistryKey => write!(f, "Registry Key"),
            IocType::Pattern     => write!(f, "Pattern"),
            IocType::Unknown     => write!(f, "Unknown"),
        }
    }
}

// How dangerous is this finding?
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Critical, // Known malware hash, active C2 connection
    High,     // Suspicious process, known bad IP
    Medium,   // Unusual port, script in temp dir
    Low,      // Minor anomaly
    Info,     // Clean, nothing found
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Info     => write!(f, "INFO"),
        }
    }
}

// A confirmed IOC match — returned when we find something bad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub value:       String,   // The actual bad thing (the hash, IP, etc.)
    pub ioc_type:    IocType,
    pub severity:    Severity,
    pub description: String,   // Human-readable explanation
    pub source:      String,   // Which database matched it
}

// ============================================================
// THREAT INTELLIGENCE DATABASE
// These are built once at first use (Lazy) and never changed.
// In a real tool you'd load these from a file or API.
// ============================================================

// Known malicious file hashes (MD5 and SHA-256 mixed)
// HashSet because we only need: "is this in the set?" — O(1)
static MALICIOUS_HASHES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        // EICAR test file — safe test malware, every AV should flag this
        "44d88612fea8a8f36de82e1278abb02f",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        // Known cryptominer
        "aec070645fe53ee3b3763059376134f8",
        // Common RAT dropper hash (example)
        "cf8bd9dfddff007f75adf4f2e4c79af9",
        // Cobalt Strike beacon (example)
        "3395856ce81f2b7382dee72602f798b6",
    ])
});

// Known C2 (Command & Control) server IP addresses
// These are IPs that malware "phones home" to for instructions
static MALICIOUS_IPS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "185.220.101.45",  // Tor exit node used for C2
        "45.142.212.100",  // Known REvil infrastructure
        "194.165.16.11",   // Cobalt Strike C2
        "91.92.109.24",    // Emotet C2
        "5.188.86.172",    // Trickbot C2
        "198.199.93.40",   // Known malware staging server
        "103.41.167.233",  // APT group infrastructure
    ])
});

// Known malicious domains — DGA domains, C2 domains, phishing infrastructure
static MALICIOUS_DOMAINS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "evil-malware.com",
        "c2server.ru",
        "exfil-data.top",        // Data exfiltration endpoint
        "stealpasswords.net",
        "cryptominer-pool.io",   // Crypto mining pool
        "cobalt-strike-c2.com",
        "dga-domain-abc123.biz", // DGA = Domain Generation Algorithm (botnet trick)
    ])
});

// Suspicious text patterns to look for inside files and command lines
// Each entry is: (regex_pattern, severity, human_description)
// These map to MITRE ATT&CK techniques — you'll use this in mitre.rs later
static SUSPICIOUS_PATTERNS: Lazy<Vec<(&'static str, Severity, &'static str)>> = Lazy::new(|| {
    vec![
        // Known attack tool names — CRITICAL if found in a file or process name
        (r"(?i)(mimikatz|meterpreter|cobalt.?strike|metasploit)",
            Severity::Critical, "Known attack tool name"),

        // Ransomware family names
        (r"(?i)(wannacry|petya|ryuk|conti|lockbit|blackcat)",
            Severity::Critical, "Ransomware family name"),

        // PowerShell encoded command — classic obfuscation technique
        // Attackers base64-encode payloads to evade detection
        (r"(?i)(powershell.*-enc|-encodedcommand|-e )",
            Severity::High, "PowerShell encoded command (T1059.001)"),

        // Reverse shell one-liners
        (r"(?i)(bash -i|/dev/tcp/|nc -e|ncat.*-e)",
            Severity::High, "Reverse shell pattern (T1059.004)"),

        // Classic credential dumping via LSASS
        (r"(?i)(lsass.*dump|procdump.*lsass|sekurlsa)",
            Severity::Critical, "LSASS credential dumping (T1003.001)"),

        // Suspicious download patterns — wget/curl to suspicious targets
        (r"(?i)(wget|curl).*(http|ftp).*(/tmp|/dev/shm|temp)",
            Severity::High, "Download to temp directory (T1105)"),

        // Persistence via cron or SSH keys
        (r"(?i)(cron\.d/|authorized_keys|\.bashrc|rc\.local)",
            Severity::Medium, "Persistence mechanism (T1053/T1098)"),

        // Double file extension — file.pdf.exe is a common trick
        (r"(?i)\.(pdf|doc|xls|jpg|png)\.(exe|bat|ps1|sh|vbs)$",
            Severity::High, "Double extension masquerading (T1036.007)"),

        // Process memory access — could be process injection
        (r"(?i)/proc/[0-9]+/(mem|maps|fd)",
            Severity::High, "Process memory access (T1055)"),

        // Executable script extensions
        (r"(?i)\.(ps1|vbs|hta|jse|wsf)$",
            Severity::Medium, "Script file type"),
    ]
});

// ============================================================
// REGEX PATTERNS — compiled once, reused many times
// Lazy<Regex> = compile the regex only when first used
// ============================================================

// IPv4: four groups of 1-3 digits separated by dots
static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$").unwrap()
});

// Hash: exactly 32 chars (MD5), 40 chars (SHA-1), or 64 chars (SHA-256)
// [a-fA-F0-9] = hex characters only
static HASH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$").unwrap()
});

// Domain: one or more labels (alphanumeric + hyphen) separated by dots
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

// ============================================================
// PUBLIC FUNCTIONS — called by scanner.rs, network.rs, process.rs
// ============================================================

// Detect what TYPE of indicator a string is.
// Called before check_ioc() so we know how to look it up.
pub fn detect_ioc_type(value: &str) -> IocType {
    if HASH_RE.is_match(value) {
        IocType::Hash
    } else if IPV4_RE.is_match(value) {
        IocType::Ip
    } else if DOMAIN_RE.is_match(value) {
        IocType::Domain
    } else if value.starts_with("HKEY") {
        IocType::RegistryKey
    } else if value.starts_with('/') || value.contains(":\\") {
        IocType::FilePath
    } else {
        IocType::Unknown
    }
}

// The main lookup function.
// Returns Some(IocMatch) if the value is known bad, None if clean.
// pub = other modules can call this
pub fn check_ioc(value: &str) -> Option<IocMatch> {
    let ioc_type = detect_ioc_type(value);
    // Normalize to lowercase for case-insensitive comparison
    let lower = value.to_lowercase();

    match &ioc_type {
        IocType::Hash => {
            // HashSet::contains is O(1) — very fast even with thousands of hashes
            if MALICIOUS_HASHES.contains(lower.as_str()) {
                Some(IocMatch {
                    value:       value.to_string(),
                    ioc_type,
                    severity:    Severity::Critical,
                    description: "Hash matches known malware signature".to_string(),
                    source:      "ThreatHunter Internal DB".to_string(),
                })
            } else {
                None
            }
        }

        IocType::Ip => {
            if MALICIOUS_IPS.contains(value) {
                Some(IocMatch {
                    value:       value.to_string(),
                    ioc_type,
                    severity:    Severity::High,
                    description: "IP matches known C2 or threat actor infrastructure".to_string(),
                    source:      "ThreatHunter Internal DB".to_string(),
                })
            } else {
                None
            }
        }

        IocType::Domain => {
            if MALICIOUS_DOMAINS.contains(lower.as_str()) {
                Some(IocMatch {
                    value:       value.to_string(),
                    ioc_type,
                    severity:    Severity::High,
                    description: "Domain matches known malicious infrastructure".to_string(),
                    source:      "ThreatHunter Internal DB".to_string(),
                })
            } else {
                None
            }
        }

        // For paths, registry keys, and unknowns — no DB lookup, just pattern check below
        _ => None,
    }
}

// Scan a blob of text (file content, log line, cmdline) for suspicious patterns.
// Returns a Vec of (matched_text, severity, description) for every hit.
// Called by scanner.rs (file content), process.rs (cmdline), siem.rs (log lines)
pub fn scan_text_for_patterns(text: &str) -> Vec<(String, Severity, String)> {
    let mut hits = Vec::new();

    for (pattern_str, severity, description) in SUSPICIOUS_PATTERNS.iter() {
        // These regexes are already compiled (Lazy), so this is fast
        if let Ok(re) = Regex::new(pattern_str) {
            for m in re.find_iter(text) {
                hits.push((
                    m.as_str().to_string(),
                    severity.clone(),
                    description.to_string(),
                ));
            }
        }
    }

    hits
}
