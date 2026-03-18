// ============================================================
// src/scanner.rs
// Scans a single file:
//   1. Hashes it (SHA-256 + MD5)
//   2. Checks the hash against ioc.rs
//   3. Reads content and scans for suspicious patterns
//   4. Detects anomalies (double extensions, executable in /tmp, etc.)
// ============================================================

use crate::ioc::{self, IocMatch, Severity};
use anyhow::Result;

// sha2 re-exports the Digest trait — we import it once and reuse for both
// SHA-256 and MD5 (both implement the same Digest trait from RustCrypto)
use sha2::{Digest, Sha256};

// NOTE: Cargo.toml lists `md-5` but the crate internally exposes itself as `md5`.
//       The old standalone `md5` crate had `md5::compute()` — that API does NOT exist here.
//       RustCrypto's md-5 uses the same Digest trait as sha2.
use md5::Md5;

use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::Path;

// ============================================================
// RESULT TYPE
// ============================================================

// The full result of scanning one file.
// pub = visible to commands/scan.rs and report.rs
// Serialize = can be written to JSON by serde_json
#[derive(Debug, Clone, Serialize)]
pub struct FileScanResult {
    pub path:         String,
    pub size:         u64,
    pub sha256:       String,
    pub md5:          String,
    pub ioc_match:    Option<IocMatch>,                 // Some() if hash is known malware
    pub pattern_hits: Vec<(String, Severity, String)>,  // text patterns found inside
    pub anomalies:    Vec<String>,                       // structural oddities
    pub severity:     Severity,                          // worst severity across all findings
}

// ============================================================
// HASHING
// ============================================================

// Hash a file and return (sha256_hex, md5_hex).
// Returns a tuple — two values at once.
// Result<T> means it can fail (file not found, permission denied, etc.)
pub fn hash_file(path: &Path) -> Result<(String, String)> {
    let mut file = fs::File::open(path)?; // ? = if this fails, return the error immediately
    let mut buf  = Vec::new();
    file.read_to_end(&mut buf)?;          // read the entire file into memory

    // Sha256::digest() takes bytes, returns a fixed-size array [u8; 32]
    // hex::encode converts that array to a human-readable 64-char hex string
    let sha256 = hex::encode(Sha256::digest(&buf));

    // FIX: Md5::digest() — same RustCrypto Digest trait, returns [u8; 16]
    // hex::encode produces a 32-char MD5 hex string
    let md5 = hex::encode(Md5::digest(&buf));

    Ok((sha256, md5))
}

// ============================================================
// FILE SCANNER
// ============================================================

// Scan a single file and return everything we found.
pub fn scan_file(path: &Path) -> Result<FileScanResult> {
    let meta = fs::metadata(path)?;
    let size = meta.len();

    // Hash the file — unwrap_or_default gives ("", "") on failure (e.g. permission denied)
    let (sha256, md5) = hash_file(path).unwrap_or_default();

    // Check BOTH hashes against the IOC database.
    // or_else() = if SHA-256 returns None, try MD5 next.
    let ioc_match = ioc::check_ioc(&sha256)
        .or_else(|| ioc::check_ioc(&md5));

    let path_str = path.to_string_lossy().to_string();

    // Always scan the filename/path itself — double extensions hide here
    let mut all_hits = ioc::scan_text_for_patterns(&path_str);

    // For small files (< 1MB), also scan the content.
    // We skip large files to avoid reading 500MB binaries into memory.
    if size < 1_048_576 {
        if let Ok(content) = fs::read_to_string(path) {
            let content_hits = ioc::scan_text_for_patterns(&content);
            all_hits.extend(content_hits); // merge the two Vecs together
        }
    }

    // ── ANOMALY DETECTION ────────────────────────────────────────────────────
    let mut anomalies = Vec::new();

    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Double extension: "invoice.pdf.exe" has 3 parts when split by '.'
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() > 2 {
        // Only flag if the last part looks like an executable
        let last = parts.last().unwrap_or(&"").to_lowercase();
        if ["exe", "bat", "ps1", "sh", "vbs", "hta"].contains(&last.as_str()) {
            anomalies.push(format!("Double extension: {}", name));
        }
    }

    // Executable living in /tmp or /dev/shm is very suspicious.
    // Malware often drops itself here to avoid detection in system dirs.
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        let is_exec = ["exe", "dll", "bat", "ps1", "sh", "elf"].contains(&ext_lower.as_str());
        if is_exec {
            let p = path_str.to_lowercase();
            if p.contains("/tmp") || p.contains("/dev/shm") || p.contains("\\temp\\") {
                anomalies.push("Executable in temp/shm directory (T1036)".to_string());
            }
        }
    }

    // Hidden file (starts with dot on Linux)
    if name.starts_with('.') && name.len() > 1 {
        anomalies.push(format!("Hidden file: {}", name));
    }

    // Unusually large script — legit scripts rarely exceed 500KB
    if size > 500_000 {
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            if ["sh", "py", "ps1", "vbs", "js"].contains(&ext_lower.as_str()) {
                anomalies.push(format!(
                    "Large script file: {} bytes (possible packed payload)",
                    size
                ));
            }
        }
    }

    // ── DETERMINE OVERALL SEVERITY ───────────────────────────────────────────
    // The worst finding sets the severity for the whole result.
    // Order matters: Critical is checked first, Info is the fallback.
    let severity = if ioc_match.is_some() {
        Severity::Critical // known malware hash → always Critical
    } else if all_hits.iter().any(|(_, s, _)| s == &Severity::Critical)
        || anomalies.iter().any(|a| a.contains("Executable in temp"))
    {
        Severity::High
    } else if all_hits.iter().any(|(_, s, _)| s == &Severity::High)
        || !anomalies.is_empty()
    {
        Severity::Medium
    } else if !all_hits.is_empty() {
        Severity::Low
    } else {
        Severity::Info // nothing found
    };

    Ok(FileScanResult {
        path: path_str,
        size,
        sha256,
        md5,
        ioc_match,
        pattern_hits: all_hits,
        anomalies,
        severity,
    })
}

// ============================================================
// HELPERS
// ============================================================

// Quick check: should we even bother scanning this file?
// Used by the scan command to skip .txt, .png, etc. unless --all is passed.
pub fn is_suspicious_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        matches!(
            ext.as_str(),
            "exe" | "dll" | "bat" | "cmd" | "vbs" | "ps1"
            | "sh"  | "py"  | "php" | "jsp" | "war"  | "jar"
            | "hta" | "scr" | "pif" | "reg" | "msi"  | "elf"
            | "so"  | "bin"
        )
    } else {
        false
    }
}
