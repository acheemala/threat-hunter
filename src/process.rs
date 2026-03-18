// ============================================================
// src/process.rs
// Reads /proc/<pid>/ for every running process
// Flags: deleted executables, processes in /tmp, name mismatches,
//        suspicious commands running as root, known malware hashes
// ============================================================

use crate::ioc::{self, Severity};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessInfo {
    pub pid:        u32,
    pub ppid:       u32,         // parent process ID — important for detecting orphaned shells
    pub name:       String,      // from /proc/PID/comm
    pub cmdline:    String,      // full command line from /proc/PID/cmdline
    pub exe_path:   String,      // resolved path of the executable
    pub state:      String,      // R=running, S=sleeping, Z=zombie, etc.
    pub uid:        u32,         // 0 = root
    pub suspicious: bool,
    pub severity:   Severity,
    pub anomalies:  Vec<String>,
}

// Read ALL processes by iterating /proc/
// /proc/ contains a numbered directory for each running process
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    let mut procs = Vec::new();

    // fs::read_dir returns an iterator of directory entries
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name  = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only process directories named with a number (those are PIDs)
        // Directories like /proc/sys, /proc/net are not PIDs
        if let Ok(pid) = name_str.parse::<u32>() {
            // We use if let Ok() so a single unreadable process doesn't crash the whole scan
            if let Ok(info) = read_process(pid) {
                procs.push(info);
            }
        }
    }

    // Sort by PID for consistent output
    procs.sort_by_key(|p| p.pid);
    Ok(procs)
}

// Read all available info for one process
fn read_process(pid: u32) -> Result<ProcessInfo> {
    let base = format!("/proc/{}", pid);

    // /proc/PID/comm — just the process name, max 15 chars
    let name = fs::read_to_string(format!("{}/comm", base))
        .unwrap_or_default()
        .trim()
        .to_string();

    // /proc/PID/cmdline — null-byte separated argv[], we replace \0 with spaces
    let cmdline_raw = fs::read(format!("{}/cmdline", base)).unwrap_or_default();
    let cmdline = String::from_utf8_lossy(&cmdline_raw)
        .replace('\0', " ")
        .trim()
        .to_string();

    // /proc/PID/exe — symlink to the real executable path on disk
    // If the exe was deleted, Linux appends " (deleted)" to the path
    let exe_path = fs::read_link(format!("{}/exe", base))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "[unreadable]".to_string());

    // /proc/PID/status — multiline text with fields like "PPid: 1234"
    let status = fs::read_to_string(format!("{}/status", base)).unwrap_or_default();

    // Extract fields from the status file
    let ppid  = parse_u32_field(&status, "PPid").unwrap_or(0);
    let uid   = parse_u32_field(&status, "Uid").unwrap_or(999);  // 999 = unknown
    let state = parse_str_field(&status, "State")
        .unwrap_or_else(|| "?".to_string());

    // ---- ANOMALY DETECTION ----
    let mut anomalies = Vec::new();

    // 1. Deleted executable on disk — classic fileless malware or in-memory injection
    //    Malware sometimes deletes itself after loading to avoid AV scanning
    if exe_path.ends_with("(deleted)") {
        anomalies.push("Executable deleted from disk (fileless malware indicator T1055)".to_string());
    }

    // 2. Process running from /tmp or /dev/shm — temp filesystem, often world-writable
    //    Legitimate programs should never be installed here
    if exe_path.starts_with("/tmp") || exe_path.starts_with("/dev/shm") {
        anomalies.push(format!(
            "Process running from suspicious location: {} (T1036)", exe_path
        ));
    }

    // 3. Process name masquerades as a system process
    //    e.g. a fake "sshd" in /tmp masquerading as the real sshd
    let fake_sys = ["sshd","nginx","apache","systemd","init","cron","bash","sh"]
        .iter()
        .any(|&sys| name == sys);
    if fake_sys && (exe_path.starts_with("/tmp") || exe_path.starts_with("/home")) {
        anomalies.push(format!(
            "System process name '{}' running from non-system path (T1036.005)", name
        ));
    }

    // 4. Root process with an interpreter name — nc, python, perl running as root
    //    can be a sign of a root shell or remote access tool
    if uid == 0 && is_interpreter(&name) {
        anomalies.push(format!(
            "Interpreter '{}' running as root — possible backdoor (T1059)", name
        ));
    }

    // 5. Scan the command line for suspicious patterns
    //    e.g. "python3 -c 'import socket...'" is a classic reverse shell
    let hits = ioc::scan_text_for_patterns(&cmdline);
    for (_, sev, desc) in &hits {
        if *sev == Severity::Critical || *sev == Severity::High {
            anomalies.push(format!("Suspicious cmdline: {} ({})", desc, sev));
        }
    }

    // 6. Hash check on the executable
    //    We skip deleted or unreadable exes
    let ioc_hit = if !exe_path.contains("(deleted)") && !exe_path.starts_with('[') {
        let path = std::path::Path::new(&exe_path);
        if let Ok((sha256, md5)) = crate::scanner::hash_file(path) {
            ioc::check_ioc(&sha256).or_else(|| ioc::check_ioc(&md5))
        } else {
            None
        }
    } else {
        None
    };

    if ioc_hit.is_some() {
        anomalies.push("Executable matches known malware hash (CRITICAL)".to_string());
    }

    // ---- SEVERITY ----
    let suspicious = !anomalies.is_empty() || ioc_hit.is_some();
    let severity = if ioc_hit.is_some() {
        Severity::Critical
    } else if anomalies.iter().any(|a|
        a.contains("deleted") || a.contains("suspicious location") || a.contains("CRITICAL")
    ) {
        Severity::High
    } else if !anomalies.is_empty() {
        Severity::Medium
    } else {
        Severity::Info
    };

    Ok(ProcessInfo {
        pid,
        ppid,
        name,
        cmdline: cmdline.chars().take(150).collect(), // truncate very long cmdlines
        exe_path,
        state,
        uid,
        suspicious,
        severity,
        anomalies,
    })
}

// ---- HELPERS ----

// Parse a numeric field from /proc/PID/status
// e.g. "PPid:\t1234\n" → 1234
fn parse_u32_field(status: &str, field: &str) -> Option<u32> {
    status
        .lines()
        .find(|l| l.starts_with(field))? // find the right line
        .split_whitespace()
        .nth(1)?                          // second token is the value
        .parse()
        .ok()
}

// Parse a string field (e.g. "State:  S (sleeping)")
fn parse_str_field(status: &str, field: &str) -> Option<String> {
    let line = status.lines().find(|l| l.starts_with(field))?;
    // Collect everything after the field name
    Some(
        line.split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ")
    )
}

// Is this process name a known interpreter?
fn is_interpreter(name: &str) -> bool {
    matches!(name,
        "sh" | "bash" | "zsh" | "dash" | "nc" | "ncat" | "netcat"
        | "python" | "python3" | "perl" | "ruby" | "php" | "socat"
    )
}
