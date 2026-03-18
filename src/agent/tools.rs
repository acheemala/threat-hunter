// ============================================================
// src/agent/tools.rs
//
// Defines the tools the AI agent can call during an investigation.
//
// Each tool has two parts:
//   1. A JSON schema definition (sent to Claude so it knows what to call)
//   2. A dispatch function (executes the actual engine when Claude calls it)
//
// Tool call lifecycle:
//   Claude sends:    { "type": "tool_use", "name": "scan_filesystem", "input": {...} }
//   We execute:      dispatch_tool("scan_filesystem", input_json)
//   We return:       { "type": "tool_result", "content": "..." }
//   Claude decides:  call another tool, or stop and write the report
//
// Why pure functions with no I/O in schema definitions:
//   The schema structs are just data — serialized and sent to the API.
//   All actual I/O is isolated in dispatch_tool(). This makes the schemas
//   unit-testable without touching the filesystem or network.
// ============================================================

use serde_json::{json, Value};

// ── Tool schema definition ────────────────────────────────────────────────────

/// One tool definition as Claude API expects it in the `tools` array.
/// Claude reads `name`, `description`, and `input_schema` to decide
/// when and how to call each tool.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ToolDefinition {
    pub name:         &'static str,
    pub description:  &'static str,
    pub input_schema: Value,
}

/// Returns all tool definitions to include in every Claude API request.
/// Claude sees this list and picks tools based on its current reasoning.
pub fn all_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "scan_filesystem",
            description: "Scan a filesystem path for malicious files, IOC hash matches, \
                          suspicious extensions, executables in /tmp, and anomalous patterns. \
                          Returns a list of findings with severity and description. \
                          Use this when you need to investigate what files exist at a path.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute filesystem path to scan (e.g. /tmp, /home/user)"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Whether to scan subdirectories recursively (default: true)"
                    },
                    "suspicious_only": {
                        "type": "boolean",
                        "description": "Return only flagged files, skip clean ones (default: false)"
                    }
                },
                "required": ["path"]
            }),
        },

        ToolDefinition {
            name: "inspect_processes",
            description: "List running processes and flag suspicious ones: deleted executables \
                          (fileless malware), interpreters running as root, processes masquerading \
                          as system names, executables launched from /tmp or /dev/shm. \
                          Use this to detect in-memory threats or privilege abuse.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "suspicious_only": {
                        "type": "boolean",
                        "description": "Return only processes with anomalies (default: false)"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Inspect a specific PID only (optional)"
                    }
                },
                "required": []
            }),
        },

        ToolDefinition {
            name: "check_network",
            description: "Read live network connections from /proc/net/tcp and /proc/net/tcp6. \
                          Flags connections to known C2 IP addresses, backdoor ports (4444, 1337, \
                          31337, 9001, etc.), and unusual listening ports. \
                          Use this to detect command-and-control activity or data exfiltration.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "suspicious_only": {
                        "type": "boolean",
                        "description": "Return only flagged connections (default: false)"
                    }
                },
                "required": []
            }),
        },

        ToolDefinition {
            name: "read_file_content",
            description: "Read the text content of a specific file for detailed analysis. \
                          Use this after scan_filesystem identifies a suspicious file — \
                          reading the content lets you determine if it contains shellcode, \
                          reverse shell code, credential harvesting logic, or persistence mechanisms.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path of the file to read"
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "Maximum bytes to read (default: 4096 to avoid flooding context)"
                    }
                },
                "required": ["path"]
            }),
        },

        ToolDefinition {
            name: "get_process_detail",
            description: "Get the full command line, environment variables, open file descriptors, \
                          and executable path for a specific process ID. \
                          Use this after inspect_processes flags a PID — the cmdline often \
                          reveals the payload, C2 address, or credential being used.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to inspect"
                    }
                },
                "required": ["pid"]
            }),
        },

        ToolDefinition {
            name: "map_to_mitre",
            description: "Map a finding description to MITRE ATT&CK Technique IDs and Tactics. \
                          Use this on any suspicious finding to get the formal technique \
                          classification before writing the final report.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "finding": {
                        "type": "string",
                        "description": "Description of the suspicious activity to classify"
                    }
                },
                "required": ["finding"]
            }),
        },
    ]
}

// ── Tool dispatch ─────────────────────────────────────────────────────────────

/// Execute a tool by name with the input JSON Claude provided.
/// Returns a plain-text string that goes back to Claude as the tool result.
///
/// Why return String instead of Value:
///   Claude's tool_result content is a string. We serialize structured data
///   (findings lists, process info) into a compact JSON string before returning.
///   This keeps the tool_result message simple and avoids nested JSON escaping.
pub fn dispatch_tool(name: &str, input: &Value) -> String {
    match name {
        "scan_filesystem"   => tool_scan_filesystem(input),
        "inspect_processes" => tool_inspect_processes(input),
        "check_network"     => tool_check_network(input),
        "read_file_content" => tool_read_file_content(input),
        "get_process_detail"=> tool_get_process_detail(input),
        "map_to_mitre"      => tool_map_to_mitre(input),
        unknown             => format!("ERROR: unknown tool '{}'", unknown),
    }
}

// ── Individual tool implementations ──────────────────────────────────────────

fn tool_scan_filesystem(input: &Value) -> String {
    let path = match input["path"].as_str() {
        Some(p) => p,
        None    => return "ERROR: path is required".to_string(),
    };
    let suspicious_only = input["suspicious_only"].as_bool().unwrap_or(false);

    use walkdir::WalkDir;
    use crate::scanner;
    use crate::ioc::Severity;

    let mut findings: Vec<Value> = Vec::new();

    let walker = WalkDir::new(path)
        .max_depth(10)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file());

    for entry in walker {
        let ep = entry.path();

        if let Ok(meta) = ep.metadata() {
            if meta.len() > 10 * 1_048_576 { continue; }
        }
        if !scanner::is_suspicious_extension(ep) { continue; }

        if let Ok(result) = scanner::scan_file(ep) {
            if result.severity == Severity::Info { continue; }
            if suspicious_only && result.severity == Severity::Low { continue; }

            findings.push(json!({
                "path":     result.path,
                "severity": format!("{}", result.severity),
                "anomalies": result.anomalies,
                "patterns": result.pattern_hits.iter().map(|(_, _, d)| d).collect::<Vec<_>>(),
                "ioc_match": result.ioc_match.as_ref().map(|m| &m.description),
            }));
        }
    }

    if findings.is_empty() {
        format!("No suspicious files found under {}", path)
    } else {
        format!(
            "{} suspicious files found:\n{}",
            findings.len(),
            serde_json::to_string_pretty(&findings).unwrap_or_default()
        )
    }
}

fn tool_inspect_processes(input: &Value) -> String {
    let suspicious_only = input["suspicious_only"].as_bool().unwrap_or(false);
    let pid_filter      = input["pid"].as_u64().map(|p| p as u32);

    use crate::process as proc_engine;

    match proc_engine::list_processes() {
        Err(e) => format!("ERROR reading /proc: {}", e),
        Ok(mut procs) => {
            if suspicious_only { procs.retain(|p| p.suspicious); }
            if let Some(pid) = pid_filter { procs.retain(|p| p.pid == pid); }

            if procs.is_empty() {
                return "No processes match the filter.".to_string();
            }

            let summary: Vec<Value> = procs.iter().map(|p| json!({
                "pid":       p.pid,
                "name":      p.name,
                "uid":       p.uid,
                "exe":       p.exe_path,
                "severity":  format!("{}", p.severity),
                "suspicious":p.suspicious,
                "anomalies": p.anomalies,
            })).collect();

            format!(
                "{} processes (showing {}):  \n{}",
                procs.len(),
                if suspicious_only { "suspicious only" } else { "all" },
                serde_json::to_string_pretty(&summary).unwrap_or_default()
            )
        }
    }
}

fn tool_check_network(input: &Value) -> String {
    let suspicious_only = input["suspicious_only"].as_bool().unwrap_or(false);

    use crate::network;

    match network::get_connections() {
        Err(e) => format!("ERROR reading /proc/net: {}", e),
        Ok(mut conns) => {
            if suspicious_only { conns.retain(|c| c.suspicious); }

            if conns.is_empty() {
                return "No network connections match the filter.".to_string();
            }

            let summary: Vec<Value> = conns.iter().map(|c| json!({
                "protocol":  c.protocol,
                "local":     c.local_addr,
                "remote":    c.remote_addr,
                "state":     c.state,
                "pid":       c.pid,
                "process":   c.process_name,
                "severity":  format!("{}", c.severity),
                "reason":    c.reason,
            })).collect();

            format!(
                "{} connections:\n{}",
                conns.len(),
                serde_json::to_string_pretty(&summary).unwrap_or_default()
            )
        }
    }
}

fn tool_read_file_content(input: &Value) -> String {
    let path = match input["path"].as_str() {
        Some(p) => p,
        None    => return "ERROR: path is required".to_string(),
    };
    let max_bytes = input["max_bytes"].as_u64().unwrap_or(4096) as usize;

    match std::fs::read(path) {
        Err(e) => format!("ERROR reading {}: {}", path, e),
        Ok(bytes) => {
            let truncated = &bytes[..bytes.len().min(max_bytes)];
            // Return as UTF-8 string, replacing non-UTF-8 bytes with replacement char
            let content = String::from_utf8_lossy(truncated);
            format!(
                "File: {} ({} bytes shown of {} total)\n---\n{}",
                path,
                truncated.len(),
                bytes.len(),
                content
            )
        }
    }
}

fn tool_get_process_detail(input: &Value) -> String {
    let pid = match input["pid"].as_u64() {
        Some(p) => p as u32,
        None    => return "ERROR: pid is required".to_string(),
    };

    let proc_base = format!("/proc/{}", pid);

    // Read cmdline — null-byte separated args
    let cmdline = std::fs::read(format!("{}/cmdline", proc_base))
        .map(|b| {
            b.split(|&x| x == 0)
             .map(|s| String::from_utf8_lossy(s).to_string())
             .filter(|s| !s.is_empty())
             .collect::<Vec<_>>()
             .join(" ")
        })
        .unwrap_or_else(|_| "unreadable".to_string());

    // Resolve exe symlink
    let exe = std::fs::read_link(format!("{}/exe", proc_base))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unreadable (permission denied or process exited)".to_string());

    // Read cwd
    let cwd = std::fs::read_link(format!("{}/cwd", proc_base))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unreadable".to_string());

    // Count open file descriptors
    let fd_count = std::fs::read_dir(format!("{}/fd", proc_base))
        .map(|d| d.count())
        .unwrap_or(0);

    // Read first 2KB of environ (null-separated env vars)
    let environ = std::fs::read(format!("{}/environ", proc_base))
        .map(|b| {
            let truncated = &b[..b.len().min(2048)];
            String::from_utf8_lossy(truncated)
                .split('\0')
                .take(20)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n  ")
        })
        .unwrap_or_else(|_| "unreadable".to_string());

    format!(
        "PID {} detail:\n  exe:     {}\n  cmdline: {}\n  cwd:     {}\n  open_fds:{}\n  environ (first 20):\n  {}",
        pid, exe, cmdline, cwd, fd_count, environ
    )
}

fn tool_map_to_mitre(input: &Value) -> String {
    let finding = match input["finding"].as_str() {
        Some(f) => f,
        None    => return "ERROR: finding is required".to_string(),
    };

    use crate::commands::mitre;
    let techniques = mitre::map_finding(finding);

    if techniques.is_empty() {
        return format!("No MITRE ATT&CK techniques matched for: {}", finding);
    }

    let mapped: Vec<Value> = techniques.iter().map(|t| json!({
        "id":     t.id,
        "name":   t.name,
        "tactic": t.tactic,
    })).collect();

    format!(
        "{} technique(s) matched:\n{}",
        mapped.len(),
        serde_json::to_string_pretty(&mapped).unwrap_or_default()
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tools_have_required_fields() {
        for t in all_tools() {
            assert!(!t.name.is_empty(), "tool name must not be empty");
            assert!(!t.description.is_empty(), "tool description must not be empty");
            assert!(t.input_schema.is_object(), "input_schema must be a JSON object");
        }
    }

    #[test]
    fn dispatch_unknown_tool_returns_error() {
        let result = dispatch_tool("nonexistent_tool", &json!({}));
        assert!(result.starts_with("ERROR:"));
    }

    #[test]
    fn tool_read_file_missing_path_returns_error() {
        let result = dispatch_tool("read_file_content", &json!({}));
        assert!(result.starts_with("ERROR"));
    }
}
