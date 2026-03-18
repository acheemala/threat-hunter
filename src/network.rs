// ============================================================
// src/network.rs
// Reads live network connections from /proc/net/tcp (Linux only)
// Checks remote IPs against the IOC database
// Flags suspicious ports used by common C2 frameworks
// ============================================================

use crate::ioc::{self, Severity};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

// One network connection entry
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetConnection {
    pub local_addr:   String,
    pub remote_addr:  String,
    pub state:        String,
    pub protocol:     String,
    pub pid:          Option<u32>,      // which process owns this socket
    pub process_name: Option<String>,
    pub suspicious:   bool,
    pub reason:       Option<String>,   // why it's flagged
    pub severity:     Severity,
}

// Entry point — called by commands/network.rs
pub fn get_connections() -> Result<Vec<NetConnection>> {
    let mut connections = Vec::new();

    // Linux exposes network state as text files in /proc/net/
    // We parse TCP, TCP6, and UDP
    if let Ok(tcp)  = parse_proc_net("/proc/net/tcp",  "TCP")  { connections.extend(tcp);  }
    if let Ok(tcp6) = parse_proc_net("/proc/net/tcp6", "TCP6") { connections.extend(tcp6); }
    if let Ok(udp)  = parse_proc_net("/proc/net/udp",  "UDP")  { connections.extend(udp);  }

    // Enrich each connection with threat intel
    for conn in &mut connections {
        // Extract just the IP part from "192.168.1.1:4444"
        let remote_ip = conn.remote_addr
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();

        // Skip loopback and unconnected sockets
        if !remote_ip.is_empty() && remote_ip != "0.0.0.0" && remote_ip != "127.0.0.1" {
            if let Some(ioc_match) = ioc::check_ioc(&remote_ip) {
                conn.suspicious = true;
                conn.reason     = Some(ioc_match.description);
                conn.severity   = ioc_match.severity;
            }
        }

        // Check for known C2 ports even if IP is not in our DB.
        // Attackers commonly use these ports because they're memorable or unmonitored.
        if let Some(port_str) = conn.remote_addr.split(':').last() {
            if let Ok(port) = port_str.parse::<u16>() {
                if is_c2_port(port) && !conn.suspicious {
                    conn.suspicious = true;
                    conn.reason     = Some(format!("Known C2/backdoor port: {}", port));
                    conn.severity   = Severity::Medium;
                }
            }
        }

        // Try to find the owning process (best-effort, Linux only)
        if let Ok(pid) = find_pid_for_socket(&conn.local_addr) {
            conn.pid          = Some(pid);
            conn.process_name = get_process_name(pid).ok();
        }
    }

    Ok(connections)
}

// ============================================================
// /proc/net PARSER
// ============================================================
//
// The file looks like:
//   sl  local_address  rem_address  st  ...
//   0:  0F02000A:0016  00000000:0000  0A ...
// Addresses are in little-endian hex: IPADDRESS:PORT
fn parse_proc_net(path: &str, proto: &str) -> Result<Vec<NetConnection>> {
    let content = fs::read_to_string(path)?;
    let mut connections = Vec::new();

    // Skip the header line with skip(1)
    for line in content.lines().skip(1) {
        // Split on whitespace — columns are fixed but whitespace-separated
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }

        // Column 1 = local addr:port (hex)
        // Column 2 = remote addr:port (hex)
        // Column 3 = TCP state (hex)
        let local  = hex_to_ipv4_addr(parts[1]);
        let remote = hex_to_ipv4_addr(parts[2]);
        let state  = tcp_state_name(parts[3]);

        connections.push(NetConnection {
            local_addr:   local,
            remote_addr:  remote,
            state,
            protocol:     proto.to_string(),
            pid:          None,
            process_name: None,
            suspicious:   false,
            reason:       None,
            severity:     Severity::Info,
        });
    }

    Ok(connections)
}

// ============================================================
// HEX ADDRESS DECODER
// ============================================================
//
// Convert Linux /proc/net hex address to human-readable form.
// Linux stores IPv4 as little-endian hex: "0F02000A:0016"
// "0F02000A" → u32 → bytes reversed → 10.0.2.15
// "0016"     → decimal 22 → SSH port
fn hex_to_ipv4_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return hex.to_string(); }

    let ip_hex   = parts[0];
    let port_hex = parts[1];

    if ip_hex.len() == 8 {
        // Parse as u32, then extract each byte in little-endian order
        let n = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
        // Little-endian: lowest byte of the u32 is the first octet
        let b0 =  n        & 0xFF;
        let b1 = (n >>  8) & 0xFF;
        let b2 = (n >> 16) & 0xFF;
        let b3 = (n >> 24) & 0xFF;
        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
        format!("{}.{}.{}.{}:{}", b0, b1, b2, b3, port)
    } else {
        // IPv6 — simplified output for now
        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
        format!("[ipv6]:{}", port)
    }
}

// ============================================================
// TCP STATE DECODER
// ============================================================
//
// Convert hex TCP state code to a readable name.
// These codes come directly from the Linux kernel source (net/ipv4/tcp.c).
fn tcp_state_name(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _    => "UNKNOWN",
    }.to_string()
}

// ============================================================
// C2 PORT DETECTION
// ============================================================
//
// Ports commonly used by C2 frameworks, RATs, and backdoors.
// Flagged as Medium severity when no IP IOC match exists.
fn is_c2_port(port: u16) -> bool {
    matches!(port,
        4444        |   // Metasploit default reverse shell
        5555        |   // Android ADB / common RAT port
        6666 | 7777 |   // Generic backdoor ports
        1337 | 31337|   // "leet" — hacker tradition, Back Orifice legacy
        4899        |   // Radmin remote admin tool
        5900        |   // VNC — remote desktop, often abused
        6667 | 6668 |   // IRC — used by botnets for C2 channels
        8080        |   // Alt HTTP — frequently used for C2 proxying
        9001 | 9030     // Tor default OR/directory ports
    )
}

// ============================================================
// PROCESS ENRICHMENT (best-effort)
// ============================================================

// Walk /proc/PID/fd/ to find which process owns a socket inode.
// Best-effort — fails silently if we don't have permissions.
// Full implementation requires: parse inode from /proc/net/tcp col 9,
// then match against /proc/PID/fd/* symlink targets.
fn find_pid_for_socket(local_addr: &str) -> Result<u32> {
    // Suppress unused variable warning — local_addr will be used
    // when full inode-matching is implemented
    let _ = local_addr;
    Err(anyhow::anyhow!("PID lookup not yet implemented"))
}

fn get_process_name(pid: u32) -> Result<String> {
    // /proc/PID/comm contains just the process name, one line, max 15 chars
    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))?;
    Ok(comm.trim().to_string())
}
