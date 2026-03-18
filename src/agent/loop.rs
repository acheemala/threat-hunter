// ============================================================
// src/agent/loop.rs
//
// The agentic investigation loop.
//
// This is where "agentic" actually happens:
//   - We do NOT pre-decide what to scan
//   - We give Claude the initial findings and let IT decide
//     which tool to call next, in what order, with what parameters
//   - The loop runs until Claude stops calling tools (final text answer)
//     or we hit max_iterations as a safety guard
//
// Loop structure:
//
//   1. Run initial scan of the target path
//   2. Send initial findings + task to Claude
//   3. Claude responds with tool_use blocks (or final text)
//   4. For each tool_use: execute dispatch_tool(), append result to history
//   5. Send updated history back to Claude
//   6. Repeat from step 3
//   7. When Claude returns only text: that is the final investigation report
//
// Why max_iterations:
//   Without a cap, a confused model can loop indefinitely calling the
//   same tools. 10 iterations = ~10 tool calls, which is more than enough
//   to fully investigate a single host. Increase for deeper investigations.
//
// Why the system prompt matters:
//   The system prompt is the only place we constrain Claude's behavior.
//   It tells Claude: you are a threat analyst, not a chatbot. Be systematic.
//   Call tools before drawing conclusions. Write ATT&CK IDs in your report.
// ============================================================

use anyhow::{anyhow, Result};
use colored::*;
use serde_json::json;

use super::client::{ClaudeClient, Message};
use super::tools::{all_tools, dispatch_tool};

// ── System prompt ─────────────────────────────────────────────────────────────

/// The system prompt is Claude's "job description" for this investigation.
/// Key instructions:
///   1. Systematic: always scan before concluding
///   2. Correlated: connect filesystem + process + network findings
///   3. Formal: use MITRE ATT&CK IDs in every finding
///   4. Conservative: never assume clean — verify with tools
const SYSTEM_PROMPT: &str = "\
You are an expert threat analyst performing a live security investigation on a Linux system. \
You have access to tools that read the real filesystem, running processes, and network connections.

Your investigation protocol:
1. Start broad — use scan_filesystem and inspect_processes before forming conclusions
2. Dig deeper — when you find something suspicious, call read_file_content or get_process_detail
3. Correlate — look for connections between filesystem findings, suspicious processes, and network activity
4. Classify — call map_to_mitre for every significant finding before writing the report
5. Be conservative — if something is ambiguous, call another tool to verify; never assume clean

When writing your final report:
- Lead with the overall risk level: CLEAN / LOW / MEDIUM / HIGH / CRITICAL
- List every finding with: severity, description, file/PID/connection detail, MITRE ATT&CK ID
- Describe the likely attack chain if multiple findings correlate
- End with specific remediation recommendations

Do not speculate. Everything you state in the report must be backed by tool output you received.";

// ── Public entry point ────────────────────────────────────────────────────────

/// Run a full agentic investigation on `target_path`.
///
/// `api_key`        — ANTHROPIC_API_KEY value
/// `target_path`    — filesystem path to start the investigation
/// `max_iterations` — safety cap on tool call rounds (default: 10)
/// `verbose`        — if true, print each tool call and result to stdout
///
/// Returns the final investigation report as a String.
pub async fn run_investigation(
    api_key:        &str,
    target_path:    &str,
    max_iterations: usize,
    verbose:        bool,
) -> Result<String> {
    let client = ClaudeClient::new(api_key);
    let tools  = all_tools();

    println!(
        "\n{} Starting agentic investigation on {}\n",
        "[AGENT]".bright_red().bold(),
        target_path.yellow()
    );

    // ── Seed message: give Claude the task ───────────────────────────────────
    // We don't pre-scan here — let Claude decide what to do first.
    // This is the key difference from report.rs which runs all engines blindly.
    let seed = format!(
        "Perform a complete threat investigation on this Linux system. \
         Start by scanning the filesystem path '{}' and inspecting running processes. \
         Follow up on anything suspicious. \
         Write a final structured threat report when your investigation is complete.",
        target_path
    );

    let mut history: Vec<Message> = vec![Message::user(seed)];

    // ── Main agentic loop ─────────────────────────────────────────────────────
    for iteration in 1..=max_iterations {
        if verbose {
            println!(
                "{} Iteration {}/{}",
                "[LOOP]".cyan().dimmed(),
                iteration,
                max_iterations
            );
        }

        // Send current history to Claude
        let response = client.send(&history, &tools, SYSTEM_PROMPT).await?;

        // Append Claude's raw response to history so it sees its own tool calls
        history.push(Message::assistant(response.raw_content));

        // ── If Claude called tools: execute them ──────────────────────────────
        if !response.tool_calls.is_empty() {
            println!(
                "  {} Claude called {} tool(s):",
                "→".bright_cyan(),
                response.tool_calls.len()
            );

            // Execute each tool call and collect results
            // We batch all results into ONE user message (Claude API requirement:
            // all tool_results for a given assistant turn must be in one user turn)
            let mut result_blocks = Vec::new();

            for call in &response.tool_calls {
                print!("    {} {}(", "⚙".yellow(), call.name.white().bold());

                // Print the input args compactly
                if let Some(obj) = call.input.as_object() {
                    let args: Vec<String> = obj.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    print!("{}", args.join(", ").dimmed());
                }
                println!(")");

                // Execute the tool
                let result = dispatch_tool(&call.name, &call.input);

                if verbose {
                    // Print first 200 chars of result to avoid flooding the terminal
                    let preview: String = result.chars().take(200).collect();
                    println!(
                        "      {} {}{}",
                        "↳".dimmed(),
                        preview.dimmed(),
                        if result.len() > 200 { "…" } else { "" }
                    );
                }

                result_blocks.push(json!({
                    "type":        "tool_result",
                    "tool_use_id": call.id,
                    "content":     result,
                }));
            }

            // Append all tool results as a single user turn
            history.push(Message {
                role:    "user".into(),
                content: json!(result_blocks),
            });

            // Continue the loop — Claude will process the results and decide next step
            continue;
        }

        // ── Claude returned only text: investigation complete ─────────────────
        if let Some(ref report) = response.text {
            println!(
                "\n{} Investigation complete after {} tool call round(s).\n",
                "[✓]".green().bold(),
                iteration - 1
            );
            return Ok(report.clone());
        }

        // Edge case: empty response with no text and no tool calls
        return Err(anyhow!(
            "Claude returned an empty response on iteration {}. \
             Check your API key and model availability.",
            iteration
        ));
    }

    // Hit max_iterations — ask Claude to wrap up with what it has
    println!(
        "\n{} Reached max iterations ({}), requesting final report...\n",
        "[!]".yellow().bold(),
        max_iterations
    );

    history.push(Message::user(
        "You have reached the investigation iteration limit. \
         Write your final threat report now based on all the information you have gathered so far. \
         Do not call any more tools."
    ));

    let final_response = client.send(&history, &[], SYSTEM_PROMPT).await?;

    final_response.text.ok_or_else(|| {
        anyhow!("Claude did not return a final report after hitting max_iterations")
    })
}
