// ============================================================
// src/agent/loop.rs
//
// The agentic investigation loop.
//
// This file is provider-agnostic. It works with any AI that
// implements the AiProvider trait — Claude, OpenAI, Groq, Ollama.
//
// Loop structure:
//   1. Send initial task + target to the AI
//   2. AI responds with tool calls (or final text)
//   3. Execute each tool call via dispatch_tool()
//   4. Append results to history, send back to AI
//   5. Repeat until AI returns only text (the final report)
//   6. Safety exit at max_iterations
// ============================================================

use anyhow::{anyhow, Result};
use colored::*;
use std::sync::Arc;

use crate::agent::provider::{AiProvider, ChatContent, ChatMessage, ToolResult};
use crate::agent::tools::{all_tools, dispatch_tool, extract_findings_from_tool_results};
use crate::report::Finding;

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

/// Run a full agentic investigation on `target_path`.
///
/// Returns `(report_markdown, findings)`.
pub async fn run_investigation(
    provider:       Arc<dyn AiProvider>,
    target_path:    &str,
    max_iterations: usize,
    verbose:        bool,
) -> Result<(String, Vec<Finding>)> {
    let tools = all_tools();

    println!(
        "\n{} Starting agentic investigation\n  Target:   {}\n  Provider: {}\n",
        "[AGENT]".bright_red().bold(),
        target_path.yellow(),
        provider.display_name().cyan(),
    );

    let seed = format!(
        "Perform a complete threat investigation on this Linux system. \
         Start by scanning the filesystem path '{}' and inspecting running processes. \
         Follow up on anything suspicious. \
         Write a final structured threat report when your investigation is complete.",
        target_path
    );

    let mut history:  Vec<ChatMessage> = vec![ChatMessage::user(seed)];
    let mut findings: Vec<Finding>     = Vec::new();

    for iteration in 1..=max_iterations {
        if verbose {
            println!(
                "{} Iteration {}/{}",
                "[LOOP]".cyan().dimmed(),
                iteration,
                max_iterations
            );
        }

        let response = provider.chat(&history, &tools, SYSTEM_PROMPT).await?;

        // ── AI called tools ───────────────────────────────────────────────────
        if !response.tool_calls.is_empty() {
            println!(
                "  {} AI called {} tool(s):",
                "→".bright_cyan(),
                response.tool_calls.len()
            );

            // Store the assistant's tool-call turn in history
            history.push(ChatMessage::assistant_tool_calls(response.tool_calls.clone()));

            let mut results: Vec<ToolResult> = Vec::new();

            for call in &response.tool_calls {
                print!("    {} {}(", "⚙".yellow(), call.name.white().bold());
                if let Some(obj) = call.input.as_object() {
                    let args: Vec<String> = obj.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    print!("{}", args.join(", ").dimmed());
                }
                println!(")");

                let result = dispatch_tool(&call.name, &call.input);

                findings.extend(extract_findings_from_tool_results(
                    &call.name, &call.input, &result,
                ));

                if verbose {
                    let preview: String = result.chars().take(200).collect();
                    println!(
                        "      {} {}{}",
                        "↳".dimmed(),
                        preview.dimmed(),
                        if result.len() > 200 { "…" } else { "" }
                    );
                }

                results.push(ToolResult {
                    tool_call_id: call.id.clone(),
                    content:      result,
                });
            }

            // Return all results as a single user turn
            history.push(ChatMessage::tool_results(results));
            continue;
        }

        // ── AI returned text: investigation complete ──────────────────────────
        if let Some(ref report) = response.text {
            println!(
                "\n{} Investigation complete after {} tool call round(s).\n",
                "[✓]".green().bold(),
                iteration - 1
            );
            return Ok((report.clone(), findings));
        }

        return Err(anyhow!(
            "AI returned an empty response on iteration {}. \
             Check your API key and model availability.",
            iteration
        ));
    }

    // Hit max_iterations — force final report
    println!(
        "\n{} Reached max iterations ({}), requesting final report...\n",
        "[!]".yellow().bold(),
        max_iterations
    );

    history.push(ChatMessage::user(
        "You have reached the investigation iteration limit. \
         Write your final threat report now based on all the information you have gathered. \
         Do not call any more tools."
    ));

    let final_response = provider.chat(&history, &[], SYSTEM_PROMPT).await?;

    let report = final_response.text.ok_or_else(|| {
        anyhow!("AI did not return a final report after hitting max_iterations")
    })?;

    Ok((report, findings))
}
