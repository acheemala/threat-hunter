// ============================================================
// src/agent/client.rs
//
// Minimal Claude API client — supports the Messages API with tool use.
//
// Why not use the official Anthropic Rust SDK?
//   There is no official Anthropic Rust SDK as of early 2025.
//   The community crate `anthropic` exists but is unmaintained.
//   We use reqwest + serde_json directly — this gives us full control
//   over the exact request shape and makes the API contract explicit.
//
// What this client does:
//   1. Sends a POST to https://api.anthropic.com/v1/messages
//   2. Includes the tools array so Claude can call our security engines
//   3. Returns the full response — the caller (loop.rs) inspects
//      whether the response contains text or tool_use blocks
//
// Claude API message flow with tool use:
//
//   Client → API:  { role: "user", content: "investigate /tmp" }
//                  + tools: [scan_filesystem, inspect_processes, ...]
//
//   API → Client:  { role: "assistant", content: [
//                     { type: "tool_use", name: "scan_filesystem",
//                       id: "toolu_01...", input: { path: "/tmp" } }
//                  ]}
//
//   Client → API:  { role: "user", content: [
//                     { type: "tool_result", tool_use_id: "toolu_01...",
//                       content: "3 suspicious files found: ..." }
//                  ]}
//
//   API → Client:  { role: "assistant", content: [
//                     { type: "text", text: "Based on the scan results..." }
//                  ]}
//
// The loop continues until the assistant returns only text (no tool_use blocks).
// ============================================================

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::tools::ToolDefinition;

// ── Constants ─────────────────────────────────────────────────────────────────

const API_URL:  &str = "https://api.anthropic.com/v1/messages";
const MODEL:    &str = "claude-sonnet-4-6";       // latest Sonnet — best tool-use reliability
const MAX_TOKENS: u32 = 4096;                     // per response; tool calls are usually small

// ── Request / response types ──────────────────────────────────────────────────

/// One message in the conversation history.
/// `role` is either "user" or "assistant".
/// `content` is a JSON Value because it can be:
///   - a plain string: "investigate /tmp"
///   - an array of content blocks: [{ type: "tool_use", ... }, { type: "text", ... }]
///   - an array of tool_result blocks (user turn after a tool call)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    pub role:    String,
    pub content: Value,
}

impl Message {
    /// Convenience: create a simple user text message.
    pub fn user(text: impl Into<String>) -> Self {
        Self { role: "user".into(), content: json!(text.into()) }
    }

    /// Convenience: create an assistant message with raw content Value.
    /// Used when replaying API responses into the conversation history.
    pub fn assistant(content: Value) -> Self {
        Self { role: "assistant".into(), content }
    }

    /// Create a tool_result message (user turn) from a completed tool call.
    #[allow(dead_code)]
    /// `tool_use_id` must match the `id` field in the tool_use block.
    /// `result` is the plain-text output from dispatch_tool().
    pub fn tool_result(tool_use_id: impl Into<String>, result: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: json!([{
                "type":        "tool_result",
                "tool_use_id": tool_use_id.into(),
                "content":     result.into(),
            }]),
        }
    }
}

/// A tool_use block extracted from the assistant response.
/// Claude sets `id`, `name`, and `input` — we execute `name(input)`
/// and return the result as a tool_result message.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id:    String,
    pub name:  String,
    pub input: Value,
}

/// The parsed response from a single API call.
/// The caller (loop.rs) checks `tool_calls` first — if non-empty,
/// dispatch them and continue the loop. If empty, `text` is the final answer.
#[derive(Debug)]
pub struct ApiResponse {
    pub text:       Option<String>,   // final text if no more tool calls
    pub tool_calls: Vec<ToolCall>,    // tool_use blocks Claude wants to execute
    pub raw_content: Value,           // full content array for history replay
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Stateless async Claude API client.
/// All state (conversation history) lives in loop.rs.
pub struct ClaudeClient {
    http:    reqwest::Client,
    api_key: String,
}

impl ClaudeClient {
    /// Create a new client. `api_key` should come from the ANTHROPIC_API_KEY env var.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            http:    reqwest::Client::new(),
            api_key: api_key.into(),
        }
    }

    /// Send one turn of the conversation to the Claude API.
    ///
    /// `messages`    — full conversation history so far (user + assistant turns)
    /// `tools`       — tool definitions (same list every turn)
    /// `system`      — system prompt (sets Claude's role as threat analyst)
    ///
    /// Returns ApiResponse with either tool_calls to execute or a final text answer.
    pub async fn send(
        &self,
        messages: &[Message],
        tools:    &[ToolDefinition],
        system:   &str,
    ) -> Result<ApiResponse> {
        let body = json!({
            "model":      MODEL,
            "max_tokens": MAX_TOKENS,
            "system":     system,
            "tools":      tools,
            "messages":   messages,
        });

        let response = self.http
            .post(API_URL)
            .header("x-api-key",         &self.api_key)
            .header("anthropic-version",  "2023-06-01")
            .header("content-type",       "application/json")
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        let json: Value = response.json().await?;

        // Surface API errors with the full error message from the response body
        if !status.is_success() {
            let msg = json["error"]["message"]
                .as_str()
                .unwrap_or("unknown API error");
            return Err(anyhow!("Claude API error {}: {}", status, msg));
        }

        parse_response(json)
    }
}

// ── Response parsing ──────────────────────────────────────────────────────────

/// Parse the raw JSON response from the Claude API into ApiResponse.
///
/// The `content` field is an array of blocks, each with a `type`:
///   "text"     → final answer from Claude
///   "tool_use" → Claude wants to call one of our tools
///
/// A single response can contain BOTH text and tool_use blocks.
/// When tool_use blocks are present, we execute them before continuing.
fn parse_response(json: Value) -> Result<ApiResponse> {
    let content = json["content"]
        .as_array()
        .ok_or_else(|| anyhow!("API response missing 'content' array: {}", json))?;

    let mut text:       Option<String> = None;
    let mut tool_calls: Vec<ToolCall>  = Vec::new();

    for block in content {
        match block["type"].as_str() {
            Some("text") => {
                text = block["text"].as_str().map(|s| s.to_string());
            }
            Some("tool_use") => {
                let id   = block["id"].as_str().unwrap_or("").to_string();
                let name = block["name"].as_str().unwrap_or("").to_string();
                let input = block["input"].clone();
                tool_calls.push(ToolCall { id, name, input });
            }
            _ => {} // ignore unknown block types
        }
    }

    Ok(ApiResponse {
        text,
        tool_calls,
        raw_content: json["content"].clone(),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_user_produces_correct_role() {
        let m = Message::user("hello");
        assert_eq!(m.role, "user");
        assert_eq!(m.content, json!("hello"));
    }

    #[test]
    fn message_tool_result_produces_correct_structure() {
        let m = Message::tool_result("toolu_01abc", "3 files found");
        assert_eq!(m.role, "user");
        let block = &m.content[0];
        assert_eq!(block["type"], "tool_result");
        assert_eq!(block["tool_use_id"], "toolu_01abc");
        assert_eq!(block["content"], "3 files found");
    }

    #[test]
    fn parse_response_extracts_text_block() {
        let json = json!({
            "content": [{ "type": "text", "text": "Investigation complete." }]
        });
        let r = parse_response(json).unwrap();
        assert_eq!(r.text.unwrap(), "Investigation complete.");
        assert!(r.tool_calls.is_empty());
    }

    #[test]
    fn parse_response_extracts_tool_use_block() {
        let json = json!({
            "content": [{
                "type":  "tool_use",
                "id":    "toolu_01xyz",
                "name":  "scan_filesystem",
                "input": { "path": "/tmp" }
            }]
        });
        let r = parse_response(json).unwrap();
        assert!(r.text.is_none());
        assert_eq!(r.tool_calls.len(), 1);
        assert_eq!(r.tool_calls[0].name, "scan_filesystem");
        assert_eq!(r.tool_calls[0].input["path"], "/tmp");
    }
}
