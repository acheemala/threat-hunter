// ============================================================
// src/agent/providers/claude.rs
//
// Anthropic Claude provider — implements AiProvider using the
// Anthropic Messages API with tool_use / tool_result blocks.
//
// Wire format:
//   POST https://api.anthropic.com/v1/messages
//   Headers: x-api-key, anthropic-version: 2023-06-01
//
//   Messages use content arrays:
//     user:      [{ type: "text", text: "..." }]
//                [{ type: "tool_result", tool_use_id: "...", content: "..." }]
//     assistant: [{ type: "text", text: "..." }]
//                [{ type: "tool_use", id: "...", name: "...", input: {...} }]
//
//   System prompt goes at the top level (not in messages).
// ============================================================

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::agent::provider::{
    AiProvider, ChatContent, ChatMessage, ChatResponse, ProviderConfig, Role, ToolCall,
};
use crate::agent::tools::ToolDefinition;

pub struct ClaudeProvider {
    http:    reqwest::Client,
    api_key: String,
    model:   String,
    api_url: String,
}

impl ClaudeProvider {
    pub fn new(config: &ProviderConfig) -> Self {
        Self {
            http:    reqwest::Client::new(),
            api_key: config.api_key.clone(),
            model:   config.model.clone(),
            api_url: config.api_url.clone()
                .unwrap_or_else(|| "https://api.anthropic.com/v1/messages".into()),
        }
    }

    /// Translate our neutral ChatMessage into the Anthropic wire format
    fn to_wire_messages(messages: &[ChatMessage]) -> Vec<Value> {
        messages.iter().map(|msg| {
            let role = match msg.role {
                Role::User      => "user",
                Role::Assistant => "assistant",
            };

            let content = match &msg.content {
                ChatContent::Text(t) => json!(t),

                ChatContent::ToolCalls(calls) => {
                    json!(calls.iter().map(|c| json!({
                        "type":  "tool_use",
                        "id":    c.id,
                        "name":  c.name,
                        "input": c.input,
                    })).collect::<Vec<_>>())
                }

                ChatContent::ToolResults(results) => {
                    json!(results.iter().map(|r| json!({
                        "type":        "tool_result",
                        "tool_use_id": r.tool_call_id,
                        "content":     r.content,
                    })).collect::<Vec<_>>())
                }
            };

            json!({ "role": role, "content": content })
        }).collect()
    }
}

#[async_trait]
impl AiProvider for ClaudeProvider {
    async fn chat(
        &self,
        messages: &[ChatMessage],
        tools:    &[ToolDefinition],
        system:   &str,
    ) -> Result<ChatResponse> {
        let wire_messages = Self::to_wire_messages(messages);

        let body = json!({
            "model":      self.model,
            "max_tokens": 4096,
            "system":     system,
            "tools":      tools,
            "messages":   wire_messages,
        });

        let resp = self.http
            .post(&self.api_url)
            .header("x-api-key",        &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type",      "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let json: Value = resp.json().await?;

        if !status.is_success() {
            let msg = json["error"]["message"].as_str().unwrap_or("unknown API error");
            return Err(anyhow!("Claude API error {}: {}", status, msg));
        }

        parse_claude_response(json)
    }

    fn display_name(&self) -> String {
        format!("Claude ({})", self.model)
    }
}

fn parse_claude_response(json: Value) -> Result<ChatResponse> {
    let content = json["content"]
        .as_array()
        .ok_or_else(|| anyhow!("Claude response missing 'content' array: {}", json))?;

    let mut text:       Option<String> = None;
    let mut tool_calls: Vec<ToolCall>  = Vec::new();

    for block in content {
        match block["type"].as_str() {
            Some("text") => {
                text = block["text"].as_str().map(|s| s.to_string());
            }
            Some("tool_use") => {
                tool_calls.push(ToolCall {
                    id:    block["id"].as_str().unwrap_or("").to_string(),
                    name:  block["name"].as_str().unwrap_or("").to_string(),
                    input: block["input"].clone(),
                });
            }
            _ => {}
        }
    }

    Ok(ChatResponse { text, tool_calls })
}
