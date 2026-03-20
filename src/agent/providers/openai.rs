// ============================================================
// src/agent/providers/openai.rs
//
// OpenAI-compatible provider — implements AiProvider using the
// OpenAI Chat Completions API format.
//
// This ONE implementation covers all OpenAI-compatible endpoints:
//   Provider      Base URL                                  Key env var
//   ─────────────────────────────────────────────────────────────────────
//   OpenAI        https://api.openai.com/v1                OPENAI_API_KEY
//   Groq          https://api.groq.com/openai/v1           GROQ_API_KEY
//   Ollama        http://localhost:11434/v1                 (none needed)
//   Azure OpenAI  https://<res>.openai.azure.com/openai/.. AZURE_OPENAI_KEY
//   Together AI   https://api.together.xyz/v1              TOGETHER_API_KEY
//   Any custom    --api-url <url>                          --api-key <key>
//
// Wire format:
//   POST <base_url>/chat/completions
//   Headers: Authorization: Bearer <key>
//
//   System prompt goes as first message: {"role": "system", "content": "..."}
//   Tool results go as:                  {"role": "tool", "tool_call_id": "...", "content": "..."}
//   Tool calls in response:              {"tool_calls": [{"id": "...", "function": {...}}]}
// ============================================================

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::agent::provider::{
    AiProvider, ChatContent, ChatMessage, ChatResponse, ProviderConfig, Role, ToolCall,
};
use crate::agent::tools::ToolDefinition;

pub struct OpenAiProvider {
    http:    reqwest::Client,
    api_key: String,
    model:   String,
    api_url: String,
}

impl OpenAiProvider {
    pub fn new(config: &ProviderConfig) -> Self {
        let default_url = config.kind.default_api_url().to_string();
        Self {
            http:    reqwest::Client::new(),
            api_key: config.api_key.clone(),
            model:   config.model.clone(),
            api_url: config.api_url.clone().unwrap_or(default_url),
        }
    }

    /// Translate our neutral ChatMessage list to OpenAI wire messages.
    /// The system prompt is prepended separately in chat().
    fn to_wire_messages(messages: &[ChatMessage]) -> Vec<Value> {
        let mut wire: Vec<Value> = Vec::new();

        for msg in messages {
            match &msg.content {
                ChatContent::Text(t) => {
                    let role = match msg.role {
                        Role::User      => "user",
                        Role::Assistant => "assistant",
                    };
                    wire.push(json!({ "role": role, "content": t }));
                }

                // Assistant turn: tool calls
                ChatContent::ToolCalls(calls) => {
                    let tool_calls: Vec<Value> = calls.iter().map(|c| json!({
                        "id":   c.id,
                        "type": "function",
                        "function": {
                            "name":      c.name,
                            // OpenAI requires arguments as a JSON *string*, not object
                            "arguments": serde_json::to_string(&c.input).unwrap_or_default(),
                        }
                    })).collect();

                    wire.push(json!({
                        "role":       "assistant",
                        "content":    null,
                        "tool_calls": tool_calls,
                    }));
                }

                // User turn: tool results — one message per result (OpenAI requirement)
                ChatContent::ToolResults(results) => {
                    for r in results {
                        wire.push(json!({
                            "role":         "tool",
                            "tool_call_id": r.tool_call_id,
                            "content":      r.content,
                        }));
                    }
                }
            }
        }

        wire
    }

    /// Translate our ToolDefinition to OpenAI function format
    fn to_wire_tools(tools: &[ToolDefinition]) -> Vec<Value> {
        tools.iter().map(|t| json!({
            "type": "function",
            "function": {
                "name":        t.name,
                "description": t.description,
                "parameters":  t.input_schema,
            }
        })).collect()
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    async fn chat(
        &self,
        messages: &[ChatMessage],
        tools:    &[ToolDefinition],
        system:   &str,
    ) -> Result<ChatResponse> {
        // OpenAI: system prompt is the first message in the array
        let mut wire_messages = vec![
            json!({ "role": "system", "content": system })
        ];
        wire_messages.extend(Self::to_wire_messages(messages));

        let mut body = json!({
            "model":    self.model,
            "messages": wire_messages,
        });

        // Only attach tools if there are any (Ollama requires no empty tools array)
        if !tools.is_empty() {
            body["tools"] = json!(Self::to_wire_tools(tools));
        }

        let mut req = self.http
            .post(&self.api_url)
            .header("content-type", "application/json")
            .json(&body);

        // Ollama local doesn't need auth; skip empty keys
        if !self.api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }

        let resp   = req.send().await?;
        let status = resp.status();
        let json: Value = resp.json().await?;

        if !status.is_success() {
            let msg = json["error"]["message"].as_str().unwrap_or("unknown API error");
            return Err(anyhow!("{} API error {}: {}", self.api_url, status, msg));
        }

        parse_openai_response(json)
    }

    fn display_name(&self) -> String {
        format!("{} ({})", self.api_url
            .replace("https://", "")
            .split('/')
            .next()
            .unwrap_or("openai"),
            self.model
        )
    }
}

fn parse_openai_response(json: Value) -> Result<ChatResponse> {
    let choice = json["choices"]
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow!("OpenAI response missing choices: {}", json))?;

    let message = &choice["message"];

    // Check for tool calls
    if let Some(tool_calls) = message["tool_calls"].as_array() {
        let calls: Vec<ToolCall> = tool_calls.iter().filter_map(|tc| {
            let id   = tc["id"].as_str()?.to_string();
            let name = tc["function"]["name"].as_str()?.to_string();
            // Arguments come as a JSON string — parse it back to Value
            let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
            let input = serde_json::from_str(args_str).unwrap_or(json!({}));
            Some(ToolCall { id, name, input })
        }).collect();

        if !calls.is_empty() {
            return Ok(ChatResponse { text: None, tool_calls: calls });
        }
    }

    // No tool calls — extract text response
    let text = message["content"].as_str().map(|s| s.to_string());

    Ok(ChatResponse { text, tool_calls: vec![] })
}
