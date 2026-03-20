// ============================================================
// src/agent/provider.rs
//
// Provider-agnostic AI abstraction layer.
//
// Why this exists:
//   The original client.rs was Claude-specific. To support
//   OpenAI, Groq, Ollama, and any future provider, we define
//   a neutral internal message format and a trait that every
//   provider implements.
//
// Architecture:
//   loop.rs       — uses &dyn AiProvider, knows nothing about wire formats
//   provider.rs   — neutral types + AiProvider trait (this file)
//   providers/
//     claude.rs   — Anthropic Messages API (tool_use / tool_result blocks)
//     openai.rs   — OpenAI Chat Completions API (also covers Groq, Ollama,
//                   Azure OpenAI, Together AI — any OpenAI-compatible endpoint)
//
// Neutral message format:
//   We do NOT use Claude's wire format or OpenAI's wire format as the
//   internal representation. Instead we use typed Rust enums that each
//   provider serialises to their own JSON structure at call time.
// ============================================================

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use super::tools::ToolDefinition;

// ── Neutral message types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role:    Role,
    pub content: ChatContent,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Clone)]
pub enum ChatContent {
    /// Plain text — used for user prompts and final assistant answers
    Text(String),
    /// Assistant decided to call tools
    ToolCalls(Vec<ToolCall>),
    /// User returning results for each tool call
    ToolResults(Vec<ToolResult>),
}

/// One tool invocation requested by the AI
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id:    String,
    pub name:  String,
    pub input: Value,
}

/// The result we return for one tool invocation
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub tool_call_id: String,
    pub content:      String,
}

impl ChatMessage {
    pub fn user(text: impl Into<String>) -> Self {
        Self { role: Role::User, content: ChatContent::Text(text.into()) }
    }

    pub fn tool_results(results: Vec<ToolResult>) -> Self {
        Self { role: Role::User, content: ChatContent::ToolResults(results) }
    }

    pub fn assistant_tool_calls(calls: Vec<ToolCall>) -> Self {
        Self { role: Role::Assistant, content: ChatContent::ToolCalls(calls) }
    }

    pub fn assistant_text(text: impl Into<String>) -> Self {
        Self { role: Role::Assistant, content: ChatContent::Text(text.into()) }
    }
}

// ── Response from one AI turn ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct ChatResponse {
    /// Final text answer — present when the AI is done calling tools
    pub text:       Option<String>,
    /// Tools the AI wants to call this turn
    pub tool_calls: Vec<ToolCall>,
}

// ── Provider trait ────────────────────────────────────────────────────────────

/// Implemented by every AI backend. The investigation loop only depends on
/// this trait — it has no knowledge of Anthropic vs OpenAI wire formats.
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Send one turn of the conversation and return the AI's response.
    async fn chat(
        &self,
        messages: &[ChatMessage],
        tools:    &[ToolDefinition],
        system:   &str,
    ) -> Result<ChatResponse>;

    /// Human-readable name shown in the terminal (e.g. "Claude claude-sonnet-4-6")
    fn display_name(&self) -> String;
}

// ── Provider selection ────────────────────────────────────────────────────────

/// Which provider and model to use — parsed from CLI flags.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub kind:    ProviderKind,
    pub model:   String,
    pub api_key: String,
    /// Base URL override — used for Ollama, Azure, custom OpenAI-compatible APIs
    pub api_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderKind {
    Claude,
    OpenAi,
    Groq,
    Ollama,
}

impl ProviderKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "claude" | "anthropic"             => Some(Self::Claude),
            "openai" | "gpt"                   => Some(Self::OpenAi),
            "groq"                             => Some(Self::Groq),
            "ollama" | "local"                 => Some(Self::Ollama),
            _                                  => None,
        }
    }

    /// Default model for each provider
    pub fn default_model(&self) -> &'static str {
        match self {
            Self::Claude => "claude-sonnet-4-6",
            Self::OpenAi => "gpt-4o",
            Self::Groq   => "llama-3.3-70b-versatile",
            Self::Ollama => "llama3.2",
        }
    }

    /// Default base URL for each provider
    pub fn default_api_url(&self) -> &'static str {
        match self {
            Self::Claude => "https://api.anthropic.com/v1/messages",
            Self::OpenAi => "https://api.openai.com/v1/chat/completions",
            Self::Groq   => "https://api.groq.com/openai/v1/chat/completions",
            Self::Ollama => "http://localhost:11434/v1/chat/completions",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Claude => "Claude (Anthropic)",
            Self::OpenAi => "OpenAI",
            Self::Groq   => "Groq",
            Self::Ollama => "Ollama (local)",
        }
    }
}
