// ============================================================
// src/agent/mod.rs
//
// Agentic AI layer — provider-agnostic investigation engine.
//
//   provider.rs   — AiProvider trait + neutral ChatMessage types
//   providers/    — one impl per AI backend
//     claude.rs   — Anthropic Messages API
//     openai.rs   — OpenAI Chat Completions (also Groq, Ollama, Azure)
//   tools.rs      — security tool definitions + dispatch
//   loop.rs       — investigation loop (uses &dyn AiProvider)
//   client.rs     — kept for reference; superseded by providers/
// ============================================================

pub mod client;
pub mod provider;
pub mod providers;
pub mod r#loop;
pub mod tools;
