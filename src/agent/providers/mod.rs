pub mod claude;
pub mod openai;

use anyhow::{anyhow, Result};
use std::sync::Arc;

use crate::agent::provider::{AiProvider, ProviderConfig, ProviderKind};
use claude::ClaudeProvider;
use openai::OpenAiProvider;

/// Build the right provider from a resolved ProviderConfig.
pub fn build(config: &ProviderConfig) -> Result<Arc<dyn AiProvider>> {
    match config.kind {
        ProviderKind::Claude => Ok(Arc::new(ClaudeProvider::new(config))),
        ProviderKind::OpenAi |
        ProviderKind::Groq   |
        ProviderKind::Ollama => Ok(Arc::new(OpenAiProvider::new(config))),
    }
}

/// Resolve a ProviderConfig from CLI arguments + environment variables.
///
/// Key resolution order per provider:
///   Claude  → --api-key | ANTHROPIC_API_KEY
///   OpenAI  → --api-key | OPENAI_API_KEY
///   Groq    → --api-key | GROQ_API_KEY
///   Ollama  → no key required
pub fn resolve_config(
    provider_str: &str,
    model_override: Option<&str>,
    api_key_override: Option<&str>,
    api_url_override: Option<&str>,
) -> Result<ProviderConfig> {
    let kind = ProviderKind::from_str(provider_str)
        .ok_or_else(|| anyhow!(
            "Unknown provider '{}'. Valid options: claude, openai, groq, ollama",
            provider_str
        ))?;

    let model = model_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| kind.default_model().to_string());

    let api_key = if let Some(k) = api_key_override {
        k.to_string()
    } else {
        match kind {
            ProviderKind::Claude => std::env::var("ANTHROPIC_API_KEY").unwrap_or_default(),
            ProviderKind::OpenAi => std::env::var("OPENAI_API_KEY").unwrap_or_default(),
            ProviderKind::Groq   => std::env::var("GROQ_API_KEY").unwrap_or_default(),
            ProviderKind::Ollama => String::new(), // no key needed
        }
    };

    // Require a key for cloud providers
    if api_key.is_empty() && kind != ProviderKind::Ollama {
        let env_var = match kind {
            ProviderKind::Claude => "ANTHROPIC_API_KEY",
            ProviderKind::OpenAi => "OPENAI_API_KEY",
            ProviderKind::Groq   => "GROQ_API_KEY",
            _                    => "API_KEY",
        };
        return Err(anyhow!(
            "No API key for provider '{}'. Set {} or pass --api-key.",
            provider_str, env_var
        ));
    }

    Ok(ProviderConfig {
        kind,
        model,
        api_key,
        api_url: api_url_override.map(|s| s.to_string()),
    })
}
