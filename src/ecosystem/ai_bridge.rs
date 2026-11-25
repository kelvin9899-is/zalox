//! Minimalist async LLM connector supporting OpenAI-compatible endpoints
//! (Groq, OpenRouter, DeepSeek, OpenAI) and Google Gemini REST APIs.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{ZaloxError, ZaloxResult};

/// Supported LLM provider backends.
#[derive(Debug, Clone)]
pub enum LlmProvider {
    /// Any OpenAI-compatible `/chat/completions` endpoint (Groq, OpenRouter, OpenAI, vLLM).
    OpenAiCompatible {
        base_url: String,
        api_key: String,
        model: String,
    },
    /// Google Gemini `generateContent` endpoint.
    Gemini { api_key: String, model: String },
}

impl LlmProvider {
    /// Preset for Groq ultra-low-latency inference (`https://api.groq.com/openai/v1`).
    pub fn groq(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self::OpenAiCompatible {
            base_url: "https://api.groq.com/openai/v1".into(),
            api_key: api_key.into(),
            model: model.into(),
        }
    }

    /// Preset for OpenRouter (`https://openrouter.ai/api/v1`).
    pub fn openrouter(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self::OpenAiCompatible {
            base_url: "https://openrouter.ai/api/v1".into(),
            api_key: api_key.into(),
            model: model.into(),
        }
    }

    /// Preset for Google Gemini (`gemini-2.5-flash` or newer).
    pub fn gemini(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self::Gemini {
            api_key: api_key.into(),
            model: model.into(),
        }
    }
}

/// Single conversational message turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTurn {
    pub role: String,
    pub content: String,
}

impl ChatTurn {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".into(),
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".into(),
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".into(),
            content: content.into(),
        }
    }
}

/// Lightweight stateless LLM completion helper ready to share across `BotRouter` state.
#[derive(Debug, Clone)]
pub struct LlmBridge {
    http: Client,
    provider: LlmProvider,
    system_prompt: Option<String>,
}

impl LlmBridge {
    pub fn new(provider: LlmProvider) -> Self {
        Self {
            http: Client::new(),
            provider,
            system_prompt: None,
        }
    }

    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Convenience helper for single-turn prompt -> reply text.
    pub async fn ask(&self, user_prompt: &str) -> ZaloxResult<String> {
        self.complete(&[ChatTurn::user(user_prompt)]).await
    }

    /// Executes a multi-turn chat completion request and returns the assistant's reply text.
    pub async fn complete(&self, history: &[ChatTurn]) -> ZaloxResult<String> {
        match &self.provider {
            LlmProvider::OpenAiCompatible {
                base_url,
                api_key,
                model,
            } => {
                let mut messages = Vec::with_capacity(history.len() + 1);
                if let Some(ref sys) = self.system_prompt {
                    messages.push(ChatTurn::system(sys.clone()));
                }
                messages.extend_from_slice(history);

                let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
                let resp: Value = self
                    .http
                    .post(&url)
                    .bearer_auth(api_key)
                    .json(&json!({
                        "model": model,
                        "messages": messages,
                    }))
                    .send()
                    .await?
                    .json()
                    .await?;

                resp.pointer("/choices/0/message/content")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        ZaloxError::Ecosystem(format!(
                            "Unexpected OpenAI-compatible response: {resp}"
                        ))
                    })
            }
            LlmProvider::Gemini { api_key, model } => {
                let url = format!(
                    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                );

                let contents: Vec<Value> = history
                    .iter()
                    .map(|t| {
                        let role = if t.role == "assistant" {
                            "model"
                        } else {
                            "user"
                        };
                        json!({
                            "role": role,
                            "parts": [{ "text": t.content }],
                        })
                    })
                    .collect();

                let mut body = json!({ "contents": contents });
                if let Some(ref sys) = self.system_prompt {
                    body["systemInstruction"] = json!({
                        "parts": [{ "text": sys }]
                    });
                }

                let resp: Value = self
                    .http
                    .post(&url)
                    .json(&body)
                    .send()
                    .await?
                    .json()
                    .await?;

                resp.pointer("/candidates/0/content/parts/0/text")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        ZaloxError::Ecosystem(format!("Unexpected Gemini response: {resp}"))
                    })
            }
        }
    }
}
