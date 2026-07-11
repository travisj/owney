//! The provider firewall: one trait, swappable backends. Claude (direct
//! HTTP, no SDK) is first-class; any OpenAI-compatible endpoint (Ollama,
//! vLLM, gateways) works for the local-model crowd.

use std::pin::Pin;

use serde_json::{Value, json};

use crate::AiError;

/// One structured-output request: the model must answer with JSON matching
/// `schema`.
#[derive(Debug, Clone)]
pub struct StructuredRequest {
    pub system: String,
    pub user: String,
    pub schema: Value,
    pub max_tokens: u32,
}

pub trait AiProvider: Send + Sync {
    /// Complete the request, returning the schema-shaped JSON.
    fn structured(
        &self,
        request: StructuredRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AiError>> + Send + '_>>;

    fn name(&self) -> &str;
}

/// Anthropic Messages API with forced tool use for structured output.
#[derive(Debug)]
pub struct ClaudeProvider {
    client: reqwest::Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl ClaudeProvider {
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            model,
            base_url: "https://api.anthropic.com".to_owned(),
        }
    }
}

impl AiProvider for ClaudeProvider {
    fn name(&self) -> &str {
        "claude"
    }

    fn structured(
        &self,
        request: StructuredRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AiError>> + Send + '_>> {
        Box::pin(async move {
            let body = json!({
                "model": self.model,
                "max_tokens": request.max_tokens,
                "system": request.system,
                "messages": [{"role": "user", "content": request.user}],
                "tools": [{
                    "name": "answer",
                    "description": "Return the structured answer.",
                    "input_schema": request.schema,
                }],
                "tool_choice": {"type": "tool", "name": "answer"},
            });

            let response = self
                .client
                .post(format!("{}/v1/messages", self.base_url))
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .json(&body)
                .send()
                .await
                .map_err(|err| AiError::Transport(err.to_string()))?;

            let status = response.status();
            let payload: Value = response
                .json()
                .await
                .map_err(|err| AiError::Transport(err.to_string()))?;
            if !status.is_success() {
                return Err(AiError::Provider(format!("{status}: {payload}")));
            }

            payload["content"]
                .as_array()
                .and_then(|content| content.iter().find(|part| part["type"] == "tool_use"))
                .map(|part| part["input"].clone())
                .ok_or_else(|| AiError::Provider(format!("no tool_use in reply: {payload}")))
        })
    }
}

#[derive(Debug)]
/// Any OpenAI-compatible /v1/chat/completions endpoint (Ollama, vLLM, ...).
/// Structured output by instruction + parse; less strict than Claude's
/// forced tool use, so results are validated by the caller anyway.
pub struct OpenAiCompatProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
}

impl OpenAiCompatProvider {
    pub fn new(base_url: String, api_key: Option<String>, model: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            api_key,
            model,
        }
    }
}

impl AiProvider for OpenAiCompatProvider {
    fn name(&self) -> &str {
        "openai-compat"
    }

    fn structured(
        &self,
        request: StructuredRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AiError>> + Send + '_>> {
        Box::pin(async move {
            let system = format!(
                "{}\n\nAnswer ONLY with a JSON object matching this schema, no prose:\n{}",
                request.system, request.schema
            );
            let body = json!({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": request.user},
                ],
                "response_format": {"type": "json_object"},
            });

            let mut http = self.client.post(format!(
                "{}/v1/chat/completions",
                self.base_url.trim_end_matches('/')
            ));
            if let Some(key) = &self.api_key {
                http = http.bearer_auth(key);
            }
            let response = http
                .json(&body)
                .send()
                .await
                .map_err(|err| AiError::Transport(err.to_string()))?;
            let status = response.status();
            let payload: Value = response
                .json()
                .await
                .map_err(|err| AiError::Transport(err.to_string()))?;
            if !status.is_success() {
                return Err(AiError::Provider(format!("{status}: {payload}")));
            }

            let text = payload["choices"][0]["message"]["content"]
                .as_str()
                .ok_or_else(|| AiError::Provider(format!("no content: {payload}")))?;
            serde_json::from_str(text)
                .map_err(|err| AiError::Provider(format!("bad JSON from model: {err}")))
        })
    }
}

/// Deterministic provider for tests: returns queued responses in order.
#[derive(Debug, Default)]
pub struct MockProvider {
    responses: std::sync::Mutex<std::collections::VecDeque<Value>>,
    pub requests: std::sync::Mutex<Vec<StructuredRequest>>,
}

impl MockProvider {
    pub fn queue(&self, response: Value) {
        self.responses.lock().expect("lock").push_back(response);
    }
}

impl AiProvider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }

    fn structured(
        &self,
        request: StructuredRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AiError>> + Send + '_>> {
        self.requests.lock().expect("lock").push(request);
        let response = self.responses.lock().expect("lock").pop_front();
        Box::pin(async move { response.ok_or_else(|| AiError::Provider("mock exhausted".into())) })
    }
}
