//! Every AI provider the agent can talk to, behind the one `Model` trait.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! The agent keeps its conversation in one shape - Gemini's `contents`
//! (`{role, parts:[{text} | {functionCall} | {functionResponse}]}`), which is
//! what it was first written against - and each provider here translates that
//! shape to its own wire format and back. So a session can switch provider or
//! model halfway through (`/provider`, `/model`) and keep its history.
//!
//! * `anthropic` - Claude, over the Messages API (default `claude-opus-5-5`).
//! * `openai`, `openrouter`, `groq`, `deepseek`, `ollama`, `custom` - anything
//!   that speaks the OpenAI Chat Completions format, which is most of them,
//!   including local models through Ollama / LM Studio (no key needed).
//! * `gemini` - Google, in `gemini.rs` (free tier available).
//!
//! HTTPS goes through `curl` for the same reason as everywhere else in this
//! tool: no TLS crate.

use crate::config::Config;
use crate::gemini::{self, Model};
use crate::json::{self, Json};

pub const ANTHROPIC_DEFAULT_MODEL: &str = "claude-opus-5-5";

/// A provider the agent can use, with its defaults.
pub struct ProviderInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub env: &'static str,
    pub default_model: &'static str,
    pub base_url: &'static str,
    pub key_url: &'static str,
    pub needs_key: bool,
}

pub const PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo { id: "anthropic", label: "Anthropic Claude", env: "ANTHROPIC_API_KEY", default_model: ANTHROPIC_DEFAULT_MODEL, base_url: "https://api.anthropic.com", key_url: "https://console.anthropic.com/settings/keys", needs_key: true },
    ProviderInfo { id: "openai", label: "OpenAI", env: "OPENAI_API_KEY", default_model: "gpt-4.1", base_url: "https://api.openai.com/v1", key_url: "https://platform.openai.com/api-keys", needs_key: true },
    ProviderInfo { id: "gemini", label: "Google Gemini (free tier)", env: "GEMINI_API_KEY", default_model: gemini::DEFAULT_MODEL, base_url: "https://generativelanguage.googleapis.com", key_url: "https://aistudio.google.com/apikey", needs_key: true },
    ProviderInfo { id: "openrouter", label: "OpenRouter (many models, one key)", env: "OPENROUTER_API_KEY", default_model: "openrouter/auto", base_url: "https://openrouter.ai/api/v1", key_url: "https://openrouter.ai/keys", needs_key: true },
    ProviderInfo { id: "groq", label: "Groq", env: "GROQ_API_KEY", default_model: "llama-3.3-70b-versatile", base_url: "https://api.groq.com/openai/v1", key_url: "https://console.groq.com/keys", needs_key: true },
    ProviderInfo { id: "deepseek", label: "DeepSeek", env: "DEEPSEEK_API_KEY", default_model: "deepseek-chat", base_url: "https://api.deepseek.com/v1", key_url: "https://platform.deepseek.com/api_keys", needs_key: true },
    ProviderInfo { id: "ollama", label: "Ollama (local, no key)", env: "OLLAMA_API_KEY", default_model: "llama3.1", base_url: "http://localhost:11434/v1", key_url: "https://ollama.com/download", needs_key: false },
    ProviderInfo { id: "custom", label: "Any OpenAI-compatible endpoint (set ai_base_url)", env: "CUSTOM_AI_API_KEY", default_model: "", base_url: "", key_url: "", needs_key: false },
];

pub fn provider(id: &str) -> Option<&'static ProviderInfo> {
    PROVIDERS.iter().find(|p| p.id.eq_ignore_ascii_case(id.trim()))
}

/// The key for `provider`: environment first, then config.
pub fn key_for(provider_id: &str, cfg: &Config) -> Option<String> {
    let p = provider(provider_id)?;
    if let Ok(k) = std::env::var(p.env) {
        if !k.trim().is_empty() {
            return Some(k.trim().to_string());
        }
    }
    let k = cfg.ai_keys.iter().find(|(id, _)| id == p.id).map(|(_, k)| k.clone()).unwrap_or_default();
    let k = if k.is_empty() && p.id == "gemini" { cfg.gemini_key.clone() } else { k };
    if k.trim().is_empty() {
        None
    } else {
        Some(k.trim().to_string())
    }
}

/// Which provider to use: explicit, then configured, then the first with a key.
pub fn resolve_provider(cli: Option<&str>, cfg: &Config) -> Option<String> {
    if let Some(p) = cli.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(p.to_ascii_lowercase());
    }
    if let Ok(p) = std::env::var("POLINRIDER_PROVIDER") {
        if !p.trim().is_empty() {
            return Some(p.trim().to_ascii_lowercase());
        }
    }
    if !cfg.ai_provider.trim().is_empty() {
        return Some(cfg.ai_provider.trim().to_ascii_lowercase());
    }
    PROVIDERS.iter().filter(|p| p.needs_key).find(|p| key_for(p.id, cfg).is_some()).map(|p| p.id.to_string())
}

/// Mask a key for display: first 6, last 4.
pub fn mask(k: &str) -> String {
    let k = k.trim();
    if k.len() <= 12 {
        return "*".repeat(k.len());
    }
    format!("{}…{}", &k[..6], &k[k.len() - 4..])
}

/// Build the model for `provider_id`.
pub fn build(provider_id: &str, model: Option<&str>, key: Option<&str>, cfg: &Config) -> Result<Box<dyn Model>, String> {
    let p = provider(provider_id).ok_or_else(|| {
        format!("unknown provider `{provider_id}` - one of: {}", PROVIDERS.iter().map(|p| p.id).collect::<Vec<_>>().join(", "))
    })?;
    if !gemini::curl_available() {
        return Err("`curl` was not found on PATH - the agent uses it for HTTPS. Install curl (it ships with Windows 10+, macOS and every Linux).".into());
    }
    let key = key.map(str::to_string).or_else(|| key_for(p.id, cfg));
    if p.needs_key && key.is_none() {
        return Err(format!(
            "no API key for {}. Get one at {}, then run\n  polinrider-hunter ai key {} <KEY>\nor set {}.",
            p.label, p.key_url, p.id, p.env
        ));
    }
    let key = key.unwrap_or_default();
    let model = model.map(str::trim).filter(|m| !m.is_empty()).map(str::to_string).or_else(|| {
        if !cfg.ai_model.trim().is_empty() && cfg.ai_provider.eq_ignore_ascii_case(p.id) {
            Some(cfg.ai_model.trim().to_string())
        } else if p.id == "gemini" && !cfg.gemini_model.trim().is_empty() {
            Some(cfg.gemini_model.trim().to_string())
        } else {
            None
        }
    });
    match p.id {
        "gemini" => Ok(Box::new(gemini::Gemini::new(&key, model.as_deref()))),
        "anthropic" => Ok(Box::new(Anthropic::new(&key, model.as_deref().unwrap_or(p.default_model), &cfg.ai_base_url))),
        _ => {
            let base = if p.id == "custom" || !cfg.ai_base_url.trim().is_empty() && cfg.ai_provider.eq_ignore_ascii_case(p.id) {
                cfg.ai_base_url.trim().to_string()
            } else {
                p.base_url.to_string()
            };
            if base.is_empty() {
                return Err("provider `custom` needs ai_base_url (e.g. http://localhost:1234/v1): polinrider-hunter ai use custom <model> --base-url <url>".into());
            }
            let m = model.unwrap_or_else(|| p.default_model.to_string());
            if m.is_empty() {
                return Err(format!("provider `{}` needs a model name: polinrider-hunter ai use {} <model>", p.id, p.id));
            }
            Ok(Box::new(OpenAiCompat::new(p.id, &key, &m, &base)))
        }
    }
}

// ---------------------------------------------------------------------------
// Shared conversions
// ---------------------------------------------------------------------------

/// Gemini-style uppercase schema types -> JSON Schema.
pub fn to_json_schema(v: &Json) -> Json {
    match v {
        Json::Obj(pairs) => Json::Obj(
            pairs
                .iter()
                .map(|(k, val)| {
                    if k == "type" {
                        if let Some(s) = val.as_str() {
                            return (k.clone(), Json::str(s.to_ascii_lowercase()));
                        }
                    }
                    (k.clone(), to_json_schema(val))
                })
                .collect(),
        ),
        Json::Arr(items) => Json::Arr(items.iter().map(to_json_schema).collect()),
        other => other.clone(),
    }
}

fn parts_of(turn: &Json) -> Vec<Json> {
    turn.get("parts").and_then(|p| p.as_arr()).cloned().unwrap_or_default()
}

/// A stable id for a call that came without one (Gemini's do not).
fn call_id(call: &Json, turn_idx: usize, part_idx: usize) -> String {
    let id = call.str_of("id");
    if id.is_empty() {
        format!("call_{turn_idx}_{part_idx}")
    } else {
        id
    }
}

/// Pair each functionResponse with the id of the call it answers, in order.
fn response_ids(contents: &[Json]) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut pending: Vec<(String, String)> = Vec::new(); // (name, id)
    for (ti, turn) in contents.iter().enumerate() {
        let mut ids = Vec::new();
        for (pi, part) in parts_of(turn).iter().enumerate() {
            if let Some(c) = part.get("functionCall") {
                pending.push((c.str_of("name"), call_id(c, ti, pi)));
            }
            if let Some(r) = part.get("functionResponse") {
                let name = r.str_of("name");
                let explicit = r.str_of("id");
                let id = if !explicit.is_empty() {
                    pending.retain(|(_, i)| *i != explicit);
                    explicit
                } else if let Some(pos) = pending.iter().position(|(n, _)| *n == name) {
                    pending.remove(pos).1
                } else {
                    format!("call_orphan_{ti}_{pi}")
                };
                ids.push(id);
            }
        }
        out.push(ids);
    }
    out
}

fn response_text(r: &Json) -> String {
    let resp = r.get("response").cloned().unwrap_or(Json::Null);
    resp.to_string()
}

// ---------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------

pub struct Anthropic {
    key: String,
    model: String,
    base: String,
    pub last_usage: Option<(u64, u64)>,
}

impl Anthropic {
    pub fn new(key: &str, model: &str, base: &str) -> Anthropic {
        let base = if base.trim().is_empty() || !base.contains("anthropic") { "https://api.anthropic.com".to_string() } else { base.trim().trim_end_matches('/').to_string() };
        Anthropic { key: key.trim().to_string(), model: model.trim().to_string(), base, last_usage: None }
    }

    /// The request body, built from the shared history.
    pub fn body(&self, system: &str, contents: &[Json], tools: &Json) -> Json {
        let ids = response_ids(contents);
        let mut messages: Vec<Json> = Vec::new();
        for (ti, turn) in contents.iter().enumerate() {
            let role = if turn.str_of("role") == "model" { "assistant" } else { "user" };
            // Replay this provider's own assistant content verbatim: thinking
            // blocks must come back unchanged or the API rejects them.
            if role == "assistant" && turn.str_of("provider") == "anthropic" {
                if let Some(raw) = turn.get("raw") {
                    messages.push(Json::obj(vec![("role", Json::str(role)), ("content", raw.clone())]));
                    continue;
                }
            }
            let mut blocks: Vec<Json> = Vec::new();
            let mut ri = 0usize;
            for (pi, part) in parts_of(turn).iter().enumerate() {
                if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                    if !t.trim().is_empty() {
                        blocks.push(Json::obj(vec![("type", Json::str("text")), ("text", Json::str(t))]));
                    }
                } else if let Some(c) = part.get("functionCall") {
                    blocks.push(Json::obj(vec![
                        ("type", Json::str("tool_use")),
                        ("id", Json::str(call_id(c, ti, pi))),
                        ("name", Json::str(c.str_of("name"))),
                        ("input", c.get("args").cloned().unwrap_or(Json::Obj(vec![]))),
                    ]));
                } else if let Some(r) = part.get("functionResponse") {
                    let id = ids[ti].get(ri).cloned().unwrap_or_default();
                    ri += 1;
                    let failed = r.path(&["response", "ok"]).and_then(|v| v.as_bool()) == Some(false);
                    blocks.push(Json::obj(vec![
                        ("type", Json::str("tool_result")),
                        ("tool_use_id", Json::str(id)),
                        ("content", Json::str(response_text(r))),
                        ("is_error", Json::Bool(failed)),
                    ]));
                }
            }
            if blocks.is_empty() {
                blocks.push(Json::obj(vec![("type", Json::str("text")), ("text", Json::str("(continue)"))]));
            }
            messages.push(Json::obj(vec![("role", Json::str(role)), ("content", Json::Arr(blocks))]));
        }
        let tool_list: Vec<Json> = tools
            .as_arr()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|t| {
                Json::obj(vec![
                    ("name", Json::str(t.str_of("name"))),
                    ("description", Json::str(t.str_of("description"))),
                    ("input_schema", to_json_schema(t.get("parameters").unwrap_or(&Json::Obj(vec![])))),
                ])
            })
            .collect();
        Json::obj(vec![
            ("model", Json::str(&self.model)),
            ("max_tokens", Json::Num(16000.0)),
            ("system", Json::str(system)),
            ("messages", Json::Arr(messages)),
            ("tools", Json::Arr(tool_list)),
            // Thinking stays on (adaptive). The agent trims old tool results
            // when the context grows, which edits history; drop_block lets the
            // API drop the thinking blocks that edit invalidates instead of
            // rejecting the whole request.
            ("thinking", Json::obj(vec![
                ("type", Json::str("adaptive")),
                ("block_binding", Json::obj(vec![("prefix_mismatch_behavior", Json::str("drop_block"))])),
            ])),
            ("output_config", Json::obj(vec![("effort", Json::str("high"))])),
            // Malware analysis can trip a safety classifier; the server-side
            // fallback re-runs a declined turn on a suitable model instead of
            // stopping the investigation.
            ("fallbacks", Json::str("default")),
        ])
    }

    /// Translate a Messages API response into a shared-history turn.
    pub fn parse(&mut self, resp: &Json) -> Result<Json, String> {
        if let Some(err) = resp.get("error") {
            return Err(format!("{}: {} {}", self.model, err.str_of("type"), err.str_of("message")));
        }
        if let Some(u) = resp.get("usage") {
            self.last_usage = Some((u.u64_of("input_tokens", 0), u.u64_of("output_tokens", 0)));
        }
        let stop = resp.str_of("stop_reason");
        let content = resp.get("content").and_then(|c| c.as_arr()).cloned().unwrap_or_default();
        if stop == "refusal" {
            let d = resp.get("stop_details").cloned().unwrap_or(Json::Null);
            return Err(format!(
                "{} declined this turn (category: {}). {} Rephrase the request, or switch model with /model.",
                self.model,
                d.str_of("category"),
                d.str_of("explanation")
            ));
        }
        let mut parts: Vec<Json> = Vec::new();
        for b in &content {
            match b.str_of("type").as_str() {
                "text" => parts.push(Json::obj(vec![("text", Json::str(b.str_of("text")))])),
                "tool_use" => parts.push(Json::obj(vec![("functionCall", Json::obj(vec![
                    ("id", Json::str(b.str_of("id"))),
                    ("name", Json::str(b.str_of("name"))),
                    ("args", b.get("input").cloned().unwrap_or(Json::Obj(vec![]))),
                ]))])),
                _ => {}
            }
        }
        if stop == "max_tokens" && parts.is_empty() {
            parts.push(Json::obj(vec![("text", Json::str("(the reply hit the token limit; ask me to continue)"))]));
        }
        Ok(Json::obj(vec![
            ("role", Json::str("model")),
            ("parts", Json::Arr(parts)),
            ("provider", Json::str("anthropic")),
            ("raw", Json::Arr(content)),
        ]))
    }
}

impl Model for Anthropic {
    fn name(&self) -> String {
        format!("anthropic/{}", self.model)
    }

    fn usage(&self) -> Option<(u64, u64)> {
        self.last_usage
    }

    fn generate(&mut self, system: &str, contents: &[Json], tools: &Json) -> Result<Json, String> {
        let body = self.body(system, contents, tools);
        let url = format!("{}/v1/messages", self.base);
        let headers = [
            ("x-api-key", self.key.as_str()),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "thinking-binding-controls-2026-08-01,server-side-fallback-2026-07-01"),
        ];
        let mut last = String::new();
        for attempt in 0..3 {
            let text = gemini::http_post_json_timeout(&url, &headers, &body.to_string(), 600)?;
            let resp = json::parse(&text).map_err(|e| format!("unreadable reply from Anthropic: {e}: {}", &text[..text.len().min(300)]))?;
            // Retry overload / rate limit with a short backoff.
            let kind = resp.path(&["error", "type"]).and_then(|t| t.as_str()).unwrap_or("").to_string();
            if matches!(kind.as_str(), "overloaded_error" | "rate_limit_error" | "api_error") && attempt < 2 {
                last = kind;
                std::thread::sleep(std::time::Duration::from_secs(4 * (attempt + 1) as u64));
                continue;
            }
            return self.parse(&resp);
        }
        Err(format!("Anthropic kept failing: {last}"))
    }
}

// ---------------------------------------------------------------------------
// OpenAI-compatible (OpenAI, OpenRouter, Groq, DeepSeek, Ollama, LM Studio…)
// ---------------------------------------------------------------------------

pub struct OpenAiCompat {
    provider: String,
    key: String,
    model: String,
    base: String,
    pub last_usage: Option<(u64, u64)>,
}

impl OpenAiCompat {
    pub fn new(provider: &str, key: &str, model: &str, base: &str) -> OpenAiCompat {
        OpenAiCompat { provider: provider.to_string(), key: key.trim().to_string(), model: model.trim().to_string(), base: base.trim().trim_end_matches('/').to_string(), last_usage: None }
    }

    pub fn body(&self, system: &str, contents: &[Json], tools: &Json) -> Json {
        let ids = response_ids(contents);
        let mut messages: Vec<Json> = vec![Json::obj(vec![("role", Json::str("system")), ("content", Json::str(system))])];
        for (ti, turn) in contents.iter().enumerate() {
            let is_model = turn.str_of("role") == "model";
            let parts = parts_of(turn);
            if is_model {
                let text: String = parts.iter().filter_map(|p| p.get("text").and_then(|t| t.as_str())).collect::<Vec<_>>().join("\n");
                let calls: Vec<Json> = parts
                    .iter()
                    .enumerate()
                    .filter_map(|(pi, p)| p.get("functionCall").map(|c| (pi, c)))
                    .map(|(pi, c)| {
                        Json::obj(vec![
                            ("id", Json::str(call_id(c, ti, pi))),
                            ("type", Json::str("function")),
                            ("function", Json::obj(vec![
                                ("name", Json::str(c.str_of("name"))),
                                ("arguments", Json::str(c.get("args").cloned().unwrap_or(Json::Obj(vec![])).to_string())),
                            ])),
                        ])
                    })
                    .collect();
                let mut m = vec![("role", Json::str("assistant")), ("content", if text.is_empty() { Json::Null } else { Json::str(text) })];
                if !calls.is_empty() {
                    m.push(("tool_calls", Json::Arr(calls)));
                }
                messages.push(Json::obj(m));
            } else {
                let mut ri = 0usize;
                let mut text = String::new();
                for part in &parts {
                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                        text.push_str(t);
                        text.push('\n');
                    } else if let Some(r) = part.get("functionResponse") {
                        let id = ids[ti].get(ri).cloned().unwrap_or_default();
                        ri += 1;
                        messages.push(Json::obj(vec![("role", Json::str("tool")), ("tool_call_id", Json::str(id)), ("content", Json::str(response_text(r)))]));
                    }
                }
                if !text.trim().is_empty() {
                    messages.push(Json::obj(vec![("role", Json::str("user")), ("content", Json::str(text.trim_end()))]));
                }
            }
        }
        let tool_list: Vec<Json> = tools
            .as_arr()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|t| {
                Json::obj(vec![
                    ("type", Json::str("function")),
                    ("function", Json::obj(vec![
                        ("name", Json::str(t.str_of("name"))),
                        ("description", Json::str(t.str_of("description"))),
                        ("parameters", to_json_schema(t.get("parameters").unwrap_or(&Json::Obj(vec![])))),
                    ])),
                ])
            })
            .collect();
        Json::obj(vec![("model", Json::str(&self.model)), ("messages", Json::Arr(messages)), ("tools", Json::Arr(tool_list)), ("tool_choice", Json::str("auto"))])
    }

    pub fn parse(&mut self, resp: &Json) -> Result<Json, String> {
        if let Some(err) = resp.get("error") {
            let msg = if let Some(s) = err.as_str() { s.to_string() } else { format!("{} {}", err.str_of("type"), err.str_of("message")) };
            return Err(format!("{}/{}: {msg}", self.provider, self.model));
        }
        if let Some(u) = resp.get("usage") {
            self.last_usage = Some((u.u64_of("prompt_tokens", 0), u.u64_of("completion_tokens", 0)));
        }
        let msg = resp.path(&["choices", "0", "message"]).cloned().ok_or_else(|| format!("{}/{}: reply without choices: {}", self.provider, self.model, &resp.to_string()[..resp.to_string().len().min(300)]))?;
        let mut parts: Vec<Json> = Vec::new();
        if let Some(t) = msg.get("content").and_then(|t| t.as_str()) {
            if !t.trim().is_empty() {
                parts.push(Json::obj(vec![("text", Json::str(t))]));
            }
        }
        for c in msg.get("tool_calls").and_then(|c| c.as_arr()).cloned().unwrap_or_default() {
            let f = c.get("function").cloned().unwrap_or(Json::Null);
            let raw = f.str_of("arguments");
            let args = if raw.trim().is_empty() { Json::Obj(vec![]) } else { json::parse(&raw).or_else(|_| json::parse_loose(&raw)).unwrap_or(Json::Obj(vec![])) };
            parts.push(Json::obj(vec![("functionCall", Json::obj(vec![("id", Json::str(c.str_of("id"))), ("name", Json::str(f.str_of("name"))), ("args", args)]))]));
        }
        Ok(Json::obj(vec![("role", Json::str("model")), ("parts", Json::Arr(parts)), ("provider", Json::str(self.provider.as_str()))]))
    }
}

impl Model for OpenAiCompat {
    fn name(&self) -> String {
        format!("{}/{}", self.provider, self.model)
    }

    fn usage(&self) -> Option<(u64, u64)> {
        self.last_usage
    }

    fn generate(&mut self, system: &str, contents: &[Json], tools: &Json) -> Result<Json, String> {
        let body = self.body(system, contents, tools);
        let url = format!("{}/chat/completions", self.base);
        let auth = format!("Bearer {}", self.key);
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if !self.key.is_empty() {
            headers.push(("Authorization", auth.as_str()));
        }
        if self.provider == "openrouter" {
            headers.push(("X-Title", "polinrider-hunter"));
        }
        let mut last = String::new();
        for attempt in 0..3 {
            let text = gemini::http_post_json_timeout(&url, &headers, &body.to_string(), 600)?;
            let resp = json::parse(&text).map_err(|e| format!("unreadable reply from {}: {e}: {}", self.provider, &text[..text.len().min(300)]))?;
            let code = resp.path(&["error", "code"]).map(|c| c.to_string()).unwrap_or_default();
            if (code.contains("429") || code.contains("rate") || code.contains("503")) && attempt < 2 {
                last = code;
                std::thread::sleep(std::time::Duration::from_secs(4 * (attempt + 1) as u64));
                continue;
            }
            return self.parse(&resp);
        }
        Err(format!("{} kept failing: {last}", self.provider))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history() -> Vec<Json> {
        vec![
            Json::obj(vec![("role", Json::str("user")), ("parts", Json::arr(vec![Json::obj(vec![("text", Json::str("scan please"))])]))]),
            Json::obj(vec![("role", Json::str("model")), ("parts", Json::arr(vec![
                Json::obj(vec![("text", Json::str("Scanning."))]),
                Json::obj(vec![("functionCall", Json::obj(vec![("name", Json::str("scan")), ("args", Json::obj(vec![("quick", Json::Bool(true))]))]))]),
            ]))]),
            Json::obj(vec![("role", Json::str("user")), ("parts", Json::arr(vec![
                Json::obj(vec![("functionResponse", Json::obj(vec![("name", Json::str("scan")), ("response", Json::obj(vec![("ok", Json::Bool(true))]))]))]),
            ]))]),
        ]
    }

    fn tools() -> Json {
        Json::arr(vec![Json::obj(vec![
            ("name", Json::str("scan")),
            ("description", Json::str("scan")),
            ("parameters", Json::obj(vec![("type", Json::str("OBJECT")), ("properties", Json::obj(vec![("quick", Json::obj(vec![("type", Json::str("BOOLEAN"))]))]))])),
        ])])
    }

    #[test]
    fn anthropic_request_pairs_tool_use_with_tool_result() {
        let a = Anthropic::new("k", ANTHROPIC_DEFAULT_MODEL, "");
        let b = a.body("sys", &history(), &tools());
        let msgs = b.get("messages").unwrap().as_arr().unwrap();
        assert_eq!(msgs.len(), 3);
        let use_id = msgs[1].path(&["content", "1", "id"]).unwrap().as_str().unwrap().to_string();
        assert_eq!(msgs[1].path(&["content", "1", "type"]).unwrap().as_str(), Some("tool_use"));
        assert_eq!(msgs[2].path(&["content", "0", "tool_use_id"]).unwrap().as_str(), Some(use_id.as_str()));
        assert_eq!(b.path(&["tools", "0", "input_schema", "type"]).unwrap().as_str(), Some("object"));
        assert_eq!(b.path(&["tools", "0", "input_schema", "properties", "quick", "type"]).unwrap().as_str(), Some("boolean"));
        assert_eq!(b.str_of("model"), "claude-opus-5-5");
    }

    #[test]
    fn anthropic_reply_keeps_raw_blocks_for_replay() {
        let mut a = Anthropic::new("k", ANTHROPIC_DEFAULT_MODEL, "");
        let resp = json::parse(r#"{"stop_reason":"tool_use","content":[{"type":"thinking","thinking":"","signature":"sig"},{"type":"text","text":"Looking."},{"type":"tool_use","id":"toolu_1","name":"scan","input":{"quick":true}}],"usage":{"input_tokens":10,"output_tokens":5}}"#).unwrap();
        let turn = a.parse(&resp).unwrap();
        assert_eq!(turn.path(&["parts", "1", "functionCall", "id"]).unwrap().as_str(), Some("toolu_1"));
        // Replayed verbatim on the next request, thinking block included.
        let mut h = history();
        h.truncate(1);
        h.push(turn);
        let b = a.body("sys", &h, &tools());
        assert_eq!(b.path(&["messages", "1", "content", "0", "type"]).unwrap().as_str(), Some("thinking"));
        assert_eq!(b.path(&["messages", "1", "content", "0", "signature"]).unwrap().as_str(), Some("sig"));
    }

    #[test]
    fn anthropic_refusal_is_an_error_not_an_empty_turn() {
        let mut a = Anthropic::new("k", ANTHROPIC_DEFAULT_MODEL, "");
        let resp = json::parse(r#"{"stop_reason":"refusal","stop_details":{"category":"cyber","explanation":"x"},"content":[]}"#).unwrap();
        assert!(a.parse(&resp).unwrap_err().contains("cyber"));
    }

    #[test]
    fn openai_request_and_reply_round_trip() {
        let mut o = OpenAiCompat::new("openai", "k", "gpt-4.1", "https://api.openai.com/v1");
        let b = o.body("sys", &history(), &tools());
        let msgs = b.get("messages").unwrap().as_arr().unwrap();
        assert_eq!(msgs[0].str_of("role"), "system");
        let call_id = msgs[2].path(&["tool_calls", "0", "id"]).unwrap().as_str().unwrap().to_string();
        assert_eq!(msgs[3].str_of("role"), "tool");
        assert_eq!(msgs[3].str_of("tool_call_id"), call_id);
        let resp = json::parse(r#"{"choices":[{"message":{"content":"ok","tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.txt\"}"}}]}}]}"#).unwrap();
        let turn = o.parse(&resp).unwrap();
        assert_eq!(turn.path(&["parts", "1", "functionCall", "args", "path"]).unwrap().as_str(), Some("a.txt"));
    }

    #[test]
    fn every_provider_is_known_and_masking_hides_keys() {
        assert!(provider("Anthropic").is_some());
        assert!(provider("nope").is_none());
        assert_eq!(mask("sk-ant-abcdefghijklmnop"), "sk-ant…mnop");
    }
}
