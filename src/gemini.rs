//! Gemini API client for the agent, over `curl`.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! The standard library has no TLS, and a TLS crate is exactly the kind of
//! dependency this tool refuses. Every modern Windows, macOS and Linux ships
//! `curl`, so HTTPS goes through it - the same "shell out to the OS tool you
//! already trust" choice `reg` and `schtasks` get elsewhere in this codebase.
//!
//! Models: the free tier of the Gemini API covers the Flash family. The client
//! walks a fallback chain (configured model → `gemini-2.5-flash` →
//! `gemini-2.5-flash-lite` → `gemini-3.1-flash-lite`) on a 404 (model not
//! available to this key), 429 (free-tier quota) or 5xx, so a run does not die
//! on a quota blip. Google's security-tuned models (`gemini-3.8-flash-cyber`,
//! Sec-Gemini) are gated to enrolled testers; anyone who has one sets
//! `gemini_model = …` in config.txt and it is tried first.

use std::path::PathBuf;

use crate::json::{self, Json};
use crate::util;

pub const DEFAULT_MODEL: &str = "gemini-3.8-flash";
pub const FALLBACK_MODELS: &[&str] = &["gemini-2.5-flash", "gemini-flash-latest", "gemini-2.5-flash-lite", "gemini-3.1-flash-lite"];
const ENDPOINT: &str = "https://generativelanguage.googleapis.com/v1beta/models";

/// Anything that can answer a turn with text and/or function calls. The live
/// implementation is `Gemini`; tests use a scripted one.
pub trait Model {
    /// Returns the model's `content` object (`{role, parts:[…]}`).
    fn generate(&mut self, system: &str, contents: &[Json], tools: &Json) -> Result<Json, String>;
    fn name(&self) -> String;
}

pub struct Gemini {
    key: String,
    models: Vec<String>,
    /// Index into `models` of the one currently in use.
    current: usize,
    pub last_usage: Option<(u64, u64)>,
}

impl Gemini {
    pub fn new(key: &str, preferred: Option<&str>) -> Gemini {
        let mut models: Vec<String> = Vec::new();
        if let Some(p) = preferred {
            if !p.trim().is_empty() {
                models.push(p.trim().to_string());
            }
        }
        for m in std::iter::once(DEFAULT_MODEL).chain(FALLBACK_MODELS.iter().copied()) {
            if !models.iter().any(|x| x == m) {
                models.push(m.to_string());
            }
        }
        Gemini { key: key.trim().to_string(), models, current: 0, last_usage: None }
    }

    fn call(&self, model: &str, body: &Json) -> Result<Json, String> {
        let url = format!("{ENDPOINT}/{model}:generateContent");
        let text = http_post_json(&url, &[("x-goog-api-key", &self.key)], &body.to_string())?;
        json::parse(&text).map_err(|e| format!("unreadable response from Gemini: {e}: {}", &text[..text.len().min(300)]))
    }
}

impl Model for Gemini {
    fn name(&self) -> String {
        self.models.get(self.current).cloned().unwrap_or_default()
    }

    fn generate(&mut self, system: &str, contents: &[Json], tools: &Json) -> Result<Json, String> {
        let body = Json::obj(vec![
            ("systemInstruction", Json::obj(vec![("parts", Json::arr(vec![Json::obj(vec![("text", Json::str(system))])]))])),
            ("contents", Json::Arr(contents.to_vec())),
            ("tools", Json::arr(vec![Json::obj(vec![("functionDeclarations", tools.clone())])])),
            ("toolConfig", Json::obj(vec![("functionCallingConfig", Json::obj(vec![("mode", Json::str("AUTO"))]))])),
            ("generationConfig", Json::obj(vec![("temperature", Json::Num(0.2)), ("maxOutputTokens", Json::Num(8192.0))])),
        ]);
        let mut last_err = String::from("no model available");
        let start = self.current;
        for attempt in 0..self.models.len() {
            let idx = (start + attempt) % self.models.len();
            let model = self.models[idx].clone();
            match self.call(&model, &body) {
                Ok(resp) => {
                    if let Some(err) = resp.get("error") {
                        let code = err.get("code").and_then(|c| c.as_f64()).unwrap_or(0.0) as u32;
                        let msg = err.str_of("message");
                        last_err = format!("{model}: HTTP {code} {msg}");
                        // Not this key's problem to fix: try the next model.
                        if code == 404 || code == 429 || code >= 500 || msg.to_ascii_lowercase().contains("quota") {
                            continue;
                        }
                        return Err(last_err);
                    }
                    self.current = idx;
                    if let Some(u) = resp.get("usageMetadata") {
                        self.last_usage = Some((u.u64_of("promptTokenCount", 0), u.u64_of("candidatesTokenCount", 0)));
                    }
                    let candidate = resp.path(&["candidates", "0"]).ok_or_else(|| {
                        let reason = resp.path(&["promptFeedback", "blockReason"]).and_then(|r| r.as_str()).unwrap_or("no candidates");
                        format!("{model}: empty reply ({reason})")
                    })?;
                    return candidate
                        .get("content")
                        .cloned()
                        .ok_or_else(|| format!("{model}: candidate without content (finishReason {})", candidate.str_of("finishReason")));
                }
                Err(e) => {
                    last_err = format!("{model}: {e}");
                    continue;
                }
            }
        }
        Err(last_err)
    }
}

// ---------------------------------------------------------------------------
// HTTP via curl
// ---------------------------------------------------------------------------

pub fn curl_available() -> bool {
    util::run("curl", &["--version"]).ok
}

fn temp_file(prefix: &str, contents: &str) -> Result<PathBuf, String> {
    let p = std::env::temp_dir().join(format!("{prefix}-{}-{}.json", std::process::id(), util::now_secs()));
    std::fs::write(&p, contents).map_err(|e| e.to_string())?;
    Ok(p)
}

/// POST a JSON body. Returns the response body; a non-2xx status still returns
/// the body (Gemini puts the error description there).
pub fn http_post_json(url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, String> {
    let file = temp_file("prh-req", body)?;
    let file_arg = format!("@{}", file.display());
    let mut args: Vec<String> = vec![
        "-sS".into(), "--max-time".into(), "180".into(), "-X".into(), "POST".into(),
        "-H".into(), "Content-Type: application/json".into(),
    ];
    for (k, v) in headers {
        args.push("-H".into());
        args.push(format!("{k}: {v}"));
    }
    args.push("--data-binary".into());
    args.push(file_arg);
    args.push(url.to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = util::run("curl", &refs);
    let _ = std::fs::remove_file(&file);
    if !out.ok && out.stdout.trim().is_empty() {
        return Err(format!("curl failed: {}", out.stderr.trim()));
    }
    Ok(out.stdout)
}

/// GET a URL as text (following redirects), with an ordinary browser UA so
/// search engines and advisory pages answer.
pub fn http_get(url: &str, headers: &[(&str, &str)], max_time_secs: u32) -> Result<String, String> {
    let mut args: Vec<String> = vec![
        "-sSL".into(), "--max-time".into(), max_time_secs.to_string(), "--compressed".into(),
        "-A".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) polinrider-hunter".into(),
    ];
    for (k, v) in headers {
        args.push("-H".into());
        args.push(format!("{k}: {v}"));
    }
    args.push(url.to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = util::run("curl", &refs);
    if !out.ok && out.stdout.trim().is_empty() {
        return Err(format!("curl failed: {}", out.stderr.trim()));
    }
    Ok(out.stdout)
}

/// Strip tags, scripts and styles from HTML and collapse whitespace.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    let bytes = html.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'<' {
            // Skip script/style blocks wholesale.
            for tag in ["script", "style", "noscript", "svg"] {
                if lower[i..].starts_with(&format!("<{tag}")) {
                    if let Some(end) = lower[i..].find(&format!("</{tag}")) {
                        i += end;
                    }
                }
            }
            if let Some(close) = html[i..].find('>') {
                let tag = &lower[i..i + close];
                if tag.starts_with("<br") || tag.starts_with("<p") || tag.starts_with("<div") || tag.starts_with("<li") || tag.starts_with("<tr") || tag.starts_with("<h") {
                    out.push('\n');
                }
                i += close + 1;
            } else {
                break;
            }
            continue;
        }
        // Decode the handful of entities that matter for readability.
        if bytes[i] == b'&' {
            let rest = &html[i..];
            let ents = [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&#x27;", "'"), ("&nbsp;", " ")];
            if let Some((e, r)) = ents.iter().find(|(e, _)| rest.starts_with(e)) {
                out.push_str(r);
                i += e.len();
                continue;
            }
        }
        // Push one whole UTF-8 char.
        let ch_len = utf8_len(bytes[i]);
        if let Some(s) = html.get(i..i + ch_len) {
            out.push_str(s);
        }
        i += ch_len;
    }
    // Collapse whitespace runs, keep paragraph breaks.
    let mut collapsed = String::with_capacity(out.len());
    let mut last_space = false;
    let mut newlines = 0;
    for ch in out.chars() {
        if ch == '\n' {
            newlines += 1;
            if newlines <= 2 {
                collapsed.push('\n');
            }
            last_space = true;
            continue;
        }
        if ch.is_whitespace() {
            if !last_space {
                collapsed.push(' ');
            }
            last_space = true;
            continue;
        }
        newlines = 0;
        last_space = false;
        collapsed.push(ch);
    }
    collapsed.trim().to_string()
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 { 1 } else if b >> 5 == 0b110 { 2 } else if b >> 4 == 0b1110 { 3 } else if b >> 3 == 0b11110 { 4 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_is_reduced_to_readable_text() {
        let t = html_to_text("<html><head><style>x{}</style><script>bad()</script></head><body><h1>Title</h1><p>Hello &amp; <b>world</b></p><ul><li>one</li><li>two</li></ul></body></html>");
        assert!(t.contains("Title"));
        assert!(t.contains("Hello & world"));
        assert!(!t.contains("bad()"));
        assert!(t.contains("one\ntwo") || t.contains("one\n two"));
    }

    #[test]
    fn fallback_chain_starts_with_the_preferred_model() {
        let g = Gemini::new("k", Some("gemini-3.8-flash-cyber"));
        assert_eq!(g.name(), "gemini-3.8-flash-cyber");
        assert!(g.models.contains(&"gemini-2.5-flash-lite".to_string()));
        let d = Gemini::new("k", None);
        assert_eq!(d.name(), DEFAULT_MODEL);
    }
}
