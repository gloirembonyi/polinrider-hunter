//! Gemini API client for the agent, and the `curl` transport every provider uses.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! The standard library has no TLS, and a TLS crate is exactly the kind of
//! dependency this tool refuses. Every modern Windows, macOS and Linux ships
//! `curl`, so HTTPS goes through it - the same "shell out to the OS tool you
//! already trust" choice `reg` and `schtasks` get elsewhere in this codebase.
//!
//! Secrets never go on curl's command line: a process's argv is readable by
//! every other process of the same user (Task Manager, `ps`, `wmic process`),
//! and an API key there is one `Get-CimInstance` away from a stealer. Headers
//! and the request body go into private temp files (`-H @file`,
//! `--data-binary @file`) that are deleted as soon as curl returns.
//!
//! Models: the free tier of the Gemini API covers the Flash family. The client
//! walks a fallback chain (configured model → `gemini-2.5-flash` →
//! `gemini-3.1-flash-lite` → `flash-lite-latest`) on a 404 (model not
//! available to this key), 429 (free-tier quota) or 5xx, so a run does not die
//! on a quota blip. Google's security-tuned models (`gemini-3.8-flash-cyber`,
//! Sec-Gemini) are gated to enrolled testers; anyone who has one sets
//! `gemini_model = …` in config.txt and it is tried first.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::json::{self, Json};
use crate::util;

pub const DEFAULT_MODEL: &str = "gemini-3.8-flash";
pub const FALLBACK_MODELS: &[&str] = &["gemini-2.5-flash", "gemini-flash-latest", "gemini-3.1-flash-lite", "gemini-flash-lite-latest", "gemini-2.5-flash-lite"];
const ENDPOINT: &str = "https://generativelanguage.googleapis.com/v1beta/models";

/// Gemini 3 rejects a replayed function call without the signature it issued;
/// history written by another provider has none, and this documented value
/// tells the API not to validate that part.
const FOREIGN_SIGNATURE: &str = "skip_thought_signature_validator";

/// Anything that can answer a turn with text and/or function calls. The live
/// implementation is `Gemini`; tests use a scripted one.
pub trait Model {
    /// Returns the model's `content` object (`{role, parts:[…]}`).
    fn generate(&mut self, system: &str, contents: &[Json], tools: &Json) -> Result<Json, String>;
    fn name(&self) -> String;
    /// (input, output) tokens of the last call, when the provider reports them.
    fn usage(&self) -> Option<(u64, u64)> {
        None
    }
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
        // Transient server errors retry on the same model; quota (429) and
        // "no such model" move down the chain instead (see `generate`).
        let reply = post_json_retry(&url, &[("x-goog-api-key", &self.key)], &body.to_string(), 180, |s| matches!(s, 408 | 500 | 502 | 503 | 504))?;
        json::parse(&reply.body).map_err(|e| format!("unreadable response from Gemini (HTTP {}): {e}: {}", reply.status, head(&reply.body, 300)))
    }
}

/// The `generateContent` request body for the shared history.
pub fn request_body(system: &str, contents: &[Json], tools: &Json) -> Json {
    // Gemini wants alternating roles; the shared history can hold two user
    // turns in a row (tool results, then a nudge), so merge them.
    let mut turns: Vec<Json> = Vec::new();
    for t in contents.iter().map(gemini_turn) {
        if let (Some(Json::Obj(prev)), Json::Obj(cur)) = (turns.last_mut(), &t) {
            let same = prev.iter().find(|(k, _)| k == "role").map(|(_, v)| v.clone()) == cur.iter().find(|(k, _)| k == "role").map(|(_, v)| v.clone());
            if same {
                let extra = cur.iter().find(|(k, _)| k == "parts").and_then(|(_, v)| v.as_arr()).cloned().unwrap_or_default();
                if let Some((_, Json::Arr(parts))) = prev.iter_mut().find(|(k, _)| k == "parts") {
                    parts.extend(extra);
                }
                continue;
            }
        }
        turns.push(t);
    }
    Json::obj(vec![
        ("systemInstruction", Json::obj(vec![("parts", Json::arr(vec![Json::obj(vec![("text", Json::str(system))])]))])),
        ("contents", Json::Arr(turns)),
        ("tools", Json::arr(vec![Json::obj(vec![("functionDeclarations", tools.clone())])])),
        ("toolConfig", Json::obj(vec![("functionCallingConfig", Json::obj(vec![("mode", Json::str("AUTO"))]))])),
        ("generationConfig", Json::obj(vec![("temperature", Json::Num(0.2)), ("maxOutputTokens", Json::Num(8192.0))])),
    ])
}

impl Model for Gemini {
    fn name(&self) -> String {
        format!("gemini/{}", self.models.get(self.current).cloned().unwrap_or_default())
    }

    fn usage(&self) -> Option<(u64, u64)> {
        self.last_usage
    }

    fn generate(&mut self, system: &str, contents: &[Json], tools: &Json) -> Result<Json, String> {
        let body = request_body(system, contents, tools);
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
                    // A candidate that stopped before saying anything (safety,
                    // recitation, max tokens) comes back without `content`.
                    let content = candidate.get("content").cloned().unwrap_or_else(|| Json::obj(vec![("role", Json::str("model")), ("parts", Json::Arr(vec![]))]));
                    if content.get("parts").and_then(|p| p.as_arr()).map(|p| p.is_empty()).unwrap_or(true) && candidate.str_of("finishReason") != "STOP" {
                        return Err(format!("{model}: reply without content (finishReason {})", candidate.str_of("finishReason")));
                    }
                    return Ok(content);
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

/// One shared-history turn in the exact shape Gemini accepts.
///
/// The history also carries other providers' bookkeeping (call ids, a
/// provider tag, raw content blocks to replay); Gemini rejects unknown fields,
/// so only the role, the three part kinds it knows and the `thoughtSignature`
/// it issued go out. Gemini 3 refuses multi-turn tool use when a function call
/// comes back without its signature.
fn gemini_turn(turn: &Json) -> Json {
    let role = if turn.str_of("role") == "model" { "model" } else { "user" };
    let foreign = role == "model" && !turn.str_of("provider").is_empty() && turn.str_of("provider") != "gemini";
    let mut signed_first_call = false;
    let parts: Vec<Json> = turn
        .get("parts")
        .and_then(|p| p.as_arr())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            let sig = p.str_of("thoughtSignature");
            let mut out = if let Some(t) = p.get("text") {
                vec![("text", t.clone())]
            } else if let Some(c) = p.get("functionCall") {
                vec![("functionCall", Json::obj(vec![("name", Json::str(c.str_of("name"))), ("args", c.get("args").cloned().unwrap_or(Json::Obj(vec![])))]))]
            } else if let Some(r) = p.get("functionResponse") {
                vec![("functionResponse", Json::obj(vec![("name", Json::str(r.str_of("name"))), ("response", r.get("response").cloned().unwrap_or(Json::Obj(vec![])))]))]
            } else {
                return None;
            };
            if !sig.is_empty() {
                out.push(("thoughtSignature", Json::str(sig)));
            } else if foreign && p.get("functionCall").is_some() && !signed_first_call {
                out.push(("thoughtSignature", Json::str(FOREIGN_SIGNATURE)));
            }
            if p.get("functionCall").is_some() {
                signed_first_call = true;
            }
            Some(Json::obj(out))
        })
        .collect();
    let parts = if parts.is_empty() { vec![Json::obj(vec![("text", Json::str("(continue)"))])] } else { parts };
    Json::obj(vec![("role", Json::str(role)), ("parts", Json::Arr(parts))])
}

// ---------------------------------------------------------------------------
// HTTP via curl
// ---------------------------------------------------------------------------

pub fn curl_available() -> bool {
    util::run("curl", &["--version"]).ok
}

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A private temp file, deleted when dropped (on success, error or panic).
///
/// The name mixes the pid, the clock, a counter and std's randomly seeded
/// hasher, and the file is created with `create_new`, so another local user
/// can neither predict it nor pre-plant it. On Unix it is 0600; on Windows the
/// per-user temp directory already denies other users.
pub struct TempFile {
    pub path: PathBuf,
}

impl TempFile {
    pub fn create(prefix: &str, contents: &[u8]) -> Result<TempFile, String> {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let mut last = String::new();
        for _ in 0..8 {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let mut h = RandomState::new().build_hasher();
            h.write_u128(nanos);
            h.write_u64(seq);
            let name = format!("{prefix}-{}-{nanos:x}-{seq}-{:016x}", std::process::id(), h.finish());
            let path = std::env::temp_dir().join(name);
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            match o.open(&path) {
                Ok(mut f) => {
                    let tf = TempFile { path };
                    f.write_all(contents).map_err(|e| e.to_string())?;
                    return Ok(tf);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = e.to_string(),
                Err(e) => return Err(format!("temp file: {e}")),
            }
        }
        Err(format!("temp file: {last}"))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The header file curl reads with `-H @file`: one `Name: value` per line.
fn header_file(headers: &[(&str, &str)]) -> Result<Option<TempFile>, String> {
    if headers.is_empty() {
        return Ok(None);
    }
    let mut s = String::new();
    for (k, v) in headers {
        // A newline in a value would inject a header; keys never contain one.
        s.push_str(&format!("{k}: {}\n", v.replace(['\r', '\n'], "")));
    }
    TempFile::create("prh-h", s.as_bytes()).map(Some)
}

const STATUS_MARK: &str = "\n__PRH_HTTP__";

/// A response: status (0 when curl could not tell) and body.
pub struct HttpReply {
    pub status: u16,
    pub body: String,
    /// Where a 3xx points, when curl reported it.
    pub location: String,
}

/// Run curl with `args`, appending the status line marker, and split it off.
fn curl(mut args: Vec<String>, headers: &[(&str, &str)]) -> Result<HttpReply, String> {
    let hf = header_file(headers)?;
    if let Some(h) = &hf {
        args.push("-H".into());
        args.push(format!("@{}", h.path.display()));
    }
    args.push("--write-out".into());
    args.push(format!("{STATUS_MARK}%{{http_code}} %{{redirect_url}}"));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = util::run("curl", &refs);
    drop(hf);
    let (body, tail) = match out.stdout.rfind(STATUS_MARK) {
        Some(i) => (out.stdout[..i].to_string(), out.stdout[i + STATUS_MARK.len()..].to_string()),
        None => (out.stdout.clone(), String::new()),
    };
    let mut it = tail.trim().splitn(2, ' ');
    let status: u16 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let location = it.next().unwrap_or("").trim().to_string();
    if !out.ok && body.trim().is_empty() && status == 0 {
        return Err(format!("curl failed: {}", out.stderr.trim()));
    }
    Ok(HttpReply { status, body, location })
}

/// POST a JSON body. Returns the response body; a non-2xx status still returns
/// the body (Gemini puts the error description there).
pub fn http_post_json(url: &str, headers: &[(&str, &str)], body: &str) -> Result<String, String> {
    http_post_json_timeout(url, headers, body, 180)
}

/// `http_post_json` with a caller-chosen ceiling: an agentic turn on a large
/// model can think for minutes.
pub fn http_post_json_timeout(url: &str, headers: &[(&str, &str)], body: &str, max_time_secs: u32) -> Result<String, String> {
    http_post_json_status(url, headers, body, max_time_secs).map(|r| r.body)
}

/// POST JSON and return status and body.
pub fn http_post_json_status(url: &str, headers: &[(&str, &str)], body: &str, max_time_secs: u32) -> Result<HttpReply, String> {
    let file = TempFile::create("prh-req", body.as_bytes())?;
    let mut all: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
    all.extend_from_slice(headers);
    let args: Vec<String> = vec![
        "-sS".into(), "--max-time".into(), max_time_secs.to_string(), "-X".into(), "POST".into(),
        "--proto".into(), "=https,http".into(),
        "--data-binary".into(), format!("@{}", file.path.display()), url.to_string(),
    ];
    curl(args, &all)
    // `file` drops here, deleting the request body.
}

/// Statuses worth another try: timeout, rate limit, server trouble, overload.
pub fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 409 | 429 | 500 | 502 | 503 | 504 | 529)
}

/// POST JSON with up to three attempts and a growing backoff when `retry`
/// says the status is transient (or curl could not connect).
pub fn post_json_retry(url: &str, headers: &[(&str, &str)], body: &str, max_time_secs: u32, retry: impl Fn(u16) -> bool) -> Result<HttpReply, String> {
    let mut last = String::new();
    for attempt in 0..3u64 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2 + 5 * attempt * attempt));
        }
        match http_post_json_status(url, headers, body, max_time_secs) {
            Ok(r) if retry(r.status) && attempt < 2 => last = format!("HTTP {}: {}", r.status, head(&r.body, 200)),
            Ok(r) => return Ok(r),
            // A timed-out model call is not retried: it already took the whole budget.
            Err(e) if attempt < 2 && !e.contains("timed out") => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(format!("gave up after 3 attempts: {last}"))
}

/// GET a URL as text (following up to 5 http(s) redirects), with an ordinary
/// browser UA so search engines and advisory pages answer. For fixed,
/// trusted endpoints; the agent's `web_fetch` uses `http_get_once` and checks
/// every hop itself.
pub fn http_get(url: &str, headers: &[(&str, &str)], max_time_secs: u32) -> Result<String, String> {
    let args: Vec<String> = vec![
        "-sS".into(), "-L".into(), "--max-redirs".into(), "5".into(), "--proto".into(), "=https,http".into(), "--proto-redir".into(), "=https,http".into(),
        "--max-time".into(), max_time_secs.to_string(), "--compressed".into(),
        "-A".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) polinrider-hunter".into(), url.to_string(),
    ];
    curl(args, headers).map(|r| r.body)
}

/// One GET without following redirects; the caller decides whether the
/// `location` of a 3xx is safe to visit. `pin` = (host, port, ip) makes curl
/// connect to the address the caller already vetted (no DNS rebinding).
pub fn http_get_once(url: &str, max_time_secs: u32, max_bytes: u64, pin: Option<(&str, u16, &str)>) -> Result<HttpReply, String> {
    let mut args: Vec<String> = vec![
        "-sS".into(), "--proto".into(), "=https,http".into(), "--max-time".into(), max_time_secs.to_string(), "--compressed".into(),
        "--max-filesize".into(), max_bytes.to_string(),
        "-A".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) polinrider-hunter".into(),
    ];
    if let Some((host, port, ip)) = pin {
        let ip = if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() };
        args.push("--resolve".into());
        args.push(format!("{host}:{port}:{ip}"));
    }
    args.push(url.to_string());
    curl(args, &[])
}

fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
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
            for tag in ["script", "style", "noscript", "svg", "template"] {
                if lower[i..].starts_with(&format!("<{tag}")) {
                    match lower[i..].find(&format!("</{tag}")) {
                        Some(end) => i += end,
                        None => i = bytes.len().saturating_sub(1),
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
        // An unterminated script never leaks its body.
        assert!(!html_to_text("<p>a</p><script>steal()").contains("steal"));
    }

    #[test]
    fn fallback_chain_starts_with_the_preferred_model() {
        let g = Gemini::new("k", Some("gemini-3.8-flash-cyber"));
        assert_eq!(g.name(), "gemini/gemini-3.8-flash-cyber");
        assert!(g.models.contains(&"gemini-2.5-flash-lite".to_string()));
        let d = Gemini::new("k", None);
        assert_eq!(d.name(), format!("gemini/{DEFAULT_MODEL}"));
    }

    fn call_part(name: &str, sig: Option<&str>) -> Json {
        let mut p = vec![("functionCall", Json::obj(vec![("name", Json::str(name)), ("args", Json::obj(vec![]))]))];
        if let Some(s) = sig {
            p.push(("thoughtSignature", Json::str(s)));
        }
        Json::obj(p)
    }

    #[test]
    fn thought_signatures_are_replayed_and_foreign_calls_are_marked() {
        let history = vec![
            Json::obj(vec![("role", Json::str("user")), ("parts", Json::arr(vec![Json::obj(vec![("text", Json::str("go"))])]))]),
            // Gemini's own turn: signature kept verbatim, no extra fields.
            Json::obj(vec![("role", Json::str("model")), ("parts", Json::arr(vec![call_part("scan", Some("SIG-1"))]))]),
            Json::obj(vec![("role", Json::str("user")), ("parts", Json::arr(vec![Json::obj(vec![("functionResponse", Json::obj(vec![("name", Json::str("scan")), ("id", Json::str("x")), ("response", Json::obj(vec![("ok", Json::Bool(true))]))]))])]))]),
            // A turn another provider wrote: the first call gets the skip marker.
            Json::obj(vec![("role", Json::str("model")), ("provider", Json::str("anthropic")), ("raw", Json::arr(vec![])), ("parts", Json::arr(vec![call_part("a", None), call_part("b", None)]))]),
            Json::obj(vec![("role", Json::str("user")), ("parts", Json::arr(vec![Json::obj(vec![("text", Json::str("one"))])]))]),
            Json::obj(vec![("role", Json::str("user")), ("parts", Json::arr(vec![Json::obj(vec![("text", Json::str("two"))])]))]),
        ];
        let b = request_body("sys", &history, &Json::arr(vec![]));
        assert_eq!(b.path(&["contents", "1", "parts", "0", "thoughtSignature"]).and_then(|v| v.as_str()), Some("SIG-1"));
        assert!(b.path(&["contents", "2", "parts", "0", "functionResponse", "id"]).is_none(), "unknown fields are not sent");
        assert_eq!(b.path(&["contents", "3", "parts", "0", "thoughtSignature"]).and_then(|v| v.as_str()), Some(FOREIGN_SIGNATURE));
        assert!(b.path(&["contents", "3", "parts", "1", "thoughtSignature"]).is_none());
        assert!(b.path(&["contents", "3", "provider"]).is_none());
        // Consecutive user turns are merged into one.
        let contents = b.get("contents").and_then(|c| c.as_arr()).unwrap();
        assert_eq!(contents.len(), 5);
        assert_eq!(contents[4].path(&["parts", "1", "text"]).and_then(|v| v.as_str()), Some("two"));
    }

    #[test]
    fn temp_files_are_unique_private_and_removed() {
        let a = TempFile::create("prh-test", b"secret").unwrap();
        let b = TempFile::create("prh-test", b"secret").unwrap();
        assert_ne!(a.path, b.path);
        assert_eq!(std::fs::read(&a.path).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&a.path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let p = a.path.clone();
        drop(a);
        assert!(!p.exists());
    }

    #[test]
    fn header_values_cannot_inject_lines() {
        let h = header_file(&[("x-api-key", "abc\r\nX-Evil: 1")]).unwrap().unwrap();
        let s = std::fs::read_to_string(&h.path).unwrap();
        assert_eq!(s, "x-api-key: abcX-Evil: 1\n");
    }

    #[test]
    fn retryable_statuses() {
        for s in [408, 429, 500, 502, 503, 504, 529] {
            assert!(is_retryable_status(s), "{s}");
        }
        for s in [200, 400, 401, 403, 404] {
            assert!(!is_retryable_status(s), "{s}");
        }
    }
}
