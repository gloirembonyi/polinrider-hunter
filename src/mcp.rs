//! A Model Context Protocol server over stdio.
//!
//! The built-in `agent` needs an LLM API key. Many people already have an AI
//! coding tool that has one - Claude Code, Cursor, Codex, Windsurf - and those
//! speak MCP. `polinrider-hunter mcp` lets such a tool drive the hunter: it
//! reads JSON-RPC 2.0 requests one per line on stdin, writes replies one per
//! line on stdout, and logs to stderr only (stdout is the wire).
//!
//! Every tool runs this same binary as a child with the matching subcommand
//! and `--json`, and hands the output back as text. That keeps one code path
//! per command, and it keeps the server itself trivial: no state, no threads,
//! nothing the agent could leave half-done. Anything that changes the machine
//! or a remote is a dry run unless the call carries `confirm: true`, so an
//! agent has to show the user the plan before it can act on it.

use std::io::{BufRead, Write};

use crate::json::{self, Json};

/// Protocol revisions this server will echo back when a client asks for them.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// The newest revision, offered when a client asks for one we do not know.
pub const DEFAULT_PROTOCOL: &str = "2025-06-18";

/// Upper bound on the text a tool result carries. Past this it is cut, with a
/// note, rather than fed to a model whole.
pub const MAX_TEXT: usize = 60 * 1024;

/// What the agent is told at `initialize`.
pub const INSTRUCTIONS: &str = "polinrider-hunter detects and removes the PolinRider supply-chain malware \
(and related campaigns) from machines and git repositories. Workflow: `scan` the project paths, \
`repos_audit` every branch of each repository (paths or URLs; nothing is checked out), then \
`repos_repair` as a dry run, show the user exactly what would be pushed, and only then call \
`repos_repair` again with confirm:true; finish with another `repos_audit`. `clean`, `hunt`, \
`processes` with kill and `persistence` with remove follow the same rule: dry run first, \
confirm:true to apply. The audit reports, per infected branch, whether the current user can push \
(`can_write`), who owns the repository and who pushed the infection - when can_write is false, the \
fix is to ask those people to run `polinrider-hunter repos --repair` on their clone. Never check out, \
pull, or npm-install an infected repository or branch; audit and repair it in place through these tools. \
Results are JSON documents, one per line.";

const CONFIRM_NOTE: &str = "Dry run. Show this to the user and call again with confirm:true to apply.";

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

/// Serve until stdin closes. Returns the process exit code.
pub fn run(version: &str) -> i32 {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    eprintln!("polinrider-hunter {version} mcp: serving JSON-RPC on stdio");
    loop {
        let Some(msg) = read_message(&mut reader) else { break };
        if msg.trim().is_empty() {
            continue;
        }
        if let Some(reply) = handle_text(&msg, version) {
            let mut out = stdout.lock();
            if writeln!(out, "{}", reply.to_string()).is_err() || out.flush().is_err() {
                break;
            }
        }
    }
    0
}

/// One message: a line of JSON, or a `Content-Length:` framed body.
fn read_message(r: &mut impl BufRead) -> Option<String> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        let t = line.trim_end_matches(['\r', '\n']);
        if t.trim().is_empty() {
            continue;
        }
        if let Some(len) = t.strip_prefix("Content-Length:") {
            let len: usize = len.trim().parse().ok()?;
            // Remaining headers, up to the blank line.
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).ok()? == 0 {
                    return None;
                }
                if h.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).ok()?;
            return Some(String::from_utf8_lossy(&body).into_owned());
        }
        return Some(t.to_string());
    }
}

/// Handle one raw message. `None` means nothing is sent back.
pub fn handle_text(text: &str, version: &str) -> Option<Json> {
    match json::parse(text) {
        Ok(req) => handle(&req, version),
        Err(e) => Some(error_reply(Json::Null, -32700, &format!("Parse error: {e}"))),
    }
}

/// Handle one parsed request.
pub fn handle(req: &Json, version: &str) -> Option<Json> {
    let id = req.get("id").cloned();
    let method = req.str_of("method");
    let params = req.get("params").cloned().unwrap_or_else(|| Json::Obj(Vec::new()));
    let notification = id.is_none();
    if method.starts_with("notifications/") {
        return None;
    }
    let result: Result<Json, (i64, String)> = match method.as_str() {
        "initialize" => Ok(initialize(&params, version)),
        "ping" => Ok(Json::Obj(Vec::new())),
        "tools/list" => Ok(Json::obj(vec![("tools", Json::arr(tool_specs()))])),
        "tools/call" => Ok(call_tool(&params)),
        "" => Err((-32600, "Invalid Request: no method".to_string())),
        other => Err((-32601, format!("Method not found: {other}"))),
    };
    if notification {
        return None;
    }
    let id = id.unwrap_or(Json::Null);
    Some(match result {
        Ok(r) => Json::obj(vec![("jsonrpc", Json::str("2.0")), ("id", id), ("result", r)]),
        Err((code, msg)) => error_reply(id, code, &msg),
    })
}

fn error_reply(id: Json, code: i64, message: &str) -> Json {
    Json::obj(vec![
        ("jsonrpc", Json::str("2.0")),
        ("id", id),
        ("error", Json::obj(vec![("code", Json::Num(code as f64)), ("message", Json::str(message))])),
    ])
}

fn initialize(params: &Json, version: &str) -> Json {
    let asked = params.str_of("protocolVersion");
    let proto = if PROTOCOL_VERSIONS.contains(&asked.as_str()) { asked.as_str() } else { DEFAULT_PROTOCOL };
    Json::obj(vec![
        ("protocolVersion", Json::str(proto)),
        ("capabilities", Json::obj(vec![("tools", Json::obj(vec![("listChanged", Json::Bool(false))]))])),
        ("serverInfo", Json::obj(vec![("name", Json::str("polinrider-hunter")), ("version", Json::str(version))])),
        ("instructions", Json::str(INSTRUCTIONS)),
    ])
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

fn prop(ty: &str, desc: &str) -> Json {
    Json::obj(vec![("type", Json::str(ty)), ("description", Json::str(desc))])
}

fn prop_default(ty: &str, desc: &str, default: Json) -> Json {
    Json::obj(vec![("type", Json::str(ty)), ("description", Json::str(desc)), ("default", default)])
}

fn strings(desc: &str) -> Json {
    Json::obj(vec![
        ("type", Json::str("array")),
        ("items", Json::obj(vec![("type", Json::str("string"))])),
        ("description", Json::str(desc)),
    ])
}

fn schema(props: Vec<(&str, Json)>, required: &[&str]) -> Json {
    Json::obj(vec![
        ("type", Json::str("object")),
        ("properties", Json::obj(props)),
        ("required", Json::arr(required.iter().map(|r| Json::str(*r)).collect())),
        ("additionalProperties", Json::Bool(false)),
    ])
}

fn tool(name: &str, desc: &str, input: Json) -> Json {
    Json::obj(vec![("name", Json::str(name)), ("description", Json::str(desc)), ("inputSchema", input)])
}

const CONFIRM: &str = "Set true to really apply the change. Without it the call is a dry run that reports what would happen.";
const DRY: &str = "Report only, change nothing (default true). confirm:true with dry_run absent or false applies the change.";

/// The tool catalogue, as `tools/list` returns it.
pub fn tool_specs() -> Vec<Json> {
    vec![
        tool(
            "scan",
            "Scan directories for PolinRider and related indicators. Report only; nothing is changed. Exit code 1 in the result means something critical was found.",
            schema(
                vec![
                    ("paths", strings("Directories or files to scan.")),
                    ("quick", prop_default("boolean", "Only read the ~30 filenames the campaign targets (fast).", Json::Bool(false))),
                ],
                &["paths"],
            ),
        ),
        tool(
            "clean",
            "Scan directories and remove payloads: strip appended payloads from config files, delete droppers, quarantine originals. Dry run unless confirm:true.",
            schema(
                vec![
                    ("paths", strings("Directories or files to clean.")),
                    ("dry_run", prop_default("boolean", DRY, Json::Bool(true))),
                    ("confirm", prop_default("boolean", CONFIRM, Json::Bool(false))),
                ],
                &["paths"],
            ),
        ),
        tool(
            "hunt",
            "Sweep the whole machine: stop running loaders, remove persistence, clean every project under the home directory (every drive with drives:true). Slow (minutes). Dry run unless confirm:true.",
            schema(
                vec![
                    ("dry_run", prop_default("boolean", DRY, Json::Bool(true))),
                    ("drives", prop_default("boolean", "Search every drive, not just the home directory.", Json::Bool(false))),
                    ("confirm", prop_default("boolean", CONFIRM, Json::Bool(false))),
                ],
                &[],
            ),
        ),
        tool(
            "repos_audit",
            "Audit every branch (local and remote-tracking) of each repository without checking anything out, plus its git config and hooks. URLs are fetched into a temporary bare mirror and deleted afterwards. Per infected branch: repo, remote, branch, files, indicators, can_write (whether you can push), owner, and who_pushed the infection.",
            schema(
                vec![
                    ("paths", strings("Local repository paths (or directories containing them).")),
                    ("urls", strings("Repository URLs (https://, git@, ssh://) to audit from their remote alone.")),
                    ("history", prop_default("boolean", "Also walk every old commit for payload blobs, not just branch tips.", Json::Bool(false))),
                    ("fetch", prop_default("boolean", "Fetch remotes first (default true). false audits the refs as they are and skips the write-access probe.", Json::Bool(true))),
                ],
                &[],
            ),
        ),
        tool(
            "repos_repair",
            "Clean each infected remote branch with one forward commit built in the object database (nothing checked out, no force push), then push it. Branches you cannot push to are reported BLOCKED with who can fix them. Dry run unless confirm:true.",
            schema(
                vec![
                    ("paths", strings("Local repository paths.")),
                    ("urls", strings("Repository URLs; the repair is built in a temporary bare mirror and pushed from there.")),
                    ("dry_run", prop_default("boolean", DRY, Json::Bool(true))),
                    ("confirm", prop_default("boolean", CONFIRM, Json::Bool(false))),
                    ("skip_remotes", strings("Remote names never to push to (for example a fork's upstream).")),
                ],
                &[],
            ),
        ),
        tool(
            "repos_history",
            "Walk every blob reachable from any ref of each repository and report payloads left in old commits, with the git filter-repo command that purges them. Report only.",
            schema(vec![("paths", strings("Local repository paths."))], &["paths"]),
        ),
        tool(
            "processes",
            "List hidden stage-2 loader processes. kill:true with confirm:true stops them.",
            schema(
                vec![
                    ("kill", prop_default("boolean", "Stop the processes found.", Json::Bool(false))),
                    ("confirm", prop_default("boolean", CONFIRM, Json::Bool(false))),
                ],
                &[],
            ),
        ),
        tool(
            "persistence",
            "Check shell profiles, cron, login agents, Run keys, scheduled tasks and Startup folders for a way back in. remove:true with confirm:true removes the entries that provably launch the campaign; hand-maintained files are only ever reported.",
            schema(
                vec![
                    ("remove", prop_default("boolean", "Remove provably malicious autostart entries.", Json::Bool(false))),
                    ("confirm", prop_default("boolean", CONFIRM, Json::Bool(false))),
                ],
                &[],
            ),
        ),
        tool("quarantine_list", "List the original files kept aside by cleaning, with their indicators.", schema(vec![], &[])),
        tool("status", "Where the tool keeps its state, whether the background guard is running, what it watches.", schema(vec![], &[])),
        tool(
            "access_check",
            "Report, for every remote of a repository (or for one URL), whether the current user can push to it, who owns it and how that was determined. Nothing is pushed.",
            schema(
                vec![
                    ("path", prop("string", "A local repository path.")),
                    ("url", prop("string", "A repository URL.")),
                ],
                &[],
            ),
        ),
    ]
}

/// Every tool name, in catalogue order.
pub fn tool_names() -> Vec<String> {
    tool_specs().iter().map(|t| t.str_of("name")).collect()
}

/// How a tool call becomes a run of this binary.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    /// Arguments after the executable (`--json --no-color` are added later).
    pub args: Vec<String>,
    /// Extra environment for the child.
    pub env: Vec<(String, String)>,
    /// A line appended to the result text (the confirm instruction).
    pub note: Option<String>,
}

fn confirmed(a: &Json) -> bool {
    let explicit_dry = a.get("dry_run").and_then(|v| v.as_bool()) == Some(true);
    a.bool_of("confirm", false) && !explicit_dry
}

fn nonempty(v: Vec<String>) -> Vec<String> {
    v.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Translate a tool call into a command line. Pure, so it can be tested.
pub fn plan_call(name: &str, a: &Json) -> Result<Invocation, String> {
    let mut inv = Invocation { args: Vec::new(), env: Vec::new(), note: None };
    let push = |inv: &mut Invocation, s: &str| inv.args.push(s.to_string());
    match name {
        "scan" => {
            let paths = nonempty(a.strings_of("paths"));
            if paths.is_empty() {
                return Err("scan needs at least one path".into());
            }
            push(&mut inv, "scan");
            inv.args.extend(paths);
            if a.bool_of("quick", false) {
                push(&mut inv, "--quick");
            }
        }
        "clean" => {
            let paths = nonempty(a.strings_of("paths"));
            if paths.is_empty() {
                return Err("clean needs at least one path".into());
            }
            push(&mut inv, "clean");
            inv.args.extend(paths);
            if !confirmed(a) {
                push(&mut inv, "--dry-run");
                inv.note = Some(CONFIRM_NOTE.into());
            }
        }
        "hunt" => {
            push(&mut inv, "hunt");
            if a.bool_of("drives", false) {
                push(&mut inv, "--drives");
            }
            if !confirmed(a) {
                push(&mut inv, "--dry-run");
                inv.note = Some(CONFIRM_NOTE.into());
            }
        }
        "repos_audit" | "repos_repair" => {
            push(&mut inv, "repos");
            if name == "repos_repair" {
                push(&mut inv, "--repair");
            }
            let paths = nonempty(a.strings_of("paths"));
            let urls = nonempty(a.strings_of("urls"));
            inv.args.extend(paths);
            for u in urls {
                push(&mut inv, "--url");
                inv.args.push(u);
            }
            if name == "repos_audit" {
                if a.bool_of("history", false) {
                    push(&mut inv, "--history");
                }
                if !a.bool_of("fetch", true) {
                    push(&mut inv, "--no-fetch");
                }
            } else {
                let skip = nonempty(a.strings_of("skip_remotes"));
                if !skip.is_empty() {
                    push(&mut inv, "--skip-remotes");
                    inv.args.push(skip.join(","));
                }
                if !confirmed(a) {
                    push(&mut inv, "--dry-run");
                    inv.note = Some(CONFIRM_NOTE.into());
                }
            }
        }
        "repos_history" => {
            let paths = nonempty(a.strings_of("paths"));
            if paths.is_empty() {
                return Err("repos_history needs at least one path".into());
            }
            push(&mut inv, "repos");
            push(&mut inv, "--history");
            inv.args.extend(paths);
        }
        "processes" => {
            push(&mut inv, "procs");
            if a.bool_of("kill", false) {
                if a.bool_of("confirm", false) {
                    push(&mut inv, "--kill");
                } else {
                    inv.note = Some(CONFIRM_NOTE.into());
                }
            }
        }
        "persistence" => {
            push(&mut inv, "persistence");
            if a.bool_of("remove", false) {
                if a.bool_of("confirm", false) {
                    push(&mut inv, "--remove");
                } else {
                    inv.note = Some(CONFIRM_NOTE.into());
                }
            }
        }
        "quarantine_list" => push(&mut inv, "quarantine"),
        "status" => push(&mut inv, "status"),
        "access_check" => {
            let path = a.str_of("path");
            let url = a.str_of("url");
            if path.trim().is_empty() && url.trim().is_empty() {
                return Err("access_check needs a path or a url".into());
            }
            push(&mut inv, "repos");
            push(&mut inv, "--access");
            if !path.trim().is_empty() {
                inv.args.push(path.trim().to_string());
            }
            if !url.trim().is_empty() {
                push(&mut inv, "--url");
                inv.args.push(url.trim().to_string());
            }
        }
        other => return Err(format!("unknown tool: {other}")),
    }
    push(&mut inv, "--json");
    push(&mut inv, "--no-color");
    Ok(inv)
}

fn text_result(text: String, is_error: bool) -> Json {
    Json::obj(vec![
        ("content", Json::arr(vec![Json::obj(vec![("type", Json::str("text")), ("text", Json::Str(text))])])),
        ("isError", Json::Bool(is_error)),
    ])
}

fn call_tool(params: &Json) -> Json {
    let name = params.str_of("name");
    let args = params.get("arguments").cloned().unwrap_or_else(|| Json::Obj(Vec::new()));
    let inv = match plan_call(&name, &args) {
        Ok(i) => i,
        Err(e) => return text_result(e, true),
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return text_result(format!("cannot locate my own executable: {e}"), true),
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(&inv.args);
    for (k, v) in &inv.env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    eprintln!("mcp: polinrider-hunter {}", inv.args.join(" "));
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => return text_result(format!("could not run polinrider-hunter {}: {e}", inv.args.join(" ")), true),
    };
    let code = out.status.code();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let (mut text, mut is_error) = render_output(&stdout, &stderr, code, &inv.args);
    if let Some(n) = &inv.note {
        text.push('\n');
        text.push_str(n);
    }
    if code == Some(2) || code.is_none() {
        is_error = true;
    }
    text_result(truncate(text), is_error)
}

/// Turn a child's output into the tool text.
///
/// `--json` output is a sequence of JSON documents (one per report section,
/// some pretty-printed). They are re-emitted compact, one per line, so the
/// caller gets well-formed JSON throughout; anything that does not parse is
/// returned raw and flagged, rather than silently passed off as data.
pub fn render_output(stdout: &str, stderr: &str, code: Option<i32>, args: &[String]) -> (String, bool) {
    let mut lines: Vec<String> = Vec::new();
    let mut bad = false;
    for doc in split_documents(stdout) {
        match json::parse(&doc) {
            Ok(v) => lines.push(v.to_string()),
            Err(_) => {
                bad = true;
                break;
            }
        }
    }
    let mut text = if bad { stdout.trim_end().to_string() } else { lines.join("\n") };
    let err = stderr.trim();
    if text.is_empty() && code.unwrap_or(0) != 0 {
        text = format!("polinrider-hunter {} exited with code {}", args.join(" "), code.map(|c| c.to_string()).unwrap_or_else(|| "none (killed)".into()));
        if !err.is_empty() {
            text.push('\n');
            text.push_str(err);
        }
        return (text, true);
    }
    if !err.is_empty() {
        text.push_str("\n[stderr]\n");
        text.push_str(err);
    }
    if bad {
        text = format!("non-JSON output from polinrider-hunter {}:\n{text}", args.join(" "));
    }
    (text, bad)
}

/// Split concatenated JSON documents, aware of strings and nesting.
pub fn split_documents(text: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    let mut start: Option<usize> = None;
    for (i, ch) in text.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => {
                if start.is_none() {
                    start = Some(i);
                }
                in_str = true;
            }
            '{' | '[' => {
                if start.is_none() {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some(s) = start.take() {
                        docs.push(text[s..=i].to_string());
                    }
                }
            }
            c if c.is_whitespace() => {}
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
            }
        }
    }
    if let Some(s) = start {
        let tail = text[s..].trim();
        if !tail.is_empty() {
            docs.push(tail.to_string());
        }
    }
    docs
}

fn truncate(text: String) -> String {
    if text.len() <= MAX_TEXT {
        return text;
    }
    let mut cut = MAX_TEXT;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let dropped = text.len() - cut;
    format!("{}\n... [truncated {dropped} bytes; narrow the paths or run the CLI directly for the full output]", &text[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_echoes_known_versions_and_falls_back_otherwise() {
        let r = handle_text(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#, "9.9.9").unwrap();
        assert_eq!(r.path(&["result", "protocolVersion"]).unwrap().as_str(), Some("2024-11-05"));
        assert_eq!(r.path(&["result", "serverInfo", "version"]).unwrap().as_str(), Some("9.9.9"));
        let r = handle_text(r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#, "x").unwrap();
        assert_eq!(r.path(&["result", "protocolVersion"]).unwrap().as_str(), Some(DEFAULT_PROTOCOL));
    }

    #[test]
    fn notifications_get_no_reply_and_unknown_methods_an_error() {
        assert!(handle_text(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, "x").is_none());
        assert!(handle_text(r#"{"jsonrpc":"2.0","method":"tools/list"}"#, "x").is_none(), "no id: a notification");
        let r = handle_text(r#"{"jsonrpc":"2.0","id":7,"method":"nope"}"#, "x").unwrap();
        assert_eq!(r.path(&["error", "code"]).unwrap().as_f64(), Some(-32601.0));
        let r = handle_text("{not json", "x").unwrap();
        assert_eq!(r.path(&["error", "code"]).unwrap().as_f64(), Some(-32700.0));
    }

    #[test]
    fn every_tool_has_an_object_schema() {
        for t in tool_specs() {
            let s = t.get("inputSchema").unwrap();
            assert_eq!(s.str_of("type"), "object", "{}", t.str_of("name"));
            assert!(s.get("properties").and_then(|p| p.as_obj()).is_some());
            assert!(s.get("required").and_then(|p| p.as_arr()).is_some());
        }
        assert_eq!(
            tool_names(),
            ["scan", "clean", "hunt", "repos_audit", "repos_repair", "repos_history", "processes", "persistence", "quarantine_list", "status", "access_check"]
        );
    }

    #[test]
    fn mutating_tools_are_dry_runs_without_confirm() {
        let a = json::parse(r#"{"paths":["C:\\p"]}"#).unwrap();
        let inv = plan_call("clean", &a).unwrap();
        assert!(inv.args.contains(&"--dry-run".to_string()));
        assert!(inv.note.is_some());
        let a = json::parse(r#"{"paths":["C:\\p"],"confirm":true}"#).unwrap();
        let inv = plan_call("clean", &a).unwrap();
        assert!(!inv.args.contains(&"--dry-run".to_string()));
        assert!(inv.note.is_none());
        // confirm with an explicit dry_run:true stays a dry run.
        let a = json::parse(r#"{"paths":["C:\\p"],"confirm":true,"dry_run":true}"#).unwrap();
        assert!(plan_call("clean", &a).unwrap().args.contains(&"--dry-run".to_string()));
        let a = json::parse(r#"{"urls":["https://github.com/o/r"],"skip_remotes":["upstream"]}"#).unwrap();
        let inv = plan_call("repos_repair", &a).unwrap();
        assert_eq!(inv.args, ["repos", "--repair", "--url", "https://github.com/o/r", "--skip-remotes", "upstream", "--dry-run", "--json", "--no-color"]);
        let a = json::parse(r#"{"kill":true}"#).unwrap();
        let inv = plan_call("processes", &a).unwrap();
        assert!(!inv.args.contains(&"--kill".to_string()));
        assert!(inv.note.is_some());
    }

    #[test]
    fn documents_are_split_and_rendered_one_per_line() {
        let out = "{\"findings\":[\n  {\"path\":\"a}b\",\"x\":\"q\\\"]\"}\n]}\n{\"type\":\"heal\",\"ok\":true}\n";
        let docs = split_documents(out);
        assert_eq!(docs.len(), 2, "{docs:?}");
        let (text, bad) = render_output(out, "", Some(1), &["scan".into()]);
        assert!(!bad);
        assert_eq!(text, "{\"findings\":[{\"path\":\"a}b\",\"x\":\"q\\\"]\"}]}\n{\"type\":\"heal\",\"ok\":true}");
        let (text, bad) = render_output("Nothing to clean.\n", "", Some(0), &["clean".into()]);
        assert!(bad, "{text}");
        let (text, bad) = render_output("", "No paths given", Some(2), &["scan".into()]);
        assert!(bad);
        assert!(text.contains("No paths given"));
    }

    #[test]
    fn long_text_is_cut_with_a_note() {
        let t = truncate("x".repeat(MAX_TEXT + 100));
        assert!(t.len() < MAX_TEXT + 200);
        assert!(t.contains("truncated 100 bytes"));
    }
}
