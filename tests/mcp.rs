//! Driving the binary through the Model Context Protocol.
//!
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! Spawns the built `polinrider-hunter mcp`, speaks JSON-RPC to it over stdin
//! and stdout the way an MCP client (Claude Code, Cursor, Codex) would, and
//! checks that the tools do what their descriptions promise: scans report,
//! mutating calls are dry runs without `confirm`, and a confirmed repair
//! really cleans a poisoned remote branch. Every fixture is inert and lives in
//! a temp directory; the only "remote" is a local bare repository.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use polinrider_hunter::json::{self, Json};

fn hunter_bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(format!("polinrider-hunter{}", std::env::consts::EXE_SUFFIX))
}

/// A scratch directory unique to this test, removed on drop.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Sandbox {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("prh-mcp-{tag}-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Sandbox { root }
    }
    fn home(&self) -> PathBuf {
        let h = self.root.join("home");
        std::fs::create_dir_all(&h).unwrap();
        h
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        polinrider_hunter::remote::remove_tree(&self.root);
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=Mallory", "-c", "user.email=mallory@example.com", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git");
    assert!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A config file with the campaign's appended payload: real content, 300 tabs
/// to push it off screen, then the obfuscated-variant marker.
fn poisoned_config() -> String {
    let pad: String = std::iter::repeat('\t').take(300).collect();
    format!("export default {{ plugins: {{}} }};{pad}global['!']='x';\n")
}

/// A bare "origin" whose `main` carries the poisoned config, and a working
/// clone `a` that tracks it. Returns (bare, clone).
fn poisoned_origin(sb: &Sandbox) -> (PathBuf, PathBuf) {
    let bare = sb.root.join("origin.git");
    let a = sb.root.join("a");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::create_dir_all(&a).unwrap();
    git(&bare, &["init", "-q", "--bare", "-b", "main"]);
    git(&a, &["init", "-q", "-b", "main"]);
    std::fs::write(a.join("postcss.config.mjs"), poisoned_config()).unwrap();
    std::fs::write(a.join("README.md"), "# fixture\n").unwrap();
    git(&a, &["add", "."]);
    git(&a, &["commit", "-q", "-m", "feat: x"]);
    git(&a, &["remote", "add", "origin", bare.to_str().unwrap()]);
    git(&a, &["push", "-q", "-u", "origin", "main"]);
    (bare, a)
}

/// The MCP server, with a line-oriented JSON-RPC client around it.
struct Server {
    child: Child,
    out: BufReader<ChildStdout>,
    next_id: u64,
}

impl Server {
    fn start(home: &Path) -> Server {
        let mut child = Command::new(hunter_bin())
            .arg("mcp")
            .env("POLINRIDER_HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn polinrider-hunter mcp");
        let out = BufReader::new(child.stdout.take().unwrap());
        Server { child, out, next_id: 1 }
    }

    fn send(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn read(&mut self) -> Json {
        let mut line = String::new();
        let n = self.out.read_line(&mut line).expect("read reply");
        assert!(n > 0, "server closed stdout");
        json::parse(line.trim()).unwrap_or_else(|e| panic!("reply is not JSON ({e}): {line}"))
    }

    fn request(&mut self, method: &str, params: &str) -> Json {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}"));
        let reply = self.read();
        assert_eq!(reply.get("id").and_then(|v| v.as_f64()), Some(id as f64), "reply id matches: {}", reply.to_string());
        reply
    }

    fn notify(&mut self, method: &str) {
        self.send(&format!("{{\"jsonrpc\":\"2.0\",\"method\":\"{method}\"}}"));
    }

    /// Call a tool; returns (text, isError).
    fn call(&mut self, tool: &str, arguments: &str) -> (String, bool) {
        let reply = self.request("tools/call", &format!("{{\"name\":\"{tool}\",\"arguments\":{arguments}}}"));
        let result = reply.get("result").unwrap_or_else(|| panic!("no result: {}", reply.to_string()));
        let text = result.path(&["content", "0", "text"]).and_then(|t| t.as_str()).unwrap_or("").to_string();
        (text, result.bool_of("isError", false))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn json_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "\\\\")
}

const CONFIRM_LINE: &str = "Dry run. Show this to the user and call again with confirm:true to apply.";

#[test]
fn a_client_can_initialise_list_tools_scan_and_clean_with_dry_runs() {
    let sb = Sandbox::new("session");
    let home = sb.home();
    let project = sb.root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let poisoned = project.join("postcss.config.mjs");
    std::fs::write(&poisoned, poisoned_config()).unwrap();
    std::fs::write(project.join("index.js"), "console.log('hi');\n").unwrap();

    let mut s = Server::start(&home);

    // initialize: a known version is echoed, an unknown one is not.
    let init = s.request("initialize", r#"{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}"#);
    assert_eq!(init.path(&["result", "protocolVersion"]).and_then(|v| v.as_str()), Some("2025-03-26"));
    assert_eq!(init.path(&["result", "serverInfo", "name"]).and_then(|v| v.as_str()), Some("polinrider-hunter"));
    assert_eq!(init.path(&["result", "serverInfo", "version"]).and_then(|v| v.as_str()), Some(env!("CARGO_PKG_VERSION")));
    assert!(init.path(&["result", "capabilities", "tools"]).is_some());
    let instructions = init.path(&["result", "instructions"]).and_then(|v| v.as_str()).unwrap_or("");
    assert!(instructions.contains("repos_repair") && instructions.contains("confirm:true"), "{instructions}");
    s.notify("notifications/initialized");

    // ping still answers after the notification: it got no reply of its own.
    let pong = s.request("ping", "{}");
    assert!(pong.get("result").is_some(), "{}", pong.to_string());

    let list = s.request("tools/list", "{}");
    let tools = list.path(&["result", "tools"]).and_then(|t| t.as_arr()).expect("tools array");
    let names: Vec<String> = tools.iter().map(|t| t.str_of("name")).collect();
    for want in ["scan", "clean", "hunt", "repos_audit", "repos_repair", "repos_history", "processes", "persistence", "quarantine_list", "status", "access_check"] {
        assert!(names.iter().any(|n| n == want), "tool {want} is listed: {names:?}");
    }
    for t in tools {
        let schema = t.get("inputSchema").expect("inputSchema");
        assert_eq!(schema.str_of("type"), "object", "{}", t.str_of("name"));
        assert!(schema.get("properties").is_some() && schema.get("required").is_some(), "{}", t.str_of("name"));
    }

    // scan: reports the poisoned file, changes nothing, is not an error even
    // though the CLI exits 1 for "found something".
    let (text, err) = s.call("scan", &format!(r#"{{"paths":["{}"]}}"#, json_path(&project)));
    assert!(!err, "{text}");
    assert!(text.contains("postcss.config.mjs"), "scan names the file: {text}");
    assert!(text.contains("\"critical\":true"), "{text}");
    assert!(!text.contains(CONFIRM_LINE), "a scan has nothing to confirm");
    let before = std::fs::read(&poisoned).unwrap();
    assert_eq!(before, poisoned_config().as_bytes());

    // clean without confirm: a dry run, the instruction, the file untouched.
    let (text, err) = s.call("clean", &format!(r#"{{"paths":["{}"]}}"#, json_path(&project)));
    assert!(!err, "{text}");
    assert!(text.contains("postcss.config.mjs"), "{text}");
    assert!(text.contains("\"dry\":true"), "{text}");
    assert!(text.ends_with(CONFIRM_LINE), "{text}");
    assert_eq!(std::fs::read(&poisoned).unwrap(), before, "a dry run leaves the file alone");

    // Every line before the instruction is a JSON document of its own.
    for line in text.lines().filter(|l| *l != CONFIRM_LINE) {
        json::parse(line).unwrap_or_else(|e| panic!("line is not JSON ({e}): {line}"));
    }

    // clean with confirm: the payload is gone, the code stays.
    let (text, err) = s.call("clean", &format!(r#"{{"paths":["{}"],"confirm":true}}"#, json_path(&project)));
    assert!(!err, "{text}");
    assert!(!text.contains(CONFIRM_LINE), "{text}");
    assert!(text.contains("\"type\":\"heal\"") && text.contains("\"ok\":true"), "{text}");
    let after = std::fs::read_to_string(&poisoned).unwrap();
    assert!(!after.contains("global['!']"), "payload removed: {after:?}");
    assert!(after.starts_with("export default { plugins: {} };"), "code kept: {after:?}");

    // status and quarantine_list are plain JSON too.
    let (text, err) = s.call("status", "{}");
    assert!(!err, "{text}");
    let st = json::parse(text.lines().next().unwrap()).unwrap();
    assert_eq!(st.str_of("version"), env!("CARGO_PKG_VERSION"));
    let (text, err) = s.call("quarantine_list", "{}");
    assert!(!err, "{text}");
    let q = json::parse(text.lines().next().unwrap()).unwrap();
    assert!(q.get("quarantine").and_then(|v| v.as_arr()).map(|a| !a.is_empty()).unwrap_or(false), "the cleaned original is in quarantine: {text}");

    // Unknown tool: an error result, not a protocol error.
    let (text, err) = s.call("nope", "{}");
    assert!(err && text.contains("unknown tool"), "{text}");

    // Unknown method: a JSON-RPC error.
    let reply = s.request("resources/list", "{}");
    assert_eq!(reply.path(&["error", "code"]).and_then(|v| v.as_f64()), Some(-32601.0), "{}", reply.to_string());

    // Garbage: a parse error, and the server is still alive afterwards.
    s.send("{this is not json");
    let reply = s.read();
    assert_eq!(reply.path(&["error", "code"]).and_then(|v| v.as_f64()), Some(-32700.0), "{}", reply.to_string());
    let pong = s.request("ping", "{}");
    assert!(pong.get("result").is_some());

    // A client that frames with Content-Length headers is understood too.
    let body = r#"{"jsonrpc":"2.0","id":900,"method":"ping","params":{}}"#;
    s.send(&format!("Content-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}", body.len()));
    let reply = s.read();
    assert_eq!(reply.get("id").and_then(|v| v.as_f64()), Some(900.0), "{}", reply.to_string());
    assert!(reply.get("result").is_some());
}

#[test]
fn repos_repair_is_a_dry_run_until_confirmed_and_then_cleans_the_remote() {
    let sb = Sandbox::new("repair");
    let home = sb.home();
    let (bare, a) = poisoned_origin(&sb);
    let poisoned_tip = git(&bare, &["rev-parse", "main"]);

    let mut s = Server::start(&home);
    s.request("initialize", r#"{"protocolVersion":"2025-06-18"}"#);
    s.notify("notifications/initialized");

    // The audit names the branch, the file, and who can fix it.
    let (text, err) = s.call("repos_audit", &format!(r#"{{"paths":["{}"]}}"#, json_path(&a)));
    assert!(!err, "{text}");
    assert!(text.contains("refs/remotes/origin/main"), "{text}");
    assert!(text.contains("\"type\":\"access\""), "{text}");
    assert!(text.contains("\"can_write\":true"), "a local bare origin accepts pushes: {text}");
    assert!(text.contains("mallory@example.com"), "who pushed the infection: {text}");
    assert!(text.contains("\"files\":[\"postcss.config.mjs\"]"), "{text}");

    // Dry run: says what it would push, pushes nothing.
    let (text, err) = s.call("repos_repair", &format!(r#"{{"paths":["{}"]}}"#, json_path(&a)));
    assert!(!err, "{text}");
    assert!(text.contains("\"type\":\"repair\"") && text.contains("\"dry\":true") && text.contains("would add"), "{text}");
    assert!(text.ends_with(CONFIRM_LINE), "{text}");
    assert_eq!(git(&bare, &["rev-parse", "main"]), poisoned_tip, "nothing was pushed");

    // Confirmed: one forward commit on top, the remote tip is clean.
    let (text, err) = s.call("repos_repair", &format!(r#"{{"paths":["{}"],"confirm":true}}"#, json_path(&a)));
    assert!(!err, "{text}");
    assert!(text.contains("\"ok\":true") && text.contains("\"dry\":false"), "{text}");
    assert!(!text.contains(CONFIRM_LINE), "{text}");
    let new_tip = git(&bare, &["rev-parse", "main"]);
    assert_ne!(new_tip, poisoned_tip);
    assert_eq!(git(&bare, &["rev-parse", "main^"]), poisoned_tip, "a forward commit, not a rewrite");
    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(files.contains("postcss.config.mjs") && files.contains("README.md"), "{files}");
    let cleaned = git(&bare, &["show", "main:postcss.config.mjs"]);
    assert!(!cleaned.contains("global['!']"), "remote tip is clean: {cleaned:?}");
    assert!(cleaned.contains("export default { plugins: {} };"), "{cleaned:?}");

    // The remote branch audits clean now. The clone's own local `main` still
    // carries the payload - a remote repair never rewrites anyone's local
    // branch; `clean` on the work tree is the fix for that - so only
    // remote-tracking refs are judged here.
    let (text, err) = s.call("repos_audit", &format!(r#"{{"paths":["{}"]}}"#, json_path(&a)));
    assert!(!err, "{text}");
    assert!(!text.contains("refs/remotes/"), "no remote branch is infected any more: {text}");
    assert!(text.contains("refs/heads/main"), "the local branch is still reported: {text}");
}

#[test]
fn a_repository_can_be_audited_and_repaired_from_its_url_alone() {
    let sb = Sandbox::new("url");
    let home = sb.home();
    let (bare, _a) = poisoned_origin(&sb);
    let poisoned_tip = git(&bare, &["rev-parse", "main"]);
    // A file:// URL to the bare origin: no clone of it exists anywhere else.
    let url = format!("file:///{}", bare.to_string_lossy().replace('\\', "/").trim_start_matches('/'));

    let mut s = Server::start(&home);
    s.request("initialize", r#"{"protocolVersion":"2025-06-18"}"#);
    s.notify("notifications/initialized");

    let (text, err) = s.call("repos_audit", &format!(r#"{{"urls":["{url}"]}}"#));
    assert!(!err, "{text}");
    assert!(text.contains(&format!("\"repo\":\"{url}\"")), "the URL stands in for the temp path: {text}");
    assert!(text.contains("refs/remotes/origin/main") && text.contains("postcss.config.mjs"), "{text}");
    assert!(text.contains("\"can_write\":true"), "{text}");

    let (text, err) = s.call("access_check", &format!(r#"{{"url":"{url}"}}"#));
    assert!(!err, "{text}");
    assert!(text.contains("\"type\":\"access\"") && text.contains("\"can_write\":true"), "{text}");

    let (text, err) = s.call("repos_repair", &format!(r#"{{"urls":["{url}"],"confirm":true}}"#));
    assert!(!err, "{text}");
    assert!(text.contains("\"ok\":true"), "{text}");
    assert_eq!(git(&bare, &["rev-parse", "main^"]), poisoned_tip);
    let cleaned = git(&bare, &["show", "main:postcss.config.mjs"]);
    assert!(!cleaned.contains("global['!']"), "{cleaned:?}");

    // No mirror is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&format!("prh-remote-{}-", std::process::id())))
        .collect();
    assert!(leftovers.is_empty(), "mirrors are deleted: {leftovers:?}");
}

#[test]
fn the_cli_accepts_a_url_positionally_and_reports_it_in_place_of_the_path() {
    let sb = Sandbox::new("cli-url");
    let home = sb.home();
    let (bare, _a) = poisoned_origin(&sb);
    let url = format!("file:///{}", bare.to_string_lossy().replace('\\', "/").trim_start_matches('/'));
    let out = Command::new(hunter_bin())
        .args(["repos", &url, "--no-color"])
        .env("POLINRIDER_HOME", &home)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains(&format!("INFECTED {url}")), "{text}");
    assert!(text.contains("remotes/origin/main :: postcss.config.mjs"), "{text}");
    assert!(!text.contains("you cannot push to"), "we can push to our own bare origin: {text}");
}
