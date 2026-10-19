//! polinrider-hunter - detect and remove the PolinRider supply-chain malware.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR (the help text names the
//! campaigns this tool hunts, which would otherwise trip its own branch audit).
//!
//! One binary, no runtime, no dependencies. `install` is the only command most
//! people need; everything else exists so you can see what it is doing and
//! check its work by hand.

use std::path::PathBuf;

use polinrider_hunter::{
    agent, config, daemon, gemini, gitconfig, gitscan, healer, mcp, monitor, notify, persist, procscan,
    llm, remote, report, scanner, service, util, winpersist,
};

use config::Config;
use util::{BOLD, DIM, GREEN, RED, RESET, YELLOW};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `println!` that first wipes the live status line (see `util::status`), so a
/// finding printed mid-sweep does not land on top of "still scanning ...".
macro_rules! sayln {
    ($($t:tt)*) => {{
        let _g = util::status::clear();
        println!($($t)*);
    }};
}

struct Args {
    cmd: String,
    positional: Vec<String>,
    flags: Vec<String>,
    interval: Option<u64>,
    port: Option<u16>,
    /// `--key`, `--model`, `--task`, `--max-steps`, `--vt-key` values.
    key: Option<String>,
    model: Option<String>,
    task: Option<String>,
    max_steps: Option<usize>,
    vt_key: Option<String>,
    /// `--provider`, `--mode`, `--base-url` for the agent.
    provider: Option<String>,
    mode: Option<String>,
    base_url: Option<String>,
    /// Repository URLs for `repos`: positional arguments that look like one
    /// (https://, git@, ssh://), or `--url <u>`.
    urls: Vec<String>,
    /// `--skip-remotes a,b` for `repos --repair`.
    skip_remotes: Option<String>,
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| "help".into());
    let mut positional = Vec::new();
    let mut flags = Vec::new();
    let mut interval = None;
    let mut port = None;
    let mut key = None;
    let mut model = None;
    let mut task = None;
    let mut max_steps = None;
    let mut vt_key = None;
    let mut provider = None;
    let mut mode = None;
    let mut base_url = None;
    let mut urls = Vec::new();
    let mut skip_remotes = None;
    while let Some(a) = it.next() {
        if a == "--url" { if let Some(u) = it.next() { urls.push(u); } continue; }
        if let Some(v) = a.strip_prefix("--url=") { urls.push(v.to_string()); continue; }
        if a == "--skip-remotes" { skip_remotes = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--skip-remotes=") { skip_remotes = Some(v.to_string()); continue; }
        if a == "--provider" { provider = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--provider=") { provider = Some(v.to_string()); continue; }
        if a == "--mode" { mode = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--mode=") { mode = Some(v.to_string()); continue; }
        if a == "--base-url" { base_url = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--base-url=") { base_url = Some(v.to_string()); continue; }
        if a == "--key" { key = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--key=") { key = Some(v.to_string()); continue; }
        if a == "--model" { model = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--model=") { model = Some(v.to_string()); continue; }
        if a == "--task" { task = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--task=") { task = Some(v.to_string()); continue; }
        if a == "--vt-key" { vt_key = it.next(); continue; }
        if let Some(v) = a.strip_prefix("--vt-key=") { vt_key = Some(v.to_string()); continue; }
        if a == "--max-steps" { max_steps = it.next().and_then(|v| v.parse().ok()); continue; }
        if let Some(v) = a.strip_prefix("--max-steps=") { max_steps = v.parse().ok(); continue; }
        if a == "--interval" {
            interval = it.next().and_then(|v| v.parse().ok());
        } else if let Some(v) = a.strip_prefix("--interval=") {
            interval = v.parse().ok();
        } else if a == "--port" {
            port = it.next().and_then(|v| v.parse().ok());
        } else if let Some(v) = a.strip_prefix("--port=") {
            port = v.parse().ok();
        } else if a.starts_with("--") {
            flags.push(a);
        } else if remote::is_url(&a) {
            urls.push(a);
        } else {
            positional.push(a);
        }
    }
    Args {
        cmd,
        positional,
        flags,
        interval,
        port,
        key,
        model,
        task,
        max_steps,
        vt_key,
        provider,
        mode,
        base_url,
        urls,
        skip_remotes,
    }
}

impl Args {
    fn has(&self, f: &str) -> bool {
        self.flags.iter().any(|x| x == f)
    }
}

/// Paths to act on: whatever was given, else whatever is configured.
fn target_paths(args: &Args, cfg: &Config) -> Vec<PathBuf> {
    if args.positional.is_empty() {
        cfg.paths.clone()
    } else {
        args.positional.iter().map(PathBuf::from).collect()
    }
}

fn main() {
    let args = parse_args();
    if args.has("--no-color") {
        util::set_colour(false);
    } else {
        util::enable_ansi();
    }
    let json = args.has("--json");
    let cfg = Config::load();

    let code = match args.cmd.as_str() {
        "hunt" => cmd_hunt(&args, json),
        "scan" => cmd_scan(&args, &cfg, json),
        "clean" => cmd_clean(&args, &cfg, json),
        "repos" => cmd_repos(&args, &cfg, json),
        "agent" | "investigate" | "chat" => cmd_agent(&args, cfg),
        "ai" => cmd_ai(&args, cfg),
        "report" => cmd_report(&args, cfg),
        "set-key" => cmd_set_key(&args, cfg),
        "protect" => cmd_protect(&args, &cfg),
        "unprotect" => cmd_unprotect(&args, &cfg),
        "procs" => cmd_procs(&args, json),
        "persistence" => cmd_persistence(&args, json),
        "mcp" => mcp::run(VERSION),
        "log" | "logs" => cmd_log(&args),
        "monitor" | "dashboard" => cmd_monitor(&args, &cfg),
        "daemon" => daemon::run(&cfg, args.has("--once")),
        "install" => cmd_install(&args, cfg),
        "stop" => cmd_stop(),
        "uninstall" => cmd_uninstall(&args),
        "test-notify" => cmd_test_notify(),
        "status" => cmd_status(&cfg, json),
        "quarantine" => cmd_quarantine(json),
        "hook" => cmd_hook(),
        "version" | "--version" | "-V" => {
            println!("polinrider-hunter {VERSION}");
            0
        }
        "help" | "--help" | "-h" => {
            usage();
            0
        }
        other => {
            eprintln!("unknown command: {other}\n");
            usage();
            2
        }
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------

fn require_paths(paths: &[PathBuf]) -> bool {
    if paths.is_empty() {
        eprintln!(
            "No paths given and none configured.\n\
             Pass directories, or run: polinrider-hunter install <dir>..."
        );
        false
    } else {
        true
    }
}

/// Sweep the whole machine, not just the configured repos.
///
/// This is the "get it off my computer" command: find every project on the
/// machine, clean each one, and stop any loader that is already running. It
/// needs no configuration and no prior install.
fn cmd_hunt(args: &Args, json: bool) -> i32 {
    let all_drives = args.has("--drives");
    let dry = args.has("--dry-run");
    let roots = config::machine_roots(all_drives);

    // A hunt reads every candidate file on the machine, so it is the heaviest
    // thing this tool does. Drop to background priority first: on a machine
    // that is already short of memory, staying responsive while the sweep runs
    // matters more than finishing it a little sooner.
    service::lower_priority();

    if !json {
        sayln!("{}", util::c(BOLD, "PolinRider hunt"));
        for r in &roots {
            sayln!("  searching {}", r.display());
        }
        if !all_drives {
            sayln!(
                "{}",
                util::c(DIM, "  (add --drives to include every drive on the machine)")
            );
        }
        sayln!(
            "{}",
            util::c(DIM, "  This takes several minutes and needs no input - the line at the bottom shows where it is. Ctrl+C stops it.")
        );
        sayln!();
        // Silence for minutes reads as "it wants me to type something" - it was
        // reported exactly like that. Keep a live line showing where the walk is.
        util::status::start(|elapsed| {
            let (files, _dirs, cur) = scanner::progress::snapshot();
            let secs = elapsed.as_secs();
            format!(
                "  working {}m{:02}s  ·  {} files read  ·  {}",
                secs / 60,
                secs % 60,
                files,
                if cur.is_empty() { "starting".to_string() } else { cur }
            )
        });
    }

    // 1. Anything running right now. Do this first: a live loader can re-drop a
    //    payload into a directory we have already passed.
    let mut killed = 0usize;
    // Everything the sweep touches, for --json: an agent driving this tool
    // needs the list, not just the counts.
    let mut j_procs: Vec<String> = Vec::new();
    let mut j_persist: Vec<String> = Vec::new();
    let mut j_cleaned: Vec<String> = Vec::new();
    let mut j_review: Vec<String> = Vec::new();
    for s in procscan::find() {
        let action = if dry {
            "would stop"
        } else if procscan::kill(s.pid) {
            killed += 1;
            "stopped"
        } else {
            "could not stop"
        };
        if json {
            j_procs.push(format!(
                "{{\"pid\":{},\"marker\":\"{}\",\"action\":\"{action}\"}}",
                s.pid,
                util::json_escape(&s.marker)
            ));
            continue;
        }
        match action {
            "would stop" => sayln!("  {} pid {} ({})", util::c(YELLOW, "would stop"), s.pid, s.marker),
            "stopped" => sayln!("  {} pid {} ({})", util::c(GREEN, "stopped loader"), s.pid, s.marker),
            _ => sayln!("  {} pid {}", util::c(RED, "could not stop"), s.pid),
        }
    }

    // 2. Persistence: a loader that arranged to come back matters as much as
    //    the files it left behind, and the check is nearly free.
    let persist_hits = persist::check();
    if !json {
        for h in &persist_hits {
            sayln!(
                "  {} {}:{}",
                util::c(YELLOW, "startup "),
                h.location,
                h.line_no
            );
            sayln!("      {}", util::c(DIM, h.why));
        }
    }

    // 2b. Windows persistence we can act on: a Run value or Scheduled Task whose
    //     launcher is provably one of the loader campaign's shims. Removed here
    //     so the machine does not simply re-drop the payload at the next login.
    let mut persist_removed = 0usize;
    for a in winpersist::sweep(dry) {
        if a.removed {
            persist_removed += 1;
        }
        if json {
            j_persist.push(format!(
                "{{\"kind\":\"{}\",\"name\":\"{}\",\"target\":\"{}\",\"removed\":{},\"dry\":{dry}}}",
                util::json_escape(&a.kind),
                util::json_escape(&a.name),
                util::json_escape(&a.target),
                a.removed
            ));
        }
        if !json {
            let verb = if dry { "would remove" } else if a.removed { "removed  " } else { "FAILED   " };
            sayln!("  {} {} {}", util::c(GREEN, verb), a.kind, a.name);
            sayln!("      {}", util::c(DIM, &a.target));
        }
    }

    // 3. Every file under every root, healing each hit as it turns up rather
    //    than at the end: a machine-wide walk takes minutes, and an interrupted
    //    run should still have cleaned whatever it already reached.
    let mut healed = 0usize;
    let mut found = 0usize;
    let mut noted = 0usize;
    let mut manual: Vec<String> = Vec::new();

    let mut handle = |f: scanner::Finding| {
        found += 1;
        if !f.is_critical() {
            noted += 1;
            if json {
                let iocs: Vec<String> = f.hits.iter().map(|h| format!("\"{}\"", util::json_escape(h.ioc))).collect();
                j_review.push(format!(
                    "{{\"path\":\"{}\",\"indicators\":[{}]}}",
                    util::json_escape(&f.path.to_string_lossy()),
                    iocs.join(",")
                ));
            }
            if !json {
                // Say what fired. A bare path under a word like "review" is a
                // demand with no information in it: the first question anybody
                // asks is what was seen, and the answer is right here.
                let iocs: Vec<&str> = f.hits.iter().map(|h| h.ioc).collect();
                sayln!(
                    "  {} {}",
                    util::c(YELLOW, "review  "),
                    f.path.display()
                );
                sayln!("      {}", util::c(DIM, &iocs.join(", ")));
            }
            return;
        }
        let outcome = healer::heal(&f, dry);
        match &outcome {
            healer::Outcome::Healed { .. } | healer::Outcome::Deleted => {
                healed += 1;
                if let Some(root) = gitscan::repo_root(f.path.parent().unwrap_or(&f.path)) {
                    gitscan::stage(&root, &f.path);
                }
            }
            healer::Outcome::Failed(r) => manual.push(format!("{} - {r}", f.path.display())),
            healer::Outcome::Skipped(_) => {}
        }
        if json {
            let iocs: Vec<String> = f.hits.iter().map(|h| format!("\"{}\"", util::json_escape(h.ioc))).collect();
            j_cleaned.push(format!(
                "{{\"path\":\"{}\",\"outcome\":\"{}\",\"indicators\":[{}]}}",
                util::json_escape(&f.path.to_string_lossy()),
                util::json_escape(outcome.label().trim()),
                iocs.join(",")
            ));
        }
        if !json {
            let iocs: Vec<&str> = f.hits.iter().map(|h| h.ioc).collect();
            sayln!(
                "  {} {}",
                util::c(GREEN, &outcome.label()),
                f.path.display()
            );
            sayln!("      {}", util::c(DIM, &iocs.join(", ")));
        }
    };

    // Walk each root one immediate subdirectory at a time, so the output shows
    // where it has got to instead of sitting silent for minutes.
    for root in &roots {
        let mut subdirs: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(root) {
            for e in entries.flatten() {
                if e.metadata().map(|m| m.is_dir()).unwrap_or(false) {
                    let name = e.file_name();
                    if !scanner::skip_dir(&name.to_string_lossy()) {
                        subdirs.push(e.path());
                    }
                }
            }
        }
        subdirs.sort();
        // Files sitting directly in the root, plus each subtree in turn.
        if !json {
            sayln!("{}", util::c(DIM, &format!("  [{}]", root.display())));
        }
        for d in subdirs {
            if !json {
                sayln!("{}", util::c(DIM, &format!("    scanning {}", d.display())));
            }
            scanner::scan_tree_cb(&d, false, &mut handle);
        }
        scanner::scan_tree_cb(root, true, &mut handle);
    }

    // 4. The AppData hideouts the walk above deliberately skips (the fake
    //    Microsoft\CLR_v4.0 stage, the npm loader's drop dirs, package caches).
    //    Small and specific, scanned last.
    if !json {
        sayln!("{}", util::c(DIM, "    scanning known hideouts and package caches"));
    }
    scanner::scan_hideouts_cb(&mut handle);
    drop(handle);

    // 4b. Cached malicious npm packages are directories; the healer works on
    //     files, so they are removed here.
    for dir in scanner::cached_malicious_packages() {
        if dry {
            if json {
                j_cleaned.push(format!("{{\"path\":\"{}\",\"outcome\":\"would remove package directory\",\"indicators\":[\"malicious-npm-package\"]}}", util::json_escape(&dir.to_string_lossy())));
            } else {
                sayln!("  {} {}", util::c(YELLOW, "would remove"), dir.display());
            }
            continue;
        }
        let ok = std::fs::remove_dir_all(&dir).is_ok();
        if ok { healed += 1; } else { manual.push(format!("{} - could not remove the package directory", dir.display())); }
        if json {
            j_cleaned.push(format!(
                "{{\"path\":\"{}\",\"outcome\":\"{}\",\"indicators\":[\"malicious-npm-package\"]}}",
                util::json_escape(&dir.to_string_lossy()),
                if ok { "removed package directory" } else { "could not remove package directory" }
            ));
        }
        if !json {
            let colour = if ok { GREEN } else { RED };
            let verb = if ok { "removed  " } else { "FAILED   " };
            sayln!("  {} {}", util::c(colour, verb), dir.display());
        }
    }

    // 5. Every repository's own git config: an injected core.fsmonitor or a
    //    hook that fetches and runs code survives a perfectly clean work tree.
    if !json {
        sayln!("{}", util::c(DIM, "    auditing git configuration of every repository"));
    }
    let cfg_hits = audit_repo_configs(&roots);
    let mut cfg_fixed = 0usize;
    if !cfg_hits.is_empty() {
        if !json {
            report::print_config_hits(&cfg_hits, false);
        }
        cfg_fixed = fix_repo_configs(&cfg_hits, dry, json);
        for h in &cfg_hits {
            if !h.fixable && h.sev == polinrider_hunter::signatures::Severity::Critical {
                manual.push(format!("{} :: {} - {}", h.location.display(), h.key, h.why));
            }
        }
    }
    healed += cfg_fixed;

    // 6. Evidence of a ClickFix / fake-CAPTCHA command having been run.
    let clickfix = winpersist::clickfix_history();
    for c in &clickfix {
        manual.push(format!("Run-dialog history holds a fetch-and-execute command (ClickFix): {c}"));
        if !json {
            sayln!("  {} {}", util::c(YELLOW, "clickfix "), c);
        }
    }

    if json {
        let strs = |v: &[String]| v.iter().map(|s| format!("\"{}\"", util::json_escape(s))).collect::<Vec<_>>().join(",");
        let startup: Vec<String> = persist_hits
            .iter()
            .map(|h| format!("{{\"location\":\"{}\",\"line\":{},\"why\":\"{}\"}}", util::json_escape(&h.location), h.line_no, util::json_escape(h.why)))
            .collect();
        sayln!(
            "{{\"dry\":{dry},\"healed\":{healed},\"found\":{found},\"needs_review\":{noted},\"persistence_removed\":{persist_removed},\"manual\":{},\
             \"processes\":[{}],\"persistence\":[{}],\"startup_review\":[{}],\"cleaned\":[{}],\"review\":[{}],\"clickfix\":[{}],\"manual_items\":[{}],\"quarantine\":\"{}\"}}",
            manual.len(),
            j_procs.join(","),
            j_persist.join(","),
            startup.join(","),
            j_cleaned.join(","),
            j_review.join(","),
            strs(&clickfix),
            strs(&manual),
            util::json_escape(&config::quarantine_dir().to_string_lossy())
        );
        return if manual.is_empty() { 0 } else { 1 };
    }

    util::status::stop();
    sayln!();
    sayln!(
        "{} {} loader process(es) stopped, {} persistence entr(y/ies) removed, {} of {} finding(s) cleaned, {} need a look",
        util::c(BOLD, "hunt complete:"),
        killed,
        persist_removed,
        healed,
        found,
        manual.len() + noted + persist_hits.len()
    );
    if noted > 0 {
        sayln!();
        sayln!(
            "{}",
            util::c(
                BOLD,
                &format!("  {noted} file(s) marked \"review\" - nothing was changed in them")
            )
        );
        sayln!(
            "{}",
            util::c(
                DIM,
                "  A weaker match than the ones cleaned above. It is usually one of:\n                   documentation or notes that quote the indicators; a JSON, YAML or UTF-16\n                   file where cutting bytes out would corrupt it; or a single weak signal\n                   with nothing to corroborate it. Open them and judge - or leave them,\n                   since a review finding is a question, not damage."
            )
        );
    }
    if !persist_hits.is_empty() {
        sayln!(
            "{}",
            util::c(
                YELLOW,
                &format!(
                    "  {} startup location(s) need your eyes - run `polinrider-hunter persistence`",
                    persist_hits.len()
                )
            )
        );
    }
    if !manual.is_empty() {
        sayln!("\n{}", util::c(YELLOW, "clean these by hand:"));
        for m in &manual {
            sayln!("  {m}");
        }
    }
    if healed > 0 && !dry {
        sayln!(
            "{}",
            util::c(
                DIM,
                &format!("originals kept in {}", config::quarantine_dir().display())
            )
        );
        sayln!(
            "{}",
            util::c(
                DIM,
                "run `polinrider-hunter install` to keep it from coming back"
            )
        );
    }
    if manual.is_empty() {
        0
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// The AI agent
// ---------------------------------------------------------------------------

fn agent_paths(args: &Args, cfg: &Config) -> Vec<PathBuf> {
    let mut paths = target_paths(args, cfg);
    if paths.is_empty() {
        // No configured paths: the projects under the current directory are the
        // natural default for "investigate this".
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let repos = config::discover_repos_under(&[cwd.clone()], 3);
        paths = if repos.is_empty() { vec![cwd] } else { repos };
    }
    paths.into_iter().map(|p| config::normalize(&p)).collect()
}

fn cmd_set_key(args: &Args, mut cfg: Config) -> i32 {
    let given = args.positional.first().cloned().or_else(|| args.key.clone());
    if given.is_some() || args.vt_key.is_some() {
        warn_key_on_command_line();
    }
    let Some(k) = given.or_else(|| prompt_key("Gemini")) else {
        eprintln!("usage: polinrider-hunter set-key [--model <id>]   (paste the key when asked)\n\nGet a free key at https://aistudio.google.com/apikey (no card needed).");
        return 2;
    };
    cfg.gemini_key = k.trim().to_string();
    if let Some(m) = &args.model { cfg.gemini_model = m.trim().to_string(); }
    if let Some(v) = &args.vt_key { cfg.vt_key = v.trim().to_string(); }
    match cfg.save() {
        Ok(()) => {
            println!("{} key saved to {}", util::c(GREEN, "ok"), config::config_path().display());
            println!("{}", util::c(DIM, "try: polinrider-hunter agent"));
            0
        }
        Err(e) => { eprintln!("could not save config: {e}"); 1 }
    }
}

/// A key typed as an argument is in the shell's history file and in the
/// process list while the command runs; say so, once.
fn warn_key_on_command_line() {
    eprintln!("{}", util::c(YELLOW, "warning: a key given on the command line is saved in your shell history - prefer `polinrider-hunter ai key <provider>` (asks for it) or an environment variable, and clear the history entry."));
}

/// Ask for a key on the terminal (hidden on Unix).
fn prompt_key(label: &str) -> Option<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        // Piped in: `cat key.txt | polinrider-hunter ai key anthropic`.
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
        return Some(s.trim().to_string()).filter(|k| !k.is_empty());
    }
    println!(
        "{}",
        util::c(DIM, "  Paste the key and press Enter. Typing is hidden, so nothing appears while you paste - that is expected. Right-click or Ctrl+Shift+V pastes in most terminals.")
    );
    config::read_secret(&format!("  {label} key: "))
}

fn build_model(args: &Args, cfg: &Config) -> Result<Box<dyn gemini::Model>, String> {
    use std::io::IsTerminal;
    let mut cfg = cfg.clone();
    if args.key.is_some() {
        warn_key_on_command_line();
    }
    let mut provider = llm::resolve_provider(args.provider.as_deref(), &cfg);
    // First run with nobody's key yet: set one up here, the way an installer
    // would, instead of printing a list of commands and quitting. Only when a
    // person is at the keyboard - a pipe or CI still gets the explanation.
    if provider.is_none() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        println!("{}", util::c(BOLD, "No AI provider is set up yet - let's add one now (Ctrl+C to cancel)."));
        println!(
            "{}",
            util::c(DIM, "  Gemini has a free tier. No key at all? Use the hunter from Claude Code, Cursor or Codex instead: polinrider-hunter mcp")
        );
        println!();
        if ai_setup(cfg.clone()) == 0 {
            cfg = Config::load();
            provider = llm::resolve_provider(args.provider.as_deref(), &cfg);
        }
    }
    let Some(provider) = provider else {
        return Err(no_key_help());
    };
    if let Some(b) = &args.base_url {
        // --base-url belongs to the provider this run uses, nothing else.
        cfg.ai_base_url = b.clone();
        cfg.ai_provider = provider.clone();
    }
    let model = args.model.clone().or_else(|| std::env::var("POLINRIDER_MODEL").ok());
    llm::build(&provider, model.as_deref(), args.key.as_deref(), &cfg)
}

fn no_key_help() -> String {
    let mut s = String::from("no AI provider is set up yet. Pick one and add its key:\n");
    for p in llm::PROVIDERS.iter().filter(|p| p.id != "custom") {
        s.push_str(&format!("  polinrider-hunter ai key {:<10}   {} ({})\n", p.id, p.label, p.key_url));
    }
    s.push_str("or run the guided setup:  polinrider-hunter ai setup");
    s
}

/// `ai` - manage providers and keys; anything else is a task for the agent.
fn cmd_ai(args: &Args, mut cfg: Config) -> i32 {
    let sub = args.positional.first().map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "status".into());
    let arg = |i: usize| args.positional.get(i).cloned().unwrap_or_default();
    match sub.as_str() {
        "status" | "list" | "providers" => {
            let active = llm::resolve_provider(args.provider.as_deref(), &cfg);
            println!("{}", util::c(BOLD, "AI providers"));
            for p in llm::PROVIDERS {
                let key = llm::key_for(p.id, &cfg);
                let state = match (&key, p.needs_key) {
                    (Some(k), _) => util::c(GREEN, &format!("key {}", llm::mask(k))),
                    (None, false) => util::c(DIM, "no key needed"),
                    (None, true) => util::c(DIM, "no key"),
                };
                let mark = if active.as_deref() == Some(p.id) { util::c(GREEN, "*") } else { " ".into() };
                println!(" {mark} {:<11} {:<48} {}", p.id, p.label, state);
            }
            match &active {
                Some(a) => {
                    let model = if !cfg.ai_model.is_empty() && cfg.ai_provider.eq_ignore_ascii_case(a) { cfg.ai_model.clone() } else { llm::provider(a).map(|p| p.default_model.to_string()).unwrap_or_default() };
                    println!("\n  active: {} {}", util::c(BOLD, a), util::c(DIM, &format!("model {model}")));
                }
                None => println!("\n  {}", util::c(YELLOW, "no provider ready - polinrider-hunter ai setup")),
            }
            println!("  {}", util::c(DIM, &format!("agent mode: {}  ·  config: {}", if cfg.agent_mode.is_empty() { "ask" } else { &cfg.agent_mode }, config::config_path().display())));
            0
        }
        "key" | "set-key" | "add" => {
            let id = arg(1);
            if id.is_empty() {
                eprintln!("usage: polinrider-hunter ai key <provider>   (you are asked for the key)\nproviders: {}, vt", llm::PROVIDERS.iter().map(|p| p.id).collect::<Vec<_>>().join(", "));
                return 2;
            }
            if llm::provider(&id).is_none() && id != "vt" {
                eprintln!("unknown provider `{id}`");
                return 2;
            }
            let key = if arg(2).is_empty() {
                match prompt_key(&id) {
                    Some(k) => k,
                    None => {
                        eprintln!("no key entered");
                        return 2;
                    }
                }
            } else {
                warn_key_on_command_line();
                arg(2)
            };
            cfg.set_ai_key(&id, &key);
            if cfg.ai_provider.is_empty() && id != "vt" {
                cfg.ai_provider = id.to_ascii_lowercase();
            }
            save_cfg(&cfg, &format!("{id} key {} saved", llm::mask(&key)))
        }
        "remove" | "rm" | "delete" => {
            let id = arg(1);
            if id.is_empty() {
                eprintln!("usage: polinrider-hunter ai remove <provider>");
                return 2;
            }
            cfg.set_ai_key(&id, "");
            if cfg.ai_provider.eq_ignore_ascii_case(&id) {
                cfg.ai_provider.clear();
                cfg.ai_model.clear();
            }
            save_cfg(&cfg, &format!("{id} key removed"))
        }
        "use" | "provider" | "switch" => {
            let id = arg(1);
            if llm::provider(&id).is_none() {
                eprintln!("usage: polinrider-hunter ai use <provider> [model] [--base-url <url>]\nproviders: {}", llm::PROVIDERS.iter().map(|p| p.id).collect::<Vec<_>>().join(", "));
                return 2;
            }
            let switching = !cfg.ai_provider.eq_ignore_ascii_case(&id);
            cfg.ai_provider = id.to_ascii_lowercase();
            cfg.ai_model = arg(2).or_else_model(args);
            if let Some(b) = &args.base_url {
                cfg.ai_base_url = b.clone();
            } else if switching && !matches!(cfg.ai_provider.as_str(), "custom" | "ollama") {
                // An endpoint set for the previous provider must not receive this one's key.
                cfg.ai_base_url.clear();
            }
            save_cfg(&cfg, &format!("now using {}{}", cfg.ai_provider, if cfg.ai_model.is_empty() { String::new() } else { format!(" / {}", cfg.ai_model) }))
        }
        "mode" => {
            let m = arg(1);
            match agent::Mode::parse(&m) {
                Some(mode) if !m.is_empty() => {
                    cfg.agent_mode = mode.label().to_string();
                    save_cfg(&cfg, &format!("default agent mode is now {}", mode.label()))
                }
                _ => {
                    eprintln!("usage: polinrider-hunter ai mode <read-only|ask|workspace-write|full-access>");
                    2
                }
            }
        }
        "setup" | "init" | "login" => ai_setup(cfg),
        "test" | "ping" => {
            let mut m = match build_model(args, &cfg) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("{} {e}", util::c(RED, "ai:"));
                    return 2;
                }
            };
            println!("{} {}", util::c(DIM, "asking"), m.name());
            let ask = polinrider_hunter::json::Json::obj(vec![
                ("role", polinrider_hunter::json::Json::str("user")),
                ("parts", polinrider_hunter::json::Json::arr(vec![polinrider_hunter::json::Json::obj(vec![("text", polinrider_hunter::json::Json::str("Reply with exactly: polinrider-hunter AI link OK"))])])),
            ]);
            match m.generate("You are a connectivity check. Answer in one short line.", &[ask], &polinrider_hunter::json::Json::arr(vec![])) {
                Ok(turn) => {
                    let text: String = turn.get("parts").and_then(|p| p.as_arr()).cloned().unwrap_or_default().iter().filter_map(|p| p.get("text").and_then(|t| t.as_str()).map(str::to_string)).collect::<Vec<_>>().join(" ");
                    println!("{} {}", util::c(GREEN, "ok"), text.trim());
                    0
                }
                Err(e) => {
                    eprintln!("{} {e}", util::c(RED, "failed:"));
                    1
                }
            }
        }
        _ => {
            // Not a subcommand: the words are a task for the agent.
            let mut a = Args {
                cmd: "agent".into(),
                positional: Vec::new(),
                flags: args.flags.clone(),
                interval: args.interval,
                port: args.port,
                key: args.key.clone(),
                model: args.model.clone(),
                task: Some(args.task.clone().unwrap_or_else(|| args.positional.join(" "))),
                max_steps: args.max_steps,
                vt_key: args.vt_key.clone(),
                provider: args.provider.clone(),
                mode: args.mode.clone(),
                base_url: args.base_url.clone(),
                urls: Vec::new(),
                skip_remotes: None,
            };
            if !a.has("--once") {
                // `ai "do X"` stays in the chat after the task, like the REPL.
                a.flags.push("--chat".into());
            }
            cmd_agent(&a, cfg)
        }
    }
}

trait OrElseModel {
    fn or_else_model(self, args: &Args) -> String;
}
impl OrElseModel for String {
    fn or_else_model(self, args: &Args) -> String {
        if self.is_empty() { args.model.clone().unwrap_or_default() } else { self }
    }
}

fn save_cfg(cfg: &Config, msg: &str) -> i32 {
    match cfg.save() {
        Ok(()) => {
            println!("{} {msg} ({})", util::c(GREEN, "ok"), config::config_path().display());
            0
        }
        Err(e) => {
            eprintln!("could not save config: {e}");
            1
        }
    }
}

/// Guided provider setup: pick, paste the key, test it.
fn ai_setup(mut cfg: Config) -> i32 {
    use std::io::{BufRead, Write};
    let read = |prompt: &str| -> Option<String> {
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        let mut s = String::new();
        match std::io::stdin().lock().read_line(&mut s) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(s.trim().to_string()),
        }
    };
    println!("{}", util::c(BOLD, "Set up the AI agent"));
    let default = llm::PROVIDERS.iter().position(|p| p.id == "gemini").unwrap_or(0);
    for (i, p) in llm::PROVIDERS.iter().enumerate() {
        let mark = if i == default { util::c(GREEN, "  <- default") } else { String::new() };
        println!("  {:>2}. {:<11} {}{}", i + 1, p.id, p.label, mark);
    }
    // Ask until the answer is usable: quitting on a typo throws away a setup the
    // user has just started.
    let p = loop {
        let Some(choice) = read(&format!("provider [number or name, Enter = {}]: ", llm::PROVIDERS[default].id)) else { return 2 };
        let choice = choice.trim().to_string();
        let pick = if choice.is_empty() {
            llm::PROVIDERS.get(default)
        } else {
            choice.parse::<usize>().ok().and_then(|n| llm::PROVIDERS.get(n.wrapping_sub(1))).or_else(|| llm::provider(&choice))
        };
        match pick {
            Some(p) => break p,
            None => println!("  {} `{choice}` is not one of the numbers or names above", util::c(YELLOW, "?")),
        }
    };
    println!("  {} {}", util::c(GREEN, "->"), p.label);
    if p.needs_key {
        println!("  get a key at {}", util::c(BOLD, p.key_url));
        let Some(key) = prompt_key(p.label) else {
            eprintln!("no key entered - run `polinrider-hunter ai setup` again when you have one");
            return 2;
        };
        cfg.set_ai_key(p.id, &key);
    }
    if p.id == "custom" || p.id == "ollama" {
        let def = if p.base_url.is_empty() { "http://localhost:1234/v1" } else { p.base_url };
        let url = read(&format!("endpoint [{def}]: ")).unwrap_or_default();
        cfg.ai_base_url = if url.is_empty() { def.to_string() } else { url };
    }
    let model = read(&format!("model [{}]: ", if p.default_model.is_empty() { "required" } else { p.default_model })).unwrap_or_default();
    cfg.ai_provider = p.id.to_string();
    cfg.ai_model = model;
    if save_cfg(&cfg, &format!("{} configured", p.id)) != 0 {
        return 1;
    }
    let args = Args { cmd: "ai".into(), positional: vec!["test".into()], flags: vec![], interval: None, port: None, key: None, model: None, task: None, max_steps: None, vt_key: None, provider: None, mode: None, base_url: None, urls: Vec::new(), skip_remotes: None };
    // A mistyped or truncated paste is the usual failure: offer another go
    // rather than leaving a broken key saved.
    for attempt in 0..3 {
        println!("{}", util::c(DIM, "testing the connection..."));
        let code = cmd_ai(&args, Config::load());
        if code == 0 {
            println!("{}", util::c(GREEN, "ready - start with: polinrider-hunter agent"));
            return 0;
        }
        if !p.needs_key || attempt == 2 {
            return code;
        }
        let again = read("the test failed - paste a different key? [Y/n]: ").unwrap_or_default();
        if again.eq_ignore_ascii_case("n") || again.eq_ignore_ascii_case("no") {
            return code;
        }
        let Some(key) = prompt_key(p.label) else { return code };
        cfg.set_ai_key(p.id, &key);
        if save_cfg(&cfg, &format!("{} key updated", p.id)) != 0 {
            return 1;
        }
    }
    1
}

fn cmd_agent(args: &Args, cfg: Config) -> i32 {
    let model = match build_model(args, &cfg) {
        Ok(m) => m,
        Err(e) => { eprintln!("{} {e}", util::c(RED, "agent:")); return 2; }
    };
    let paths = agent_paths(args, &cfg);
    let yes = args.has("--yes");
    let mode_name = args.mode.clone().unwrap_or_else(|| cfg.agent_mode.clone());
    let mode = if yes { agent::Mode::FullAccess } else {
        match agent::Mode::parse(&mode_name) {
            Some(m) => m,
            None => { eprintln!("unknown --mode `{mode_name}` (read-only | ask | workspace-write | full-access)"); return 2; }
        }
    };
    // No task (or `ai "task"`) = a chat that stays open; --task = one job, then exit.
    let interactive = args.task.is_none() || args.has("--chat");
    let opts = agent::Options {
        yes,
        interactive,
        max_steps: args.max_steps.unwrap_or(if interactive { 400 } else { 60 }),
        paths,
        verbose: args.has("--verbose"),
    };
    let vt = args.vt_key.clone().or_else(|| std::env::var("VT_API_KEY").ok()).unwrap_or_else(|| cfg.vt_key.clone());
    let mut a = agent::Agent::new(model, opts, &vt).with_config(cfg.clone());
    a.set_mode(mode);

    println!("{}", util::c(BOLD, "polinrider-hunter agent"));
    println!("{}", util::c(DIM, "  Malware responder and terminal engineer. Ask for anything on this machine or your repos -\n  investigate, clean, repair branches, edit code, run builds/tests. /help for commands, exit to stop."));
    match mode {
        agent::Mode::FullAccess => println!("{}", util::c(YELLOW, "  full-access: changes run without asking. Disk wipes and download-piped-to-shell are still refused.")),
        agent::Mode::ReadOnly => println!("{}", util::c(DIM, "  read-only: nothing on this machine will be changed.")),
        agent::Mode::WorkspaceWrite => println!("{}", util::c(DIM, "  workspace-write: file edits inside the workspace run without asking; everything else asks.")),
        agent::Mode::Ask => {}
    }
    println!();
    let task = if args.has("--investigate") { agent::DEFAULT_INVESTIGATION.to_string() } else { args.task.clone().unwrap_or_default() };
    match a.run(&task) {
        Ok(summary) => {
            println!();
            println!("{} {} step(s), {:.0}s, transcript {}", util::c(DIM, "session:"), a.steps, a.elapsed().as_secs_f32(), a.transcript_path().display());
            for r in &a.reports { println!("{} {}", util::c(GREEN, "report:"), r.display()); }
            let _ = summary;
            0
        }
        Err(e) => {
            eprintln!("{} {e}", util::c(RED, "agent error:"));
            eprintln!("{}", util::c(DIM, &format!("transcript so far: {}", a.transcript_path().display())));
            1
        }
    }
}

fn cmd_report(args: &Args, cfg: Config) -> i32 {
    let paths = agent_paths(args, &cfg);
    let dir = config::home().join("reports");
    let _ = std::fs::create_dir_all(&dir);
    // With a key: the agent investigates and writes the report itself.
    if llm::resolve_provider(args.provider.as_deref(), &cfg).is_some() && !args.has("--plain") {
        let model = match build_model(args, &cfg) { Ok(m) => m, Err(e) => { eprintln!("{e}"); return 2; } };
        let opts = agent::Options { yes: false, interactive: false, max_steps: args.max_steps.unwrap_or(40), paths, verbose: args.has("--verbose") };
        let vt = std::env::var("VT_API_KEY").unwrap_or_else(|_| cfg.vt_key.clone());
        let mut a = agent::Agent::new(model, opts, &vt);
        a.set_mode(agent::Mode::ReadOnly);
        println!("{}", util::c(BOLD, "writing an incident report (read-only investigation; nothing will be changed)"));
        let task = "Produce a complete incident report for this machine and the project directories using READ-ONLY tools only (scan, repos_audit, repos_history, repos_repair with dry_run=true, persistence, processes, credential_exposure, quarantine_list, list_dir, read_file, run_command with read-only commands, web_search). Do not call clean, remove_persistence, repos_fix, repos_excise, kill_process or repos_repair with dry_run=false. Then call write_report with the full report and finish with a 5-line summary.";
        return match a.run(task) {
            Ok(_) => { for r in &a.reports { println!("{} {}", util::c(GREEN, "report:"), r.display()); } if a.reports.is_empty() { println!("{}", util::c(YELLOW, "the model did not write a report file; see the transcript")); } 0 }
            Err(e) => { eprintln!("{} {e}", util::c(RED, "report:")); 1 }
        };
    }
    // Without a key: a factual status report from the hunter's own engines.
    let md = agent::deterministic_report(&paths);
    let path = dir.join(format!("{}-status.md", util::fmt_stamp(util::now_secs())));
    match std::fs::write(&path, &md) {
        Ok(()) => { println!("{md}"); println!("{} {}", util::c(GREEN, "saved:"), path.display()); println!("{}", util::c(DIM, "(set up an AI provider with `polinrider-hunter ai setup` for an AI-written root-cause report)")); 0 }
        Err(e) => { eprintln!("could not write report: {e}"); 1 }
    }
}

fn cmd_scan(args: &Args, cfg: &Config, json: bool) -> i32 {
    let paths = target_paths(args, cfg);
    if !require_paths(&paths) {
        return 2;
    }
    let findings = scanner::scan_paths(&paths, args.has("--quick"));
    report::print_findings(&findings, json);
    let cfg_hits = audit_repo_configs(&paths);
    if !cfg_hits.is_empty() {
        if !json {
            println!();
        }
        report::print_config_hits(&cfg_hits, json);
    }
    let crit_cfg = cfg_hits.iter().any(|h| h.sev == polinrider_hunter::signatures::Severity::Critical);
    if findings.iter().any(|f| f.is_critical()) || crit_cfg {
        1
    } else {
        0
    }
}

/// Every repository at or under `paths`, audited for executable git config.
fn audit_repo_configs(paths: &[PathBuf]) -> Vec<gitconfig::ConfigHit> {
    let mut repos: Vec<PathBuf> = Vec::new();
    for p in paths {
        if gitscan::is_repo(p) {
            if let Some(root) = gitscan::repo_root(p) {
                if !repos.contains(&root) {
                    repos.push(root);
                }
            }
        } else {
            for r in config::discover_repos_under(&[p.clone()], 6) {
                if !repos.contains(&r) {
                    repos.push(r);
                }
            }
        }
    }
    let mut out = Vec::new();
    for r in repos {
        out.extend(gitconfig::audit(&r));
    }
    out
}

/// Fix what can be fixed in the config hits; print what happened.
fn fix_repo_configs(hits: &[gitconfig::ConfigHit], dry: bool, json: bool) -> usize {
    let mut fixed = 0usize;
    for h in hits {
        if !h.fixable {
            continue;
        }
        let ok = gitconfig::fix(h, dry);
        if ok {
            fixed += 1;
        }
        if !json {
            let colour = if ok { GREEN } else { RED };
            let verb = if dry { "would unset" } else if ok { "unset    " } else { "FAILED   " };
            println!("  {} {} {} (in {})", util::c(colour, verb), h.key, util::c(DIM, &h.value), h.location.display());
        }
    }
    fixed
}

fn cmd_clean(args: &Args, cfg: &Config, json: bool) -> i32 {
    let paths = target_paths(args, cfg);
    if !require_paths(&paths) {
        return 2;
    }
    let dry = args.has("--dry-run");
    let findings = scanner::scan_paths(&paths, false);
    let cfg_hits = audit_repo_configs(&paths);
    if findings.is_empty() && cfg_hits.is_empty() {
        if json {
            println!("{{\"findings\":[]}}");
            println!("{{\"type\":\"summary\",\"dry\":{dry},\"found\":0,\"healed\":0,\"failed\":0}}");
        } else {
            println!("{}", util::c(GREEN, "Nothing to clean."));
        }
        return 0;
    }
    report::print_findings(&findings, json);
    if !cfg_hits.is_empty() {
        if !json {
            println!();
        }
        report::print_config_hits(&cfg_hits, json);
        if !json {
            println!();
        }
        fix_repo_configs(&cfg_hits, dry, json);
    }
    if !json {
        println!();
    }

    let mut healed = 0usize;
    let mut failed = 0usize;
    for f in &findings {
        if !f.is_critical() {
            continue;
        }
        let outcome = healer::heal(f, dry);
        let ok = matches!(
            outcome,
            healer::Outcome::Healed { .. } | healer::Outcome::Deleted
        );
        if ok {
            healed += 1;
            if let Some(root) = gitscan::repo_root(f.path.parent().unwrap_or(&f.path)) {
                gitscan::stage(&root, &f.path);
            }
        }
        if matches!(outcome, healer::Outcome::Failed(_)) {
            failed += 1;
        }
        if json {
            println!(
                "{{\"type\":\"heal\",\"path\":\"{}\",\"outcome\":\"{}\",\"ok\":{ok},\"dry\":{dry}}}",
                util::json_escape(&f.path.to_string_lossy()),
                util::json_escape(outcome.label().trim())
            );
            continue;
        }
        let colour = if ok { GREEN } else { YELLOW };
        println!(
            "  {} {}",
            util::c(colour, &outcome.label()),
            f.path.display()
        );
    }
    if json {
        println!(
            "{{\"type\":\"summary\",\"dry\":{dry},\"found\":{},\"healed\":{healed},\"failed\":{failed},\"quarantine\":\"{}\"}}",
            findings.len(),
            util::json_escape(&config::quarantine_dir().to_string_lossy())
        );
        return if failed > 0 { 1 } else { 0 };
    }
    println!();
    report::summary_line(findings.len(), healed);
    if !dry {
        println!(
            "{}",
            util::c(
                DIM,
                &format!("originals kept in {}", config::quarantine_dir().display())
            )
        );
    }
    if failed > 0 {
        1
    } else {
        0
    }
}

/// One repository under audit: a local path, or a temporary bare mirror of a
/// URL (see `remote::mirror`). Mirrors are deleted when they are dropped.
struct RepoTarget {
    path: PathBuf,
    /// What to print for it: the path, or the URL it mirrors.
    label: String,
    bare: bool,
}

/// An infected remote branch, with everything needed to say who can fix it.
struct InfectedBranch {
    repo: PathBuf,
    remote: String,
    branch: String,
    git_ref: String,
    files: Vec<String>,
    iocs: Vec<String>,
    access: gitscan::Access,
    who: Vec<gitscan::Pusher>,
}

/// Resolve the paths and URLs `repos` was given.
fn repo_targets(args: &Args, cfg: &Config, json: bool) -> (Vec<RepoTarget>, Vec<remote::Mirror>, usize) {
    let mut targets = Vec::new();
    let mut mirrors = Vec::new();
    let mut failed = 0usize;
    let paths: Vec<PathBuf> = if args.positional.is_empty() && args.urls.is_empty() {
        cfg.paths.clone()
    } else {
        args.positional.iter().map(PathBuf::from).collect()
    };
    for p in paths {
        let bare = gitscan::is_bare(&p);
        if !bare && !gitscan::is_repo(&p) {
            continue;
        }
        targets.push(RepoTarget { label: p.display().to_string(), path: p, bare });
    }
    for u in &args.urls {
        if !json {
            println!("{} {}", util::c(DIM, "fetching"), u);
        }
        match remote::mirror(u) {
            Ok(m) => {
                targets.push(RepoTarget { path: m.dir.clone(), label: u.clone(), bare: true });
                mirrors.push(m);
            }
            Err(e) => {
                failed += 1;
                if json {
                    println!("{{\"type\":\"error\",\"url\":\"{}\",\"error\":\"{}\"}}", util::json_escape(u), util::json_escape(&e));
                } else {
                    println!("  {} {}: {}", util::c(RED, "cannot fetch"), u, e);
                }
            }
        }
    }
    (targets, mirrors, failed)
}

/// `write_access`, remembered per (repository, remote) for the run.
fn access_for(cache: &mut Vec<(PathBuf, String, gitscan::Access)>, repo: &std::path::Path, remote: &str, online: bool) -> gitscan::Access {
    if let Some((_, _, a)) = cache.iter().find(|(p, r, _)| p == repo && r == remote) {
        return a.clone();
    }
    let a = if online {
        gitscan::write_access(repo, remote)
    } else {
        let url = gitscan::remote_url(repo, remote);
        let (_, owner, name) = gitscan::parse_remote_url(&url).unwrap_or_default();
        let project = if owner.is_empty() { String::new() } else { format!("{owner}/{name}") };
        gitscan::Access { can_write: None, how: "not checked (--no-fetch)".into(), owner, project, url }
    };
    cache.push((repo.to_path_buf(), remote.to_string(), a.clone()));
    a
}

fn access_json(label: &str, remote: &str, branch: &str, a: &gitscan::Access, files: &[String], iocs: &[String], who: &[gitscan::Pusher]) -> String {
    let strs = |v: &[String]| v.iter().map(|s| format!("\"{}\"", util::json_escape(s))).collect::<Vec<_>>().join(",");
    let who: Vec<String> = who
        .iter()
        .map(|p| {
            format!(
                "{{\"name\":\"{}\",\"email\":\"{}\",\"sha\":\"{}\",\"date\":\"{}\"}}",
                util::json_escape(&p.name),
                util::json_escape(&p.email),
                p.sha,
                util::json_escape(&p.date)
            )
        })
        .collect();
    format!(
        "{{\"type\":\"access\",\"repo\":\"{}\",\"remote\":\"{}\",\"branch\":\"{}\",\"url\":\"{}\",\"owner\":\"{}\",\"project\":\"{}\",\"can_write\":{},\"how\":\"{}\",\"files\":[{}],\"indicators\":[{}],\"who_pushed\":[{}]}}",
        util::json_escape(label),
        util::json_escape(remote),
        util::json_escape(branch),
        util::json_escape(&a.url),
        util::json_escape(&a.owner),
        util::json_escape(&a.project),
        match a.can_write { Some(b) => b.to_string(), None => "null".into() },
        util::json_escape(&a.how),
        strs(files),
        strs(iocs),
        who.join(",")
    )
}

fn who_line(who: &[gitscan::Pusher]) -> String {
    if who.is_empty() {
        return "(no commit found for the infected files)".into();
    }
    who.iter()
        .map(|p| format!("{} <{}> ({}, {})", p.name, p.email, &p.sha[..10.min(p.sha.len())], p.date))
        .collect::<Vec<_>>()
        .join("; ")
}

const ASK_LINE: &str = "ask them to run: polinrider-hunter repos --repair <their clone>";

/// `repos --access`: only the question "can I push to this, and who owns it?".
fn cmd_repos_access(targets: &[RepoTarget], do_fetch: bool, json: bool) -> i32 {
    let mut cache = Vec::new();
    let mut unknown = 0usize;
    for t in targets {
        if do_fetch && !t.bare {
            gitscan::fetch(&t.path);
        }
        for r in gitscan::remotes(&t.path) {
            let a = access_for(&mut cache, &t.path, &r, true);
            if a.can_write.is_none() {
                unknown += 1;
            }
            if json {
                println!("{}", access_json(&t.label, &r, "", &a, &[], &[], &[]));
                continue;
            }
            let verdict = match a.can_write {
                Some(true) => util::c(GREEN, "CAN PUSH   "),
                Some(false) => util::c(RED, "READ-ONLY  "),
                None => util::c(YELLOW, "UNKNOWN    "),
            };
            println!("{verdict} {} {} {}", util::c(DIM, &t.label), util::c(BOLD, &r), a.url);
            if !a.project.is_empty() {
                println!("    owner: {}  project: {}", a.owner, a.project);
            }
            println!("    {}", util::c(DIM, &a.how));
        }
    }
    if unknown > 0 { 1 } else { 0 }
}

fn cmd_repos(args: &Args, cfg: &Config, json: bool) -> i32 {
    if args.positional.is_empty() && args.urls.is_empty() && !require_paths(&cfg.paths) {
        return 2;
    }
    let do_fetch = !args.has("--no-fetch");
    let (targets, _mirrors, url_failed) = repo_targets(args, cfg, json);
    let label = |p: &std::path::Path| -> String {
        targets.iter().find(|t| t.path == p).map(|t| t.label.clone()).unwrap_or_else(|| p.display().to_string())
    };
    let relabel = |hits: &[gitscan::RefHit]| -> Vec<gitscan::RefHit> {
        hits.iter().map(|h| gitscan::RefHit { repo: PathBuf::from(label(&h.repo)), ..h.clone() }).collect()
    };
    let audit = |t: &RepoTarget, fetch: bool| -> Vec<gitscan::RefHit> {
        if t.bare { gitscan::scan_bare(&t.path) } else { gitscan::scan_repo(&t.path, fetch) }
    };
    let with_url_failures = |code: i32| if url_failed > 0 && code == 0 { 2 } else { code };

    if args.has("--access") {
        return with_url_failures(cmd_repos_access(&targets, do_fetch, json));
    }

    let mut all = Vec::new();
    for t in &targets {
        if !json {
            println!("{} {}", util::c(DIM, "auditing"), t.label);
        }
        all.extend(audit(t, do_fetch));
    }
    report::print_ref_hits(&relabel(&all), json);

    // Ref tips answer "what would run if I checked this out". They do not
    // answer "what is still in this repository": cleaning a branch leaves every
    // earlier copy of the payload in the object database, reachable by object
    // id for anyone who has the repo. --history walks every blob instead.
    let mut hist: Vec<gitscan::HistoryHit> = Vec::new();
    if args.has("--history") {
        for t in &targets {
            if !json {
                println!("{} {}", util::c(DIM, "walking history of"), t.label);
            }
            hist.extend(gitscan::scan_history_any(&t.path, do_fetch));
        }
        if json {
            // The text report runs git against each repo path; only the JSON
            // can carry the URL in its place.
            let shown: Vec<gitscan::HistoryHit> = hist
                .iter()
                .map(|h| gitscan::HistoryHit { repo: PathBuf::from(label(&h.repo)), size: h.size, blob: h.blob.clone(), path: h.path.clone(), iocs: h.iocs.clone() })
                .collect();
            report::print_history_hits(&shown, true);
        } else {
            println!();
            report::print_history_hits(&hist, false);
        }
    }

    // Repository configuration is part of the audit too: an injected
    // core.fsmonitor or a hook that curls into sh is how a clean-looking clone
    // still runs attacker code.
    let mut cfg_hits = Vec::new();
    for t in &targets {
        cfg_hits.extend(gitconfig::audit(&t.path));
    }
    if !cfg_hits.is_empty() {
        if !json {
            println!();
        }
        report::print_config_hits(&cfg_hits, json);
    }

    // Who can push to each infected remote branch, and who put the infection
    // there. An audit that ends "infected" without saying who can act on it
    // leaves the reader stuck; this is the part that tells them.
    let mut infected: Vec<InfectedBranch> = Vec::new();
    for h in &all {
        let Some(short) = h.git_ref.strip_prefix("refs/remotes/") else { continue };
        let Some((remote, branch)) = short.split_once('/') else { continue };
        if let Some(b) = infected.iter_mut().find(|b| b.repo == h.repo && b.remote == remote && b.branch == branch) {
            if !b.files.contains(&h.file) {
                b.files.push(h.file.clone());
            }
            for i in &h.iocs {
                if !b.iocs.contains(i) {
                    b.iocs.push(i.clone());
                }
            }
            continue;
        }
        infected.push(InfectedBranch {
            repo: h.repo.clone(),
            remote: remote.to_string(),
            branch: branch.to_string(),
            git_ref: h.git_ref.clone(),
            files: vec![h.file.clone()],
            iocs: h.iocs.clone(),
            access: gitscan::Access { can_write: None, how: String::new(), owner: String::new(), project: String::new(), url: String::new() },
            who: Vec::new(),
        });
    }
    let mut cache: Vec<(PathBuf, String, gitscan::Access)> = Vec::new();
    for b in infected.iter_mut() {
        b.access = access_for(&mut cache, &b.repo, &b.remote, do_fetch);
        b.who = gitscan::who_pushed(&b.repo, &b.git_ref, &b.files);
        if json {
            println!("{}", access_json(&label(&b.repo), &b.remote, &b.branch, &b.access, &b.files, &b.iocs, &b.who));
        }
    }
    if !json {
        let cannot: Vec<&InfectedBranch> = infected.iter().filter(|b| b.access.can_write == Some(false)).collect();
        if !cannot.is_empty() {
            println!();
            println!("{}", util::c(BOLD, "infected branches you cannot push to"));
            for b in cannot {
                let owner = if b.access.project.is_empty() { b.access.url.clone() } else { format!("{} ({})", b.access.project, b.access.url) };
                println!("  {} {} {}/{}", util::c(YELLOW, "READ-ONLY"), util::c(DIM, &label(&b.repo)), b.remote, b.branch);
                println!("           owner: {owner}");
                println!("           {}", util::c(DIM, &b.access.how));
                println!("           pushed the infection: {}", who_line(&b.who));
                println!("           {}", util::c(BOLD, ASK_LINE));
            }
        }
        let unknown: Vec<&InfectedBranch> = infected.iter().filter(|b| b.access.can_write.is_none()).collect();
        if !unknown.is_empty() && do_fetch {
            println!();
            println!("{}", util::c(BOLD, "infected branches whose push access could not be determined"));
            for b in unknown {
                println!("  {} {} {}/{}", util::c(YELLOW, "UNKNOWN  "), util::c(DIM, &label(&b.repo)), b.remote, b.branch);
                println!("           {}", util::c(DIM, &b.access.how));
                println!("           pushed the infection: {}", who_line(&b.who));
            }
        }
    }

    let history_found = !hist.is_empty();
    let fix = args.has("--fix");
    let dry = args.has("--dry-run");
    let mut plans: Vec<gitscan::RemotePlan> = Vec::new();
    for t in &targets {
        // A mirror has no local branch to restore from; --fix is for clones.
        if !t.bare {
            plans.extend(gitscan::plan_remote_fixes(&t.path, &all));
        }
    }
    let mut unresolved = all.len();
    if !plans.is_empty() {
        if !json {
            println!();
            println!("{}", util::c(BOLD, if fix { "repairing remote branches" } else { "remote branches that could be repaired with --fix" }));
        }
        report::print_remote_plans(&plans, json);
        if fix {
            if !json {
                println!();
            }
            for plan in &plans {
                match gitscan::apply_remote_fix(plan, dry) {
                    Ok(msg) => {
                        if !dry {
                            unresolved = unresolved.saturating_sub(plan.infected_files.len());
                        }
                        if !json {
                            let verb = if dry { "dry-run " } else { "repaired" };
                            println!("  {} {}", util::c(GREEN, verb), msg);
                        }
                    }
                    Err(e) => {
                        if !json {
                            println!("  {} {}/{}: {}", util::c(RED, "not done"), plan.remote, plan.branch, e);
                        }
                    }
                }
            }
        }
    }
    // --excise: cut the poisoned commit out of each remote branch's recent
    // history, even with no clean local branch and even under a cleanup commit.
    let mut excised_ok = 0usize;
    let mut excise_failed = 0usize;
    if args.has("--excise") {
        let mut plans: Vec<gitscan::ExcisePlan> = Vec::new();
        for t in &targets {
            plans.extend(gitscan::plan_excisions(&t.path));
        }
        if !json {
            println!();
            if plans.is_empty() {
                println!(
                    "{}",
                    util::c(GREEN, &format!("No poisoned commit in the last {} commits of any remote branch.", gitscan::EXCISE_DEPTH))
                );
            } else {
                println!("{}", util::c(BOLD, if dry { "poisoned commits that --excise would remove" } else { "removing poisoned commits" }));
            }
        }
        for mut plan in plans {
            let name = format!("{}/{}", plan.remote, plan.branch);
            let shown = label(&plan.repo);
            match gitscan::apply_excise(&mut plan, dry) {
                Ok(msg) => {
                    excised_ok += 1;
                    if json {
                        println!(
                            "{{\"type\":\"excise\",\"repo\":\"{}\",\"branch\":\"{}\",\"ok\":true,\"poisoned\":\"{}\",\"new\":\"{}\",\"dry\":{}}}",
                            util::json_escape(&shown),
                            util::json_escape(&name),
                            plan.poisoned,
                            plan.rebuilt.clone().unwrap_or_default(),
                            dry
                        );
                    } else {
                        println!("  {} {} {}", util::c(GREEN, if dry { "dry-run " } else { "excised " }), util::c(DIM, &shown), msg);
                        println!("           {} {} restored: {}", util::c(DIM, "poisoned:"), &plan.poisoned[..10.min(plan.poisoned.len())], plan.restored.join(", "));
                    }
                }
                Err(e) => {
                    excise_failed += 1;
                    if json {
                        println!(
                            "{{\"type\":\"excise\",\"repo\":\"{}\",\"branch\":\"{}\",\"ok\":false,\"error\":\"{}\"}}",
                            util::json_escape(&shown),
                            util::json_escape(&name),
                            util::json_escape(&e)
                        );
                    } else {
                        println!("  {} {} {}: {}", util::c(YELLOW, "BLOCKED "), util::c(DIM, &shown), name, e);
                    }
                }
            }
        }
    }
    // --repair: clean each infected remote branch with one forward commit,
    // built in the object database (nothing checked out) and pushed as a plain
    // fast-forward. Works when teammates' work sits on top of the infection.
    if args.has("--repair") {
        let mut plans: Vec<gitscan::RepairPlan> = Vec::new();
        for t in &targets {
            plans.extend(gitscan::plan_repairs(&t.path, &all));
        }
        // Remotes that are somebody else's repository: report, do not push.
        let mut skip: Vec<String> = std::env::var("POLINRIDER_SKIP_REMOTES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(s) = &args.skip_remotes {
            skip.extend(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()));
        }
        plans.retain(|p| !skip.contains(&p.remote));
        if !json {
            println!();
            println!("{}", util::c(BOLD, if dry { "remote branches --repair would clean (dry run, nothing pushed)" } else { "repairing remote branches (forward commit, no force push)" }));
            if plans.is_empty() {
                println!("  {}", util::c(GREEN, "No infected remote branch tips."));
            }
        }
        let mut failed = 0usize;
        for mut plan in plans {
            let name = format!("{}/{}", plan.remote, plan.branch);
            let shown = label(&plan.repo);
            // No push access: say who has it instead of letting the push fail.
            if let Some(b) = infected.iter().find(|b| b.repo == plan.repo && b.remote == plan.remote && b.branch == plan.branch && b.access.can_write == Some(false)) {
                let owner = if b.access.project.is_empty() { b.access.url.clone() } else { format!("{} ({})", b.access.project, b.access.url) };
                let msg = format!("no push access to {owner} - {}; pushed the infection: {}; {ASK_LINE}", b.access.how, who_line(&b.who));
                failed += 1;
                if json {
                    println!(
                        "{{\"type\":\"repair\",\"repo\":\"{}\",\"branch\":\"{}\",\"ok\":false,\"dry\":{dry},\"blocked\":\"no push access\",\"message\":\"{}\",\"actions\":[]}}",
                        util::json_escape(&shown),
                        util::json_escape(&name),
                        util::json_escape(&msg)
                    );
                } else {
                    println!("  {} {} {}: {}", util::c(YELLOW, "BLOCKED "), util::c(DIM, &shown), name, msg);
                }
                continue;
            }
            let res = gitscan::apply_repair(&mut plan, dry);
            if json {
                let acts: Vec<String> = plan.actions.iter().map(|a| format!("\"{}\"", util::json_escape(a))).collect();
                let (ok, msg) = match &res {
                    Ok(m) => (true, m.clone()),
                    Err(e) => (false, e.clone()),
                };
                println!(
                    "{{\"type\":\"repair\",\"repo\":\"{}\",\"branch\":\"{}\",\"ok\":{ok},\"dry\":{dry},\"message\":\"{}\",\"actions\":[{}]}}",
                    util::json_escape(&shown),
                    util::json_escape(&name),
                    util::json_escape(&msg),
                    acts.join(",")
                );
            } else {
                match &res {
                    Ok(m) => println!("  {} {} {}", util::c(GREEN, if dry { "ready   " } else { "repaired" }), util::c(DIM, &shown), m),
                    Err(e) => println!("  {} {} {}: {}", util::c(YELLOW, "BLOCKED "), util::c(DIM, &shown), name, e),
                }
                for a in &plan.actions {
                    println!("           - {a}");
                }
            }
            if res.is_err() {
                failed += 1;
            }
        }
        if !dry {
            let remaining = targets
                .iter()
                .flat_map(|t| audit(t, false))
                .filter(|h| h.git_ref.starts_with("refs/remotes/"))
                .count();
            return with_url_failures(if failed == 0 && remaining == 0 { 0 } else { 1 });
        }
        return with_url_failures(if failed == 0 { 0 } else { 1 });
    }
    if args.has("--excise") && !dry {
        if excise_failed > 0 {
            return 1;
        }
        if excised_ok > 0 {
            // apply_excise re-audited each pushed tip. Local branches may still
            // point at the old poisoned commits, so judge the remote refs only.
            let remaining: Vec<_> = targets
                .iter()
                .flat_map(|t| audit(t, false))
                .filter(|h| h.git_ref.starts_with("refs/remotes/"))
                .collect();
            return with_url_failures(if remaining.is_empty() { 0 } else { 1 });
        }
    }
    if !json && !all.is_empty() {
        println!();
        if fix && !dry {
            println!("{}", util::c(DIM, "Repaired branches were re-fetched and re-audited. Anything still listed above needs a hand: see docs/GUIDE.md."));
        } else {
            println!(
                "{}",
                util::c(
                    YELLOW,
                    "These are branch contents, not your working tree. `repos --repair` adds one clean\n\
                     commit on top of each poisoned remote branch (no force push); `repos --fix` pushes\n\
                     your clean local branch over it instead. Add --dry-run to preview either."
                )
            );
        }
    }
    if history_found {
        // A payload still in the object database is a finding even when every
        // tip is clean, so this cannot exit 0 just because --fix succeeded.
        return 1;
    }
    with_url_failures(if all.is_empty() && cfg_hits.iter().all(|h| h.sev != polinrider_hunter::signatures::Severity::Critical) {
        0
    } else if fix && !dry && unresolved == 0 {
        0
    } else {
        1
    })
}

fn cmd_protect(args: &Args, cfg: &Config) -> i32 {
    let paths = target_paths(args, cfg);
    if !require_paths(&paths) {
        return 2;
    }
    let exe = config::exe_path();
    let mut n = 0;
    for p in &paths {
        match gitscan::repo_root(p) {
            Some(root) => match gitscan::install_hook(&root, &exe) {
                Ok(h) => {
                    println!("{} {}", util::c(GREEN, "protected"), h.display());
                    n += 1;
                }
                Err(e) => eprintln!("{} {}: {e}", util::c(RED, "failed"), p.display()),
            },
            None => eprintln!(
                "{} not a git repository: {}",
                util::c(YELLOW, "skip"),
                p.display()
            ),
        }
    }
    println!("{n} repo(s) protected");
    0
}

fn cmd_unprotect(args: &Args, cfg: &Config) -> i32 {
    let paths = target_paths(args, cfg);
    for p in &paths {
        if let Some(root) = gitscan::repo_root(p) {
            match gitscan::uninstall_hook(&root) {
                Ok(true) => println!("{} {}", util::c(GREEN, "hook removed"), root.display()),
                Ok(false) => println!("{} {}", util::c(DIM, "no hook"), root.display()),
                Err(e) => eprintln!("{} {}: {e}", util::c(RED, "failed"), root.display()),
            }
        }
    }
    0
}

/// Live view of everything the guard is doing.
fn cmd_monitor(args: &Args, cfg: &Config) -> i32 {
    if args.has("--json") {
        println!("{}", monitor::json_snapshot(cfg));
        return 0;
    }
    if args.has("--web") {
        let port = args.port.unwrap_or(8787);
        return monitor::serve(cfg, port);
    }
    if args.has("--once") {
        print!("{}", monitor::render(&monitor::snapshot(cfg)));
        return 0;
    }
    monitor::watch(cfg, args.interval.unwrap_or(3))
}

/// Show what the guard has been doing.
///
/// The commonest question about any background process is "is it actually doing
/// anything?", and answering it should not mean hunting for a log file - or
/// installing Python for the richer dashboard.
fn cmd_log(args: &Args) -> i32 {
    let path = config::log_path();
    let follow = args.has("--follow") || args.has("-f");
    let all = args.has("--all");

    let read = || -> Vec<String> {
        std::fs::read_to_string(&path)
            .map(|t| t.lines().map(str::to_string).collect())
            .unwrap_or_default()
    };

    let lines = read();
    if lines.is_empty() {
        println!("{}", util::c(DIM, &format!("no activity recorded yet ({})", path.display())));
        println!(
            "{}",
            util::c(DIM, "An empty log is the good outcome: it only writes when it finds something.")
        );
        return 0;
    }

    let start = if all { 0 } else { lines.len().saturating_sub(40) };
    if !all && start > 0 {
        println!("{}", util::c(DIM, &format!("... {start} earlier line(s), use --all")));
    }
    for line in &lines[start..] {
        println!("{}", colourise(line));
    }

    if !follow {
        println!();
        println!(
            "{}",
            util::c(
                DIM,
                "polinrider-hunter log --follow   watch it live\n\
                 python tools/monitor.py          full dashboard (--web for a browser view)"
            )
        );
        return 0;
    }

    // Polling rather than a filesystem watch: the guard appends a few lines a
    // day at most, and a dependency-free watcher is not worth the complexity.
    println!("{}", util::c(DIM, "-- following, Ctrl+C to stop --"));
    let mut seen = lines.len();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let now = read();
        if now.len() < seen {
            seen = 0; // rotated or cleared
        }
        for line in now.iter().skip(seen) {
            println!("{}", colourise(line));
        }
        seen = now.len();
    }
}

/// Tint a log line by what kind of event it is, so a wall of text reads at a glance.
fn colourise(line: &str) -> String {
    if line.contains(" DETECT ") {
        if line.contains("-> healed") || line.contains("-> deleted") {
            util::c(GREEN, line)
        } else {
            util::c(RED, line)
        }
    } else if line.contains(" PROC ") {
        util::c(RED, line)
    } else if line.contains(" NOTICE ") || line.contains(" REF ") {
        util::c(YELLOW, line)
    } else {
        util::c(DIM, line)
    }
}

/// Look where the loader would arrange to come back from.
fn cmd_persistence(args: &Args, json: bool) -> i32 {
    let remove = args.has("--remove");
    if !json {
        println!("{}", util::c(BOLD, "checking persistence locations"));
        println!(
            "{}",
            util::c(
                DIM,
                "  shell startup files, scheduled jobs, login agents - the places the\n  \
                 published cleanup guidance says to check by hand"
            )
        );
    }
    let hits = persist::check();
    // What `hunt` would remove outright: Run keys, tasks and Startup shims that
    // provably launch the campaign. --remove does it here.
    let removable = winpersist::sweep(!remove);
    let clickfix = winpersist::clickfix_history();
    if json {
        let review: Vec<String> = hits
            .iter()
            .map(|h| {
                format!(
                    "{{\"location\":\"{}\",\"line\":{},\"why\":\"{}\",\"text\":\"{}\"}}",
                    util::json_escape(&h.location),
                    h.line_no,
                    util::json_escape(h.why),
                    util::json_escape(&h.line)
                )
            })
            .collect();
        let auto: Vec<String> = removable
            .iter()
            .map(|a| {
                format!(
                    "{{\"kind\":\"{}\",\"name\":\"{}\",\"target\":\"{}\",\"removed\":{}}}",
                    util::json_escape(&a.kind),
                    util::json_escape(&a.name),
                    util::json_escape(&a.target),
                    a.removed
                )
            })
            .collect();
        let cf: Vec<String> = clickfix.iter().map(|c| format!("\"{}\"", util::json_escape(c))).collect();
        println!(
            "{{\"remove\":{remove},\"review\":[{}],\"removable\":[{}],\"clickfix\":[{}]}}",
            review.join(","),
            auto.join(","),
            cf.join(",")
        );
        return if hits.is_empty() && removable.iter().all(|a| a.removed) && clickfix.is_empty() { 0 } else { 1 };
    }
    println!();
    for a in &removable {
        if remove {
            let verb = if a.removed { "removed  " } else { "FAILED   " };
            println!("{} {} {}", util::c(if a.removed { GREEN } else { RED }, verb), a.kind, util::c(BOLD, &a.name));
            println!("    {}", util::c(DIM, &a.target));
            continue;
        }
        println!("{} {} {}", util::c(RED, "REMOVABLE"), a.kind, util::c(BOLD, &a.name));
        println!("    {}", util::c(DIM, &a.target));
        println!("    {}", util::c(DIM, "`polinrider-hunter persistence --remove` or `hunt` removes this (original quarantined)"));
    }
    for c in &clickfix {
        println!("{} {}", util::c(YELLOW, "CLICKFIX "), util::c(BOLD, "Run dialog history"));
        println!("    {}", c);
        println!("    {}", util::c(DIM, "a fetch-and-execute command was pasted into Win+R - a fake CAPTCHA was likely followed"));
    }
    if hits.is_empty() && removable.is_empty() && clickfix.is_empty() {
        println!("{}", util::c(GREEN, "Nothing suspicious in any startup location."));
        return 0;
    }
    if hits.is_empty() {
        return 1;
    }
    for h in &hits {
        println!(
            "{} {}",
            util::c(YELLOW, "REVIEW  "),
            util::c(BOLD, &format!("{}:{}", h.location, h.line_no))
        );
        println!("    {}", util::c(DIM, h.why));
        println!("    {}", h.line);
    }
    println!();
    println!(
        "{}",
        util::c(
            YELLOW,
            &format!(
                "{} line(s) to look at. Nothing was changed: these files are hand-maintained,\n\
                 and editing someone's shell profile unasked breaks machines in ways that are\n\
                 hard to trace back. Delete what you do not recognise.",
                hits.len()
            )
        )
    );
    1
}

fn cmd_procs(args: &Args, json: bool) -> i32 {
    let suspects = procscan::find();
    if json {
        let kill = args.has("--kill");
        let items: Vec<String> = suspects
            .iter()
            .map(|s| {
                let killed = if kill { Some(procscan::kill(s.pid)) } else { None };
                format!(
                    "{{\"pid\":{},\"marker\":\"{}\",\"cmdline\":\"{}\",\"killed\":{}}}",
                    s.pid,
                    util::json_escape(&s.marker),
                    util::json_escape(&s.cmdline),
                    match killed { Some(b) => b.to_string(), None => "null".into() }
                )
            })
            .collect();
        println!("{{\"kill\":{kill},\"processes\":[{}]}}", items.join(","));
        return if suspects.is_empty() { 0 } else { 1 };
    }
    if suspects.is_empty() {
        println!("{}", util::c(GREEN, "No hidden loader processes running."));
        return 0;
    }
    for s in &suspects {
        println!(
            "{} pid {} {}",
            util::c(RED, "LOADER"),
            s.pid,
            util::c(DIM, &s.marker)
        );
        println!("    {}", util::c(DIM, &s.cmdline));
        if args.has("--kill") {
            let ok = procscan::kill(s.pid);
            println!(
                "    {}",
                if ok {
                    util::c(GREEN, "terminated")
                } else {
                    util::c(RED, "could not terminate")
                }
            );
        }
    }
    if !args.has("--kill") {
        println!("\nre-run with --kill to stop them");
    }
    1
}

fn cmd_install(args: &Args, mut cfg: Config) -> i32 {
    let exe = config::exe_path();

    // Paths: whatever was given, else keep what is configured, else discover.
    let given: Vec<PathBuf> = args.positional.iter().map(PathBuf::from).collect();
    if !given.is_empty() {
        for p in given {
            let abs = config::normalize(&p);
            if !cfg.paths.contains(&abs) {
                cfg.paths.push(abs);
            }
        }
    } else if cfg.paths.is_empty() {
        cfg.paths = config::discover_repos();
        println!(
            "{} {} git repo(s) discovered under your home directory",
            util::c(DIM, "auto-detected:"),
            cfg.paths.len()
        );
    }
    if let Some(i) = args.interval {
        cfg.interval = i;
    }
    if cfg.paths.is_empty() {
        eprintln!("Nothing to watch. Pass one or more directories to install.");
        return 2;
    }
    if let Err(e) = cfg.save() {
        eprintln!("could not write config: {e}");
        return 1;
    }
    println!(
        "{} {}",
        util::c(GREEN, "config written"),
        config::config_path().display()
    );
    for p in &cfg.paths {
        println!("    watching {}", p.display());
    }

    // Pre-commit protection for every watched repo.
    let mut hooks = 0;
    for p in &cfg.paths {
        if let Some(root) = gitscan::repo_root(p) {
            if gitscan::install_hook(&root, &exe).is_ok() {
                hooks += 1;
            }
        }
    }
    println!(
        "{} {hooks} repo(s)",
        util::c(GREEN, "pre-commit hook installed in")
    );

    // Immediate sweep, so `install` actually cleans rather than only promising to.
    //
    // The git-ref audit is deliberately skipped here: it fetches every remote,
    // which across a handful of repos takes minutes and makes a run-once-and-
    // forget command look hung. The file sweep is what matters now, and the
    // guard performs the ref audit on its own schedule shortly after.
    println!("\n{}", util::c(BOLD, "initial sweep"));
    let sweep = Config {
        paths: cfg.paths.clone(),
        git_interval: 0,
        ..Config::default()
    };
    let code = daemon::run(&sweep, true);
    if cfg.git_interval > 0 {
        println!(
            "{}",
            util::c(
                DIM,
                "branch audit left to the guard; `polinrider-hunter repos` runs it now"
            )
        );
    }

    if !args.has("--no-autostart") {
        match service::install_autostart(&exe) {
            Ok(p) => println!(
                "\n{} {}",
                util::c(GREEN, "starts at login via"),
                p.display()
            ),
            Err(e) => eprintln!("could not register autostart: {e}"),
        }
    }

    // Registering a login entry and having a guard running right now are two
    // separate things, and were once one flag. Somebody who does not want the
    // tool starting itself at login still wants it watching this session.
    if !args.has("--no-guard") {
        // Hand over from any guard already running. Without this an upgrade
        // silently keeps the old build alive: the new process finds the lock
        // held, exits, and `install` reports success.
        match service::stop_daemon() {
            service::Stopped::Stopped(old) => {
                println!("{} pid {old}", util::c(DIM, "stopped the previous guard,"))
            }
            service::Stopped::Denied(old) => println!(
                "{} pid {old} {}",
                util::c(YELLOW, "could not stop the previous guard,"),
                util::c(DIM, "- it keeps running the older build")
            ),
            service::Stopped::None => {}
        }
        let _ = service::stop_stragglers();

        match service::spawn_daemon(&exe) {
            Ok(pid) => {
                // Confirm it stayed up rather than trusting spawn(). Report the
                // pid that actually holds the heartbeat, not the one we spawned:
                // if another guard was already running, ours exits immediately
                // and printing its pid would name a dead process.
                // Report the pid that holds the heartbeat, which is the guard
                // that is actually watching. It is usually the one just spawned;
                // when a hand-over raced it may not be, and the distinction was
                // never worth the confusing second message it used to print.
                if service::wait_for_daemon(cfg.interval, 10) {
                    let live = service::daemon_pid().unwrap_or(pid);
                    println!(
                        "{} pid {live}",
                        util::c(GREEN, "guard running in background,")
                    );
                } else {
                    println!(
                        "{}",
                        util::c(
                            YELLOW,
                            "guard did not report in; start it with `polinrider-hunter daemon`                              and check the log"
                        )
                    );
                }
            }
            Err(e) => eprintln!("could not start the guard: {e}"),
        }
    } else {
        println!(
            "\n{}",
            util::c(
                DIM,
                "guard not started (--no-guard); start it with `polinrider-hunter install`"
            )
        );
    }
    println!(
        "\n{}",
        util::c(DIM, "check on it any time with: polinrider-hunter status")
    );
    code
}

/// Send a notification, so you can see whether they reach you on this machine.
fn cmd_test_notify() -> i32 {
    println!("{}", util::c(DIM, "sending a test notification..."));
    notify::send(
        notify::Level::Removed,
        "This is a test. If you can read this, polinrider-hunter can reach you when it finds something.",
    );
    println!(
        "  {}",
        util::c(
            DIM,
            "sent. Nothing on screen? Check your notification settings, or set\n  \
             `notify = false` in the config - the log records every detection regardless."
        )
    );
    0
}

/// Stop the background guard, leaving everything else in place.
///
/// Needed on its own account - "pause it while I work" is a reasonable thing to
/// want - but mostly it exists so an upgrade can free the executable before
/// overwriting it. Windows refuses to replace a running image, and the
/// installer failing halfway with a file-locking error is the worst outcome:
/// the old guard keeps running and you think you upgraded.
fn cmd_stop() -> i32 {
    let mut denied: Vec<u32> = Vec::new();
    let mut stopped = 0usize;

    match service::stop_daemon() {
        service::Stopped::Stopped(pid) => {
            println!("{} pid {pid}", util::c(GREEN, "guard stopped,"));
            stopped += 1;
        }
        service::Stopped::Denied(pid) => denied.push(pid),
        service::Stopped::None => {}
    }

    // There may still be an older build running that never wrote a heartbeat,
    // or one orphaned by a purge, so sweep by name as well.
    let (extra, more_denied) = service::stop_stragglers();
    stopped += extra;
    denied.extend(more_denied);
    denied.sort_unstable();
    denied.dedup();
    if extra > 0 {
        println!("{} {extra} other guard process(es)", util::c(GREEN, "stopped"));
    }

    if !denied.is_empty() {
        let list = denied
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "{} {list}",
            util::c(YELLOW, "could not stop pid(s)")
        );
        eprintln!(
            "{}",
            util::c(
                DIM,
                "The operating system refused. That happens when the process belongs to another\n\
                 session, or was started with higher privileges. End it from Task Manager\n\
                 (or with `sudo kill`), then run this again."
            )
        );
        return 1;
    }
    if stopped == 0 {
        println!("{}", util::c(DIM, "no guard was running"));
    }
    0
}

fn cmd_uninstall(args: &Args) -> i32 {
    let purge = args.has("--purge") || args.has("--all");
    let mut removed: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();

    // Stop the guard first, before removing anything it might rewrite.
    match service::stop_daemon() {
        service::Stopped::Stopped(pid) => removed.push(format!("stopped the guard (pid {pid})")),
        service::Stopped::Denied(pid) => kept.push(format!(
            "could not stop the guard (pid {pid}) - end it from Task Manager or with sudo"
        )),
        service::Stopped::None => kept.push("guard was not running".into()),
    }
    // Older builds, or ones orphaned by a previous purge, hold no heartbeat but
    // are still running. Leaving them behind is how "uninstalled" software keeps
    // showing up in Task Manager.
    let (orphans, denied) = service::stop_stragglers();
    if orphans > 0 {
        removed.push(format!("stopped {orphans} orphaned guard process(es)"));
    }
    for pid in denied {
        kept.push(format!("guard process {pid} refused to stop"));
    }

    match service::uninstall_autostart() {
        Ok(true) => removed.push(format!(
            "autostart entry ({})",
            service::autostart_path().display()
        )),
        Ok(false) => kept.push("autostart was not installed".into()),
        Err(e) => kept.push(format!("could not remove autostart: {e}")),
    }

    let cfg = Config::load();
    let mut hooks = 0;
    for p in &cfg.paths {
        if let Some(root) = gitscan::repo_root(p) {
            if gitscan::uninstall_hook(&root).unwrap_or(false) {
                hooks += 1;
            }
        }
    }
    if hooks > 0 {
        removed.push(format!("pre-commit hook from {hooks} repo(s)"));
    } else {
        kept.push("no pre-commit hooks to remove".into());
    }

    if !purge {
        report_uninstall(&removed, &kept);
        println!(
            "\n{}",
            util::c(
                DIM,
                &format!(
                    "The binary, and the config/log/quarantine in {}, are still here.\n\
                     Remove everything with: polinrider-hunter uninstall --purge",
                    config::home().display()
                )
            )
        );
        return 0;
    }

    // ---- --purge: leave nothing behind ------------------------------------
    let home = config::home();
    let exe = config::exe_path();

    // The quarantine holds the only copies of what was cut out of your files.
    // Destroying that silently would be the wrong kind of thorough.
    let quarantined = std::fs::read_dir(config::quarantine_dir())
        .map(|d| d.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0);
    if quarantined > 0 {
        println!(
            "{}",
            util::c(
                YELLOW,
                &format!(
                    "  note: deleting {quarantined} quarantined original(s) - the only copies of\n  \
                     what was removed from your files"
                )
            )
        );
    }

    match std::fs::remove_dir_all(&home) {
        Ok(()) => removed.push(format!("state directory ({})", home.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            kept.push("no state directory".into())
        }
        Err(e) => kept.push(format!("could not remove {}: {e}", home.display())),
    }

    if let Some(dir) = exe.parent() {
        if service::remove_from_path(dir) {
            removed.push("PATH entry".into());
        } else if cfg!(windows) {
            kept.push("PATH entry was not present".into());
        } else {
            kept.push(format!(
                "PATH: remove `export PATH=\"$PATH:{}\"` from your shell profile by hand",
                dir.display()
            ));
        }
    }

    report_uninstall(&removed, &kept);

    if service::remove_self(&exe) {
        println!(
            "\n{} {}",
            util::c(GREEN, "gone."),
            util::c(
                DIM,
                &format!("({} removes itself in a moment)", exe.display())
            )
        );
    } else {
        println!(
            "\n{}",
            util::c(
                YELLOW,
                &format!("delete the binary yourself: {}", exe.display())
            )
        );
    }
    0
}

fn report_uninstall(removed: &[String], kept: &[String]) {
    if !removed.is_empty() {
        println!("{}", util::c(BOLD, "removed"));
        for r in removed {
            println!("  {} {r}", util::c(GREEN, "-"));
        }
    }
    if !kept.is_empty() {
        println!("{}", util::c(DIM, "nothing to do"));
        for k in kept {
            println!("  {}", util::c(DIM, &format!("- {k}")));
        }
    }
}
fn cmd_status(cfg: &Config, json: bool) -> i32 {
    if json {
        let heartbeat = service::daemon_alive(cfg.interval);
        let paths: Vec<String> = cfg.paths.iter().map(|p| format!("\"{}\"", util::json_escape(&p.to_string_lossy()))).collect();
        let j = |p: &std::path::Path| util::json_escape(&p.to_string_lossy());
        println!(
            "{{\"version\":\"{VERSION}\",\"home\":\"{}\",\"config\":\"{}\",\"log\":\"{}\",\"quarantine\":\"{}\",\
             \"autostart\":{{\"installed\":{},\"path\":\"{}\"}},\"guard\":{{\"running\":{},\"heartbeat_age_secs\":{}}},\
             \"interval\":{},\"full_interval\":{},\"git_interval\":{},\"auto_heal\":{},\"kill_procs\":{},\"paths\":[{}]}}",
            j(&config::home()),
            j(&config::config_path()),
            j(&config::log_path()),
            j(&config::quarantine_dir()),
            service::is_installed(),
            j(&service::autostart_path()),
            heartbeat.is_some(),
            heartbeat.map(|a| a.to_string()).unwrap_or_else(|| "null".into()),
            cfg.interval,
            cfg.full_interval,
            cfg.git_interval,
            cfg.auto_heal,
            cfg.kill_procs,
            paths.join(",")
        );
        return 0;
    }
    println!("{}", util::c(BOLD, &format!("polinrider-hunter {VERSION}")));
    println!("  home         {}", config::home().display());
    println!("  config       {}", config::config_path().display());
    println!("  log          {}", config::log_path().display());
    println!("  quarantine   {}", config::quarantine_dir().display());
    println!(
        "  autostart    {} ({})",
        if service::is_installed() {
            util::c(GREEN, "installed")
        } else {
            util::c(YELLOW, "not installed")
        },
        service::autostart_path().display()
    );
    match service::daemon_alive(cfg.interval) {
        Some(age) => println!(
            "  guard        {} (heartbeat {age}s ago)",
            util::c(GREEN, "running")
        ),
        None => println!("  guard        {}", util::c(YELLOW, "not running")),
    }
    println!(
        "  cadence      quick {}s / full {}s / git {}s",
        cfg.interval, cfg.full_interval, cfg.git_interval
    );
    println!(
        "  auto-heal    {}   stop processes {}",
        cfg.auto_heal, cfg.kill_procs
    );
    println!("  watching     {} path(s)", cfg.paths.len());
    for p in &cfg.paths {
        println!("      {}", p.display());
    }
    if let Ok(text) = std::fs::read_to_string(config::log_path()) {
        let tail: Vec<&str> = text.lines().rev().take(8).collect();
        if !tail.is_empty() {
            println!("\n{}", util::c(BOLD, "recent activity"));
            for l in tail.into_iter().rev() {
                println!("  {l}");
            }
        }
    }
    0
}

fn cmd_quarantine(json: bool) -> i32 {
    let idx = config::quarantine_index();
    if json {
        // The index is already one JSON object per line.
        let text = std::fs::read_to_string(&idx).unwrap_or_default();
        let entries: Vec<&str> = text.lines().map(str::trim).filter(|l| l.starts_with('{')).collect();
        println!(
            "{{\"dir\":\"{}\",\"quarantine\":[{}]}}",
            util::json_escape(&config::quarantine_dir().to_string_lossy()),
            entries.join(",")
        );
        return 0;
    }
    match std::fs::read_to_string(&idx) {
        Ok(t) if !t.trim().is_empty() => {
            println!("{}", util::c(BOLD, "quarantined originals"));
            for l in t.lines() {
                println!("  {l}");
            }
        }
        _ => println!("{}", util::c(DIM, "quarantine is empty")),
    }
    0
}

/// Invoked by the git pre-commit hook. Git runs hooks from the repo root.
fn cmd_hook() -> i32 {
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let findings = scanner::scan_paths(&[root.clone()], true);
    let critical: Vec<_> = findings.iter().filter(|f| f.is_critical()).collect();
    if critical.is_empty() {
        return 0;
    }
    let mut blocked = false;
    for f in critical {
        let outcome = healer::heal(f, false);
        match outcome {
            healer::Outcome::Healed { removed } => {
                println!(
                    "{} removed from {} (-{removed} bytes) - re-staged",
                    util::c(RED, "PolinRider"),
                    f.path.display()
                );
                gitscan::stage(&root, &f.path);
            }
            healer::Outcome::Deleted => {
                println!(
                    "{} dropper {} deleted and untracked",
                    util::c(RED, "PolinRider"),
                    f.path.display()
                );
            }
            other => {
                eprintln!(
                    "{}",
                    util::c(
                        RED,
                        &format!(
                            "PolinRider present in {} and not auto-cleanable: {}",
                            f.path.display(),
                            other.label()
                        )
                    )
                );
                blocked = true;
            }
        }
    }
    if blocked {
        eprintln!("commit blocked - clean the file listed above, then commit again");
        return 1;
    }
    0
}

fn usage() {
    // The help screen is one pre-formatted block, so it needs the codes as
    // values rather than wrapping each span; blank them out when colour is off.
    let (b, r) = if util::colour_enabled() {
        (BOLD, RESET)
    } else {
        ("", "")
    };
    println!(
        r#"{b}polinrider-hunter {VERSION}{r}
Detects and removes the PolinRider supply-chain malware.

{b}USAGE{r}
  polinrider-hunter <command> [paths...] [flags]

{b}GETTING STARTED{r}
  hunt                   Sweep this whole machine: stop any running loader, find
                         every infected file under your home directory and clean
                         it. Needs no setup. --drives covers every drive.
  install [paths...]     Watch these directories, protect their repos with a
                         pre-commit hook, sweep them now, and start a background
                         guard that keeps doing it at every login. Run once.
  status                 Where everything lives and whether the guard is alive.
  log                    What the guard has been doing. --follow to watch live,
                         --all for the whole history.
  monitor                Live dashboard in the terminal. --web serves it in a
                         browser on localhost, --once for a single snapshot.
  stop                   Stop the background guard, leaving everything else
                         in place. Start it again with `install`.
  uninstall              Stop the guard and remove the hooks. --purge also
                         deletes the state directory, PATH entry and binary.
  test-notify            Send a notification, to check they reach you.

{b}AI AGENT{r}
  agent [paths...]       Chat with an AI agent that does real work in your terminal:
                         malware investigation and cleanup, repairing poisoned
                         branches, reading/writing/editing files, glob/grep search,
                         running builds, tests, git and any other command, web
                         search, hash lookups. Type what you want; /help lists
                         commands (/provider, /model, /mode, /plan, /status...).
                         --task "…" runs one job and exits; --investigate starts
                         the full malware investigation; --mode sets permissions.
  ai [status]            Show AI providers, which keys are set and which is active.
  ai setup               Guided setup: pick a provider, paste a key, test it.
  ai key <provider> <K>  Save a key: anthropic, openai, gemini, openrouter, groq,
                         deepseek, ollama (no key), custom (any OpenAI-compatible).
  ai use <provider> [m]  Make a provider (and model) the default. --base-url <url>
                         for custom endpoints, proxies, LM Studio.
  ai mode <mode>         Default permission mode: read-only | ask (default) |
                         workspace-write | full-access.
  ai test                Send one message to check the key and model work.
  ai remove <provider>   Forget a stored key.
  ai "<task>"            Shorthand: start the agent on a task and stay in the chat.
  report [paths...]      Write an incident report to the state dir: AI-written root
                         cause with a key, or a factual status report without one.
  set-key <KEY>          Store a Gemini API key (free at aistudio.google.com/apikey).
                         --model <id> picks a model (e.g. a cyber-tuned one you have
                         access to); --vt-key <KEY> enables VirusTotal lookups.

{b}ON DEMAND{r}
  scan [paths...]        Report indicators; change nothing. Exit 1 if infected.
  clean [paths...]       Scan, then remove payloads. Originals are quarantined.
  repos [paths|urls...]  Fetch and audit every branch of each repo, local and
                         remote-tracking, without pulling or checking out; also
                         audits each repo's git config and hooks. A URL
                         (https://, git@, ssh://) is fetched into a temporary
                         bare mirror - nothing is ever checked out - audited,
                         and the mirror deleted. For every infected remote
                         branch it says whether you can push, who owns the
                         repository and who pushed the infection. --repair adds
                         one clean commit on top of each poisoned remote branch
                         (no force push; works from a URL too); --fix pushes
                         your clean local branch over a poisoned remote branch;
                         --excise removes the poisoned commit itself from each
                         remote branch (no local copy needed; cleanup commits
                         are folded away; original message/author/date kept);
                         --history also audits old commits, not just the tips;
                         --access only reports push access per remote.
  mcp                    Serve the Model Context Protocol on stdin/stdout, so
                         Claude Code, Cursor, Codex, Windsurf or any MCP client
                         can drive this tool (no API key needed here). Tools:
                         scan, clean, hunt, repos_audit, repos_repair,
                         repos_history, processes, persistence, quarantine_list,
                         status, access_check. Anything that changes something
                         is a dry run until the call carries confirm:true.
  procs                  List hidden stage-2 processes. --kill stops them.
  persistence            Check shell profiles, cron and login agents for a
                         way back in. Reports only; --remove deletes the Run
                         keys, tasks and Startup shims that provably launch
                         the campaign (hand-maintained files are never edited).
  protect [repos...]     Install just the pre-commit hook.
  unprotect [repos...]   Remove it.
  quarantine             List originals kept aside during healing.

{b}FLAGS{r}
  --json                 Machine-readable output (scan, clean, hunt, repos,
                         procs, persistence, quarantine, status).
  --dry-run              clean/hunt/repos: report what would change, write nothing.
  --url <url>            repos: audit a repository by URL (bare mirror, nothing
                         checked out). Bare URLs are recognised without it.
  --repair               repos: one clean forward commit per infected remote
                         branch, pushed fast-forward; branches you cannot push
                         to are reported BLOCKED with who can fix them.
  --skip-remotes <a,b>   repos --repair: remotes never to push to.
  --access               repos: report push access per remote, nothing else.
  --remove               persistence: remove provably malicious autostart entries.
  --quick                scan: only the filenames PolinRider targets.
  --no-fetch             repos: audit refs as they are, do not contact remotes.
  --history              repos: also walk every blob reachable from any ref, not
                         just the tips - finds payloads left in old commits after
                         a branch was cleaned. Prints the `git filter-repo`
                         command that purges them.
  --fix                  repos: repair infected remote branches (force-with-lease
                         push of the clean local branch; --dry-run to preview).
  --kill                 procs: stop what is found.
  --drives               hunt: search every drive, not just your home directory.
  --interval <secs>      install: seconds between quick passes (default 30).
                         monitor: seconds between redraws (default 3).
  --port <n>             monitor --web: port to listen on (default 8787).
  --no-autostart         install: do not register a login entry.
  --no-guard             install: set everything up but do not start the guard.
  --yes                  agent: approve mutating tool calls without asking
                         (same as --mode full-access).
  --mode <m>             agent: read-only | ask | workspace-write | full-access.
  --provider <id>        agent/report/ai test: AI provider for this run.
  --base-url <url>       agent/ai use: endpoint for OpenAI-compatible providers.
  --investigate          agent: start with the full malware investigation.
  --task <text>          agent: run one task non-interactively, then exit.
  --model <id>           agent/report/ai: model for the active provider.
  --key <KEY>            agent/report: API key for this run only.
  --max-steps <n>        agent: cap on model turns (default 400 interactive, 60 task).
  --verbose              agent: show every tool result.
  --plain                report: skip the AI even if a key is configured.
  --no-color             Plain output.

{b}NOTES{r}
  Healing never rewrites line endings, so a fix stays a one-line diff.
  The guard heals working trees only. It never rewrites git history and never
  pushes on its own; `repos` reports what is on a branch, and only `repos --fix`,
  run by you, pushes - and only when every extra remote commit is the infection.
  Also covered: Shai-Hulud npm worm, GlassWorm invisible-Unicode payloads, npm
  install-script droppers, Contagious-Interview keylogger kits, injected git
  config (core.fsmonitor, hooks, nested repos), ClickFix run history.
"#
    );
}
