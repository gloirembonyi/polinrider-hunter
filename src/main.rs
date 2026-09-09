//! polinrider-hunter — detect and remove the PolinRider supply-chain malware.
//!
//! One binary, no runtime, no dependencies. `install` is the only command most
//! people need; everything else exists so you can see what it is doing and
//! check its work by hand.

use std::path::PathBuf;

use polinrider_hunter::{
    config, daemon, gitscan, healer, monitor, notify, persist, procscan, report, scanner,
    service, util,
};

use config::Config;
use util::{BOLD, DIM, GREEN, RED, RESET, YELLOW};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Args {
    cmd: String,
    positional: Vec<String>,
    flags: Vec<String>,
    interval: Option<u64>,
    port: Option<u16>,
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| "help".into());
    let mut positional = Vec::new();
    let mut flags = Vec::new();
    let mut interval = None;
    let mut port = None;
    while let Some(a) = it.next() {
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
        "protect" => cmd_protect(&args, &cfg),
        "unprotect" => cmd_unprotect(&args, &cfg),
        "procs" => cmd_procs(&args),
        "persistence" => cmd_persistence(),
        "log" | "logs" => cmd_log(&args),
        "monitor" | "dashboard" => cmd_monitor(&args, &cfg),
        "daemon" => daemon::run(&cfg, args.has("--once")),
        "install" => cmd_install(&args, cfg),
        "stop" => cmd_stop(),
        "uninstall" => cmd_uninstall(&args),
        "test-notify" => cmd_test_notify(),
        "status" => cmd_status(&cfg),
        "quarantine" => cmd_quarantine(),
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
        println!("{}", util::c(BOLD, "PolinRider hunt"));
        for r in &roots {
            println!("  searching {}", r.display());
        }
        if !all_drives {
            println!(
                "{}",
                util::c(DIM, "  (add --drives to include every drive on the machine)")
            );
        }
        println!();
    }

    // 1. Anything running right now. Do this first: a live loader can re-drop a
    //    payload into a directory we have already passed.
    let mut killed = 0usize;
    for s in procscan::find() {
        if dry {
            println!("  {} pid {} ({})", util::c(YELLOW, "would stop"), s.pid, s.marker);
            continue;
        }
        if procscan::kill(s.pid) {
            killed += 1;
            println!(
                "  {} pid {} ({})",
                util::c(GREEN, "stopped loader"),
                s.pid,
                s.marker
            );
        } else {
            println!("  {} pid {}", util::c(RED, "could not stop"), s.pid);
        }
    }

    // 2. Persistence: a loader that arranged to come back matters as much as
    //    the files it left behind, and the check is nearly free.
    let persist_hits = persist::check();
    if !json {
        for h in &persist_hits {
            println!(
                "  {} {}:{}",
                util::c(YELLOW, "startup "),
                h.location,
                h.line_no
            );
            println!("      {}", util::c(DIM, h.why));
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
            if !json {
                println!(
                    "  {} {}",
                    util::c(YELLOW, "review  "),
                    f.path.display()
                );
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
        if !json {
            let iocs: Vec<&str> = f.hits.iter().map(|h| h.ioc).collect();
            println!(
                "  {} {}",
                util::c(GREEN, &outcome.label()),
                f.path.display()
            );
            println!("      {}", util::c(DIM, &iocs.join(", ")));
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
            println!("{}", util::c(DIM, &format!("  [{}]", root.display())));
        }
        for d in subdirs {
            if !json {
                println!("{}", util::c(DIM, &format!("    scanning {}", d.display())));
            }
            scanner::scan_tree_cb(&d, false, &mut handle);
        }
        scanner::scan_tree_cb(root, true, &mut handle);
    }
    drop(handle);

    if json {
        println!(
            "{{\"healed\":{healed},\"found\":{found},\"needs_review\":{noted},\"manual\":{}}}",
            manual.len()
        );
        return if manual.is_empty() { 0 } else { 1 };
    }

    println!();
    println!(
        "{} {} loader process(es) stopped, {} of {} finding(s) cleaned, {} need a look",
        util::c(BOLD, "hunt complete:"),
        killed,
        healed,
        found,
        manual.len() + noted + persist_hits.len()
    );
    if !persist_hits.is_empty() {
        println!(
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
        println!("\n{}", util::c(YELLOW, "clean these by hand:"));
        for m in &manual {
            println!("  {m}");
        }
    }
    if healed > 0 && !dry {
        println!(
            "{}",
            util::c(
                DIM,
                &format!("originals kept in {}", config::quarantine_dir().display())
            )
        );
        println!(
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

fn cmd_scan(args: &Args, cfg: &Config, json: bool) -> i32 {
    let paths = target_paths(args, cfg);
    if !require_paths(&paths) {
        return 2;
    }
    let findings = scanner::scan_paths(&paths, args.has("--quick"));
    report::print_findings(&findings, json);
    if findings.iter().any(|f| f.is_critical()) {
        1
    } else {
        0
    }
}

fn cmd_clean(args: &Args, cfg: &Config, json: bool) -> i32 {
    let paths = target_paths(args, cfg);
    if !require_paths(&paths) {
        return 2;
    }
    let dry = args.has("--dry-run");
    let findings = scanner::scan_paths(&paths, false);
    if findings.is_empty() {
        println!("{}", util::c(GREEN, "Nothing to clean."));
        return 0;
    }
    report::print_findings(&findings, json);
    println!();

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
        let colour = if ok { GREEN } else { YELLOW };
        println!(
            "  {} {}",
            util::c(colour, &outcome.label()),
            f.path.display()
        );
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

fn cmd_repos(args: &Args, cfg: &Config, json: bool) -> i32 {
    let paths = target_paths(args, cfg);
    if !require_paths(&paths) {
        return 2;
    }
    let do_fetch = !args.has("--no-fetch");
    let mut all = Vec::new();
    for p in &paths {
        if !gitscan::is_repo(p) {
            continue;
        }
        if !json {
            println!("{} {}", util::c(DIM, "auditing"), p.display());
        }
        all.extend(gitscan::scan_repo(p, do_fetch));
    }
    report::print_ref_hits(&all, json);
    if !json && !all.is_empty() {
        println!();
        println!(
            "{}",
            util::c(
                YELLOW,
                "These are branch contents, not your working tree. Cleaning them means\n\
                 committing a fix on each branch - deliberately not automated. See README."
            )
        );
    }
    if all.is_empty() {
        0
    } else {
        1
    }
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
/// anything?", and answering it should not mean hunting for a log file — or
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
fn cmd_persistence() -> i32 {
    println!("{}", util::c(BOLD, "checking persistence locations"));
    println!(
        "{}",
        util::c(
            DIM,
            "  shell startup files, scheduled jobs, login agents - the places the\n  \
             published cleanup guidance says to check by hand"
        )
    );
    let hits = persist::check();
    println!();
    if hits.is_empty() {
        println!("{}", util::c(GREEN, "Nothing suspicious in any startup location."));
        return 0;
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

fn cmd_procs(args: &Args) -> i32 {
    let suspects = procscan::find();
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
fn cmd_status(cfg: &Config) -> i32 {
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

fn cmd_quarantine() -> i32 {
    let idx = config::quarantine_index();
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

{b}ON DEMAND{r}
  scan [paths...]        Report indicators; change nothing. Exit 1 if infected.
  clean [paths...]       Scan, then remove payloads. Originals are quarantined.
  repos [paths...]       Fetch and audit every branch of each repo, local and
                         remote-tracking, without pulling or checking out.
  procs                  List hidden stage-2 processes. --kill stops them.
  persistence            Check shell profiles, cron and login agents for a
                         way back in. Reports only; never edits them.
  protect [repos...]     Install just the pre-commit hook.
  unprotect [repos...]   Remove it.
  quarantine             List originals kept aside during healing.

{b}FLAGS{r}
  --json                 Machine-readable output (scan, clean, repos).
  --dry-run              clean: report what would change, write nothing.
  --quick                scan: only the filenames PolinRider targets.
  --no-fetch             repos: audit refs as they are, do not contact remotes.
  --kill                 procs: stop what is found.
  --drives               hunt: search every drive, not just your home directory.
  --interval <secs>      install: seconds between quick passes (default 30).
                         monitor: seconds between redraws (default 3).
  --port <n>             monitor --web: port to listen on (default 8787).
  --no-autostart         install: do not register a login entry.
  --no-guard             install: set everything up but do not start the guard.
  --no-color             Plain output.

{b}NOTES{r}
  Healing never rewrites line endings, so a fix stays a one-line diff.
  The guard heals working trees only. It never rewrites git history and never
  pushes; `repos` reports what is on a branch and leaves the decision to you.
"#
    );
}
