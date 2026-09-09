//! polinrider-hunter — detect and remove the PolinRider supply-chain malware.
//!
//! One binary, no runtime, no dependencies. `install` is the only command most
//! people need; everything else exists so you can see what it is doing and
//! check its work by hand.

mod config;
mod daemon;
mod gitscan;
mod healer;
mod procscan;
mod report;
mod scanner;
mod service;
mod signatures;
mod util;

use std::path::PathBuf;

use config::Config;
use util::{BOLD, DIM, GREEN, RED, RESET, YELLOW};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Args {
    cmd: String,
    positional: Vec<String>,
    flags: Vec<String>,
    interval: Option<u64>,
}

fn parse_args() -> Args {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| "help".into());
    let mut positional = Vec::new();
    let mut flags = Vec::new();
    let mut interval = None;
    while let Some(a) = it.next() {
        if a == "--interval" {
            interval = it.next().and_then(|v| v.parse().ok());
        } else if let Some(v) = a.strip_prefix("--interval=") {
            interval = v.parse().ok();
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
        "scan" => cmd_scan(&args, &cfg, json),
        "clean" => cmd_clean(&args, &cfg, json),
        "repos" => cmd_repos(&args, &cfg, json),
        "protect" => cmd_protect(&args, &cfg),
        "unprotect" => cmd_unprotect(&args, &cfg),
        "procs" => cmd_procs(&args),
        "daemon" => daemon::run(&cfg, args.has("--once")),
        "install" => cmd_install(&args, cfg),
        "uninstall" => cmd_uninstall(),
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
    println!("\n{}", util::c(BOLD, "initial sweep"));
    let code = daemon::run(&cfg, true);

    if !args.has("--no-autostart") {
        match service::install_autostart(&exe) {
            Ok(p) => println!(
                "\n{} {}",
                util::c(GREEN, "starts at login via"),
                p.display()
            ),
            Err(e) => eprintln!("could not register autostart: {e}"),
        }
        match service::spawn_daemon(&exe) {
            Ok(pid) => println!(
                "{} pid {pid}",
                util::c(GREEN, "guard running in background,")
            ),
            Err(e) => eprintln!("could not start the guard: {e}"),
        }
    }
    println!(
        "\n{}",
        util::c(DIM, "check on it any time with: polinrider-hunter status")
    );
    code
}

fn cmd_uninstall() -> i32 {
    match service::uninstall_autostart() {
        Ok(true) => println!("{}", util::c(GREEN, "autostart removed")),
        Ok(false) => println!("{}", util::c(DIM, "autostart was not installed")),
        Err(e) => eprintln!("could not remove autostart: {e}"),
    }
    let cfg = Config::load();
    for p in &cfg.paths {
        if let Some(root) = gitscan::repo_root(p) {
            let _ = gitscan::uninstall_hook(&root);
        }
    }
    println!(
        "{}",
        util::c(
            DIM,
            &format!(
                "config, log and quarantine kept in {} - delete it by hand if you want them gone",
                config::home().display()
            )
        )
    );
    0
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
                    "{RED}PolinRider{RESET} removed from {} (-{removed} bytes) - re-staged",
                    f.path.display()
                );
                gitscan::stage(&root, &f.path);
            }
            healer::Outcome::Deleted => {
                println!(
                    "{RED}PolinRider{RESET} dropper {} deleted and untracked",
                    f.path.display()
                );
            }
            other => {
                eprintln!(
                    "{RED}PolinRider present in {} and not auto-cleanable: {}{RESET}",
                    f.path.display(),
                    other.label()
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
    println!(
        r#"{BOLD}polinrider-hunter {VERSION}{RESET}
Detects and removes the PolinRider supply-chain malware.

{BOLD}USAGE{RESET}
  polinrider-hunter <command> [paths...] [flags]

{BOLD}GETTING STARTED{RESET}
  install [paths...]     Watch these directories, protect their repos with a
                         pre-commit hook, sweep them now, and start a background
                         guard that keeps doing it at every login. Run once.
  status                 Where everything lives and whether the guard is alive.
  uninstall              Stop the guard and remove the hooks.

{BOLD}ON DEMAND{RESET}
  scan [paths...]        Report indicators; change nothing. Exit 1 if infected.
  clean [paths...]       Scan, then remove payloads. Originals are quarantined.
  repos [paths...]       Fetch and audit every branch of each repo, local and
                         remote-tracking, without pulling or checking out.
  procs                  List hidden stage-2 processes. --kill stops them.
  protect [repos...]     Install just the pre-commit hook.
  unprotect [repos...]   Remove it.
  quarantine             List originals kept aside during healing.

{BOLD}FLAGS{RESET}
  --json                 Machine-readable output (scan, clean, repos).
  --dry-run              clean: report what would change, write nothing.
  --quick                scan: only the filenames PolinRider targets.
  --no-fetch             repos: audit refs as they are, do not contact remotes.
  --kill                 procs: stop what is found.
  --interval <secs>      install: seconds between quick passes (default 30).
  --no-autostart         install: set up, but do not start at login.
  --no-color             Plain output.

{BOLD}NOTES{RESET}
  Healing never rewrites line endings, so a fix stays a one-line diff.
  The guard heals working trees only. It never rewrites git history and never
  pushes; `repos` reports what is on a branch and leaves the decision to you.
"#
    );
}
