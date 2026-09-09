//! The background loop.
//!
//! Three cadences, because the cheap check is the one worth running often:
//!
//! * **quick** (default 30s) — `stat` a precomputed list of concrete target
//!   paths, and read one only when its mtime has moved. No directory walking at
//!   all: an earlier version re-walked every watched repository twice a minute,
//!   which is thousands of directory reads for nothing and the reason this felt
//!   heavy. Catches a fresh infection within half a minute at near-zero cost.
//! * **full** (default 15m) — walk the watched trees properly, in case a
//!   variant picks a filename we have not seen before.
//! * **git** (default 1h) — fetch and audit every ref, reporting anything that
//!   arrived on a branch upstream.
//!
//! The daemon heals working trees. It never rewrites history and never pushes:
//! an automated process that force-pushes to shared branches is a worse problem
//! than the one it is solving.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::healer;
use crate::gitscan;
use crate::notify;
use crate::procscan;
use crate::scanner;
use crate::service;
use crate::util;
use crate::{config, report};

/// "1 file" / "3 files" - a notification reading "Cleaned 1 files" looks broken.
fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("{n} {word}")
    } else {
        format!("{n} {word}s")
    }
}

fn mtime(p: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok()?.modified().ok()
}

/// Run the guard loop. `once` performs a single full cycle and returns, which
/// is what `install` uses for its initial sweep and what CI would call.
pub fn run(cfg: &Config, once: bool) -> i32 {
    let log = config::log_path();
    let echo = once;

    if cfg.paths.is_empty() {
        util::log_line(
            &log,
            "no paths configured; run `polinrider-hunter install <dir>...` first",
            true,
        );
        return 2;
    }

    if !once {
        if let Some(age) = service::daemon_alive(cfg.interval) {
            util::log_line(
                &log,
                &format!(
                    "another daemon is alive (heartbeat {age}s ago, pid {:?}); pid {} exiting",
                    service::daemon_pid(),
                    std::process::id()
                ),
                true,
            );
            return 0;
        }
        util::log_line(
            &log,
            &format!(
                "guard started: pid {}, {} path(s), quick={}s full={}s git={}s auto_heal={}",
                std::process::id(),
                cfg.paths.len(),
                cfg.interval,
                cfg.full_interval,
                cfg.git_interval,
                cfg.auto_heal
            ),
            false,
        );
    }

    // Claim the heartbeat now, before doing anything slow.
    //
    // It used to be written at the top of the loop, which is after the priority
    // shell-out below - leaving several seconds in which the guard was running
    // but nothing could tell. `install` waits for a heartbeat to confirm the
    // guard came up, so in that window it reported the wrong thing, and a second
    // `install` could spawn a rival daemon because the lock looked free.
    if !once {
        service::write_heartbeat();
    }

    // Lower our own priority: a guard must never compete with the work the
    // person is actually doing. One shell-out at startup, then never again.
    if !once {
        service::lower_priority();
    }

    let mut seen: HashMap<PathBuf, SystemTime> = HashMap::new();
    // Concrete paths the quick pass stats. Rebuilt on each full cycle.
    let mut watch: Vec<PathBuf> = Vec::new();
    let mut last_full = 0u64;
    let mut last_git = 0u64;
    let mut total_healed = 0usize;

    loop {
        // Only a resident guard publishes a heartbeat. A one-shot sweep - what
        // `install` runs before starting the guard, and what CI calls - is not
        // one, and writing it here meant `install` read its own sweep back as
        // "a guard is already running" and named its own pid. Worse, the guard
        // it had just spawned could see that fresh heartbeat, conclude another
        // instance owned the lock, and quietly exit.
        if !once {
            service::write_heartbeat();
        }
        let now = util::now_secs();

        // ---- quick pass over known targets -----------------------------------
        let due_full = once || now.saturating_sub(last_full) >= cfg.full_interval;
        let findings = if due_full {
            last_full = now;
            // Refresh the watch list: the fixed candidate paths plus whatever
            // the walk turns up somewhere unexpected.
            watch.clear();
            for r in &cfg.paths {
                watch.extend(scanner::direct_target_paths(r));
                watch.extend(scanner::find_target_files(r));
            }
            watch.sort();
            watch.dedup();
            // Drop mtimes for paths no longer watched, so `seen` cannot grow
            // without bound over a long-running process.
            seen.retain(|p, _| watch.binary_search(p).is_ok());
            // Record current mtimes now. The full scan below has already read
            // these files, so without this the very next quick pass would
            // consider every one of them "changed" and read them all again.
            for p in &watch {
                if let Some(m) = mtime(p) {
                    seen.insert(p.clone(), m);
                }
            }
            scanner::scan_paths(&cfg.paths, false)
        } else {
            // Pure stat pass: read a file only when it has actually changed.
            let mut out = Vec::new();
            for p in &watch {
                let Some(m) = mtime(p) else {
                    seen.remove(p);
                    continue;
                };
                let changed = seen.get(p).map(|prev| m > *prev).unwrap_or(true);
                if changed {
                    seen.insert(p.clone(), m);
                    if let Some(f) = scanner::scan_file(p) {
                        out.push(f);
                    }
                }
            }
            out
        };

        // Collected so the person gets one notification per cycle rather than
        // one per file: five infected configs in a monorepo is one event to a
        // human, not five.
        let mut cleaned: Vec<String> = Vec::new();
        let mut needs_you: Vec<String> = Vec::new();

        for f in &findings {
            let iocs: Vec<&str> = f.hits.iter().map(|h| h.ioc).collect();
            if f.is_critical() && cfg.auto_heal {
                let outcome = healer::heal(f, false);
                let name = f
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| f.path.display().to_string());
                match &outcome {
                    healer::Outcome::Healed { .. } | healer::Outcome::Deleted => cleaned.push(name),
                    healer::Outcome::Failed(_) => needs_you.push(name),
                    healer::Outcome::Skipped(_) => {}
                }
                if matches!(outcome, healer::Outcome::Healed { .. } | healer::Outcome::Deleted) {
                    total_healed += 1;
                    // Re-stage in git so the clean version is what gets committed.
                    if let Some(root) = gitscan::repo_root(f.path.parent().unwrap_or(&f.path)) {
                        gitscan::stage(&root, &f.path);
                    }
                }
                util::log_line(
                    &log,
                    &format!(
                        "DETECT {} [{}] -> {}",
                        f.path.display(),
                        iocs.join(","),
                        outcome.label()
                    ),
                    echo,
                );
                // Force a re-read next cycle.
                seen.remove(&f.path);
            } else {
                util::log_line(
                    &log,
                    &format!("NOTICE {} [{}]", f.path.display(), iocs.join(",")),
                    echo,
                );
            }
        }

        if cfg.notify && !cleaned.is_empty() {
            notify::send(
                notify::Level::Removed,
                &format!("Cleaned {}: {}", plural(cleaned.len(), "file"), cleaned.join(", ")),
            );
        }
        if cfg.notify && !needs_you.is_empty() {
            notify::send(
                notify::Level::NeedsYou,
                &format!(
                    "Could not clean {} automatically: {}. Run `polinrider-hunter scan` for detail.",
                    plural(needs_you.len(), "file"),
                    needs_you.join(", ")
                ),
            );
        }

        // ---- running stage-2 processes ---------------------------------------
        //
        // Only on the full cycle, not every quick pass. Enumerating command
        // lines means spawning a shell, and doing that every 30 seconds is a
        // lot of work for something that changes rarely - the payload has to
        // survive a build to exist at all.
        for s in if due_full { procscan::find() } else { Vec::new() } {
            if cfg.kill_procs {
                let killed = procscan::kill(s.pid);
                if killed && cfg.notify {
                    notify::send(
                        notify::Level::Removed,
                        &format!(
                            "Stopped a hidden PolinRider process (pid {}). It was already running \
                             and would not have been caught by cleaning files alone.",
                            s.pid
                        ),
                    );
                }
                util::log_line(
                    &log,
                    &format!(
                        "PROC pid={} marker={} -> {}",
                        s.pid,
                        s.marker,
                        if killed { "killed" } else { "kill failed" }
                    ),
                    echo,
                );
            } else {
                util::log_line(
                    &log,
                    &format!("PROC pid={} marker={} (kill disabled)", s.pid, s.marker),
                    echo,
                );
            }
        }

        // ---- git refs --------------------------------------------------------
        let due_git =
            cfg.git_interval > 0 && (once || now.saturating_sub(last_git) >= cfg.git_interval);
        if due_git {
            last_git = now;
            for p in &cfg.paths {
                if !gitscan::is_repo(p) {
                    continue;
                }
                for hit in gitscan::scan_repo(p, true) {
                    util::log_line(
                        &log,
                        &format!(
                            "REF {} {} :: {} [{}]",
                            hit.repo.display(),
                            hit.git_ref,
                            hit.file,
                            hit.iocs.join(",")
                        ),
                        echo,
                    );
                }
            }
        }

        if once {
            if echo {
                report::summary_line(findings.len(), total_healed);
            }
            return if findings.iter().any(|f| f.is_critical()) && !cfg.auto_heal {
                1
            } else {
                0
            };
        }
        std::thread::sleep(Duration::from_secs(cfg.interval.max(5)));
    }
}
