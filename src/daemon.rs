//! The background loop.
//!
//! Three cadences, because the cheap check is the one worth running often:
//!
//! * **quick** (default 30s) — stat and read only the ~30 filenames PolinRider
//!   actually writes to, and only when their mtime moved. This is what catches
//!   a fresh infection within half a minute of it landing, and it costs
//!   essentially nothing.
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
use crate::procscan;
use crate::scanner;
use crate::service;
use crate::util;
use crate::{config, report};

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
                &format!("another daemon is alive (heartbeat {age}s ago); exiting"),
                true,
            );
            return 0;
        }
        util::log_line(
            &log,
            &format!(
                "guard started: {} path(s), quick={}s full={}s git={}s auto_heal={}",
                cfg.paths.len(),
                cfg.interval,
                cfg.full_interval,
                cfg.git_interval,
                cfg.auto_heal
            ),
            false,
        );
    }

    let mut seen: HashMap<PathBuf, SystemTime> = HashMap::new();
    let mut last_full = 0u64;
    let mut last_git = 0u64;
    let mut total_healed = 0usize;

    loop {
        service::write_heartbeat();
        let now = util::now_secs();

        // ---- quick pass over known targets -----------------------------------
        let due_full = once || now.saturating_sub(last_full) >= cfg.full_interval;
        let findings = if due_full {
            last_full = now;
            scanner::scan_paths(&cfg.paths, false)
        } else {
            // Only look at targets whose mtime changed since we last saw them.
            let mut out = Vec::new();
            for f in scanner::scan_paths(&cfg.paths, true) {
                let m = mtime(&f.path);
                let changed = match (seen.get(&f.path), m) {
                    (Some(prev), Some(cur)) => cur > *prev,
                    _ => true,
                };
                if changed {
                    if let Some(cur) = m {
                        seen.insert(f.path.clone(), cur);
                    }
                    out.push(f);
                }
            }
            out
        };

        for f in &findings {
            let iocs: Vec<&str> = f.hits.iter().map(|h| h.ioc).collect();
            if f.is_critical() && cfg.auto_heal {
                let outcome = healer::heal(f, false);
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

        // ---- running stage-2 processes ---------------------------------------
        for s in procscan::find() {
            if cfg.kill_procs {
                let killed = procscan::kill(s.pid);
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
