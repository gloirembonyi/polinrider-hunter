//! Where the hunter keeps its state, and the tiny `key = value` config format
//! it reads. Deliberately not JSON: this file is meant to be hand-edited, and
//! parsing it must not need a crate.

use std::path::{Path, PathBuf};

pub struct Config {
    /// Directories to scan and watch.
    pub paths: Vec<PathBuf>,
    /// Seconds between quick passes over known config targets.
    pub interval: u64,
    /// Seconds between full recursive scans.
    pub full_interval: u64,
    /// Seconds between git-ref audits. 0 disables them.
    pub git_interval: u64,
    /// Heal automatically, rather than only reporting.
    pub auto_heal: bool,
    /// Kill hidden loader processes when we find them.
    pub kill_procs: bool,
    /// Raise a desktop notification when something is found.
    pub notify: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            paths: Vec::new(),
            interval: 30,
            full_interval: 900,
            git_interval: 3600,
            auto_heal: true,
            kill_procs: true,
            notify: true,
        }
    }
}

/// Per-user state directory. Honours `POLINRIDER_HOME` for tests and for
/// people who would rather keep it somewhere else.
pub fn home() -> PathBuf {
    if let Ok(p) = std::env::var("POLINRIDER_HOME") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(p).join("polinrider-hunter");
        }
    }
    if let Ok(p) = std::env::var("XDG_DATA_HOME") {
        if !p.is_empty() {
            return PathBuf::from(p).join("polinrider-hunter");
        }
    }
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(base)
        .join(".local")
        .join("share")
        .join("polinrider-hunter")
}

pub fn config_path() -> PathBuf {
    home().join("config.txt")
}
pub fn log_path() -> PathBuf {
    home().join("hunter.log")
}
pub fn quarantine_dir() -> PathBuf {
    home().join("quarantine")
}
pub fn quarantine_index() -> PathBuf {
    quarantine_dir().join("index.jsonl")
}
pub fn heartbeat_path() -> PathBuf {
    home().join("daemon.heartbeat")
}

/// Drop a Windows extended-length prefix, if present.
///
/// `\\?\C:\x` becomes `C:\x`, and the UNC form `\\?\UNC\srv\share` becomes
/// `\\srv\share`. Split out from `normalize` so it can be tested without
/// touching the filesystem.
fn strip_verbatim(s: &str) -> Option<PathBuf> {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return Some(PathBuf::from(format!(r"\\{rest}")));
    }
    s.strip_prefix(r"\\?\").map(PathBuf::from)
}

/// Resolve a path, dropping Windows' `\\?\` verbatim prefix.
///
/// `canonicalize` returns an extended-length path. It is correct, and the APIs
/// accept it, but it leaks into the config file and into every line of output,
/// so trim it back to the form a person recognises.
pub fn normalize(p: &Path) -> PathBuf {
    let abs = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    // into_owned() ends the borrow so `abs` can still be returned below.
    let s = abs.to_string_lossy().into_owned();
    strip_verbatim(&s).unwrap_or(abs)
}

/// Path of the running executable, resolved for autostart registration.
pub fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("polinrider-hunter"))
}

impl Config {
    pub fn load() -> Config {
        let mut cfg = Config::default();
        let text = match std::fs::read_to_string(config_path()) {
            Ok(t) => t,
            Err(_) => return cfg,
        };
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            match k {
                // `path` repeats, one directory per line.
                "path" => {
                    if !v.is_empty() {
                        cfg.paths.push(PathBuf::from(v));
                    }
                }
                "interval" => cfg.interval = v.parse().unwrap_or(cfg.interval),
                "full_interval" => cfg.full_interval = v.parse().unwrap_or(cfg.full_interval),
                "git_interval" => cfg.git_interval = v.parse().unwrap_or(cfg.git_interval),
                "auto_heal" => cfg.auto_heal = parse_bool(v, cfg.auto_heal),
                "kill_procs" => cfg.kill_procs = parse_bool(v, cfg.kill_procs),
                "notify" => cfg.notify = parse_bool(v, cfg.notify),
                _ => {}
            }
        }
        cfg
    }

    pub fn save(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(home())?;
        let mut s = String::new();
        s.push_str("# polinrider-hunter configuration\n");
        s.push_str("# `path` may repeat, one directory per line.\n\n");
        for p in &self.paths {
            s.push_str(&format!("path = {}\n", p.display()));
        }
        s.push('\n');
        s.push_str(&format!("interval = {}\n", self.interval));
        s.push_str(&format!("full_interval = {}\n", self.full_interval));
        s.push_str(&format!("git_interval = {}\n", self.git_interval));
        s.push_str(&format!("auto_heal = {}\n", self.auto_heal));
        s.push_str(&format!("kill_procs = {}\n", self.kill_procs));
        s.push_str(&format!("notify = {}\n", self.notify));
        std::fs::write(config_path(), s)
    }
}

fn parse_bool(v: &str, default: bool) -> bool {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

/// The user's home directory.
pub fn user_home() -> PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(base)
}

/// Everywhere worth hunting on this machine.
///
/// The home directory always, plus every fixed drive when `all_drives` is set.
/// A developer's projects are almost always under home, so the default keeps a
/// full hunt to minutes rather than hours; `--drives` is there for the machine
/// with a D:\work partition.
pub fn machine_roots(all_drives: bool) -> Vec<PathBuf> {
    let mut out = vec![user_home()];
    if !all_drives {
        return out;
    }
    #[cfg(windows)]
    {
        // Probe drive letters directly: enumerating volumes properly needs the
        // Windows API, and a bare existence check costs nothing.
        for letter in b'A'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            let p = PathBuf::from(&root);
            if p.exists() && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    #[cfg(not(windows))]
    {
        for extra in ["/home", "/Users", "/opt", "/srv", "/var/www"] {
            let p = PathBuf::from(extra);
            if p.exists() && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// Find git repositories under `roots`, recursively.
///
/// Stops descending once a `.git` is found - nested repos inside a repo are
/// covered by scanning the parent, and not recursing saves a lot of walking.
pub fn discover_repos_under(roots: &[PathBuf], max_depth: usize) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0usize)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if depth > max_depth {
            continue;
        }
        if dir.join(".git").exists() {
            if !out.contains(&dir) {
                out.push(dir);
            }
            continue; // do not descend into a repo
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(meta) = e.metadata() else { continue };
            if !meta.is_dir() {
                continue;
            }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if crate::scanner::skip_dir(&name) {
                continue;
            }
            stack.push((p, depth + 1));
        }
    }
    out.sort();
    out
}

/// Repos under the home directory - what `install` uses when given no paths.
pub fn discover_repos() -> Vec<PathBuf> {
    discover_repos_under(&[user_home()], 6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bools_round_trip() {
        assert!(parse_bool("yes", false));
        assert!(parse_bool("TRUE", false));
        assert!(!parse_bool("off", true));
        // Unrecognised values keep the default rather than silently flipping.
        assert!(parse_bool("banana", true));
        assert!(!parse_bool("banana", false));
    }

    #[test]
    fn verbatim_prefixes_are_stripped() {
        assert_eq!(
            strip_verbatim(r"\\?\C:\Users\x\repo"),
            Some(PathBuf::from(r"C:\Users\x\repo"))
        );
        assert_eq!(
            strip_verbatim(r"\\?\UNC\server\share\repo"),
            Some(PathBuf::from(r"\\server\share\repo"))
        );
        // A path that never had the prefix is left for the caller to keep as-is.
        assert_eq!(strip_verbatim(r"C:\Users\x"), None);
        assert_eq!(strip_verbatim("/home/x/repo"), None);
    }

    #[test]
    fn home_honours_override() {
        std::env::set_var("POLINRIDER_HOME", "/tmp/pr-test-home");
        assert_eq!(home(), PathBuf::from("/tmp/pr-test-home"));
        std::env::remove_var("POLINRIDER_HOME");
    }
}
