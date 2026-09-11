//! Windows persistence used by the AppData loader campaign, and its removal.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! `persist.rs` reports startup locations and never edits them, on purpose:
//! shell profiles and login agents are full of legitimate entries, and deleting
//! one on suspicion is worse than leaving it. This module is narrower and may
//! act, because it only ever touches an entry whose *target* is provably
//! malware:
//!
//!   * an `HKCU\...\Run` value whose command launches a `.vbs`/`.js` shim that
//!     carries a campaign indicator (or the fake-NGEN path), and
//!   * a Scheduled Task whose action does the same.
//!
//! Both persistence forms seen in the wild pose as Microsoft/VS Code
//! ("MicrosoftCLROptimization", "VSCodeUpdater") and run a one-line `wscript`
//! shim out of %LOCALAPPDATA%. The decision to remove is keyed on the shim's
//! contents, not on the entry's name, so a genuine "VSCodeUpdater" could never
//! be removed by mistake.
//!
//! Everything here shells out to `reg` and `schtasks` through `util::run`; the
//! matching logic that decides *whether* to act is pure and unit-tested.

use std::path::{Path, PathBuf};

use crate::scanner;
use crate::util;

/// One thing found, and what happened to it.
pub struct Action {
    pub kind: &'static str,
    pub name: String,
    pub target: String,
    /// `true` if it was (or would be) removed; `false` if only reported.
    pub removed: bool,
    pub detail: String,
}

/// Campaign markers that, seen in a launcher command or the file it runs, mark
/// the whole persistence entry as malware. Kept in step with signatures.rs.
const COMMAND_MARKERS: &[&str] = &[
    "clr_init.vbs",
    "CLR_v4.0\\Optimization",
    "CLR_v4.0/Optimization",
    "194.11.226.41",
    "193.247.144.38",
];

/// Does a launcher command line (a Run value's data, or a task's action) point
/// at this campaign? True when the command itself carries a marker, or when it
/// runs a script file that does.
pub fn command_is_malicious(command: &str) -> bool {
    if COMMAND_MARKERS.iter().any(|m| command.contains(m)) {
        return true;
    }
    // Otherwise, follow the script it launches and judge that.
    if let Some(script) = script_path_in(command) {
        return file_carries_marker(&script);
    }
    false
}

/// Extract the first `.vbs` / `.js` path from a launcher command line.
///
/// Handles the quoting these shims use: a wscript/cscript or node invocation
/// with the script path as a quoted argument, e.g.
/// `wscript.exe //B "C:\...\VSCodeUpdater.vbs"` or
/// `"C:\Program Files\nodejs\node.exe" "C:\...\loader.js" --token ...`.
pub fn script_path_in(command: &str) -> Option<PathBuf> {
    // Prefer a quoted token that ends in a script extension.
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(end) = command[i + 1..].find('"') {
                let inner = &command[i + 1..i + 1 + end];
                if has_script_ext(inner) {
                    return Some(PathBuf::from(inner));
                }
                i = i + 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    // Fall back to any whitespace-separated token that ends in a script ext.
    command
        .split_whitespace()
        .map(|t| t.trim_matches('"'))
        .find(|t| has_script_ext(t))
        .map(PathBuf::from)
}

fn has_script_ext(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.ends_with(".vbs") || l.ends_with(".js") || l.ends_with(".cjs") || l.ends_with(".mjs")
}

/// Read `path` and report whether the hunter flags it as malware.
fn file_carries_marker(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    scanner::scan_file(path)
        .map(|f| f.is_critical())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// The Registry Run keys.
// ---------------------------------------------------------------------------

const RUN_KEYS: &[&str] = &[
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
];

/// Parse `reg query` output into `(value_name, data)` pairs.
///
/// A data row looks like: `    NAME    REG_SZ    C:\...\thing.exe --flag`.
/// The three columns are separated by runs of spaces; the data itself may
/// contain spaces, so only the first two gaps are split on.
pub fn parse_reg_query(out: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if !line.starts_with("    ") {
            continue; // key headers and blank lines
        }
        let t = line.trim_start();
        // NAME <ws> TYPE <ws> DATA
        let Some((name, rest)) = split_once_ws(t) else {
            continue;
        };
        let Some((ty, data)) = split_once_ws(rest) else {
            continue;
        };
        if !ty.starts_with("REG_") {
            continue;
        }
        pairs.push((name.to_string(), data.to_string()));
    }
    pairs
}

/// Split on the first run of whitespace (two or more spaces, or a tab).
fn split_once_ws(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // A single space inside a name is possible in theory but not in the
        // values these tools emit; two spaces or a tab is the column gap.
        if bytes[i] == b'\t' || (bytes[i] == b' ' && i + 1 < bytes.len() && bytes[i + 1] == b' ') {
            let name = s[..i].trim_end();
            let rest = s[i..].trim_start();
            return Some((name, rest));
        }
        i += 1;
    }
    None
}

fn sweep_run_keys(dry: bool, out: &mut Vec<Action>) {
    for key in RUN_KEYS {
        let q = util::run("reg", &["query", key]);
        if !q.ok {
            continue;
        }
        for (name, data) in parse_reg_query(&q.stdout) {
            if !command_is_malicious(&data) {
                continue;
            }
            let removed = if dry {
                false
            } else {
                util::run("reg", &["delete", key, "/v", &name, "/f"]).ok
            };
            out.push(Action {
                kind: "run-key",
                name: format!("{key}\\{name}"),
                target: data,
                removed,
                detail: if dry {
                    "would remove (dry run)".into()
                } else if removed {
                    "removed".into()
                } else {
                    "removal FAILED - remove by hand".into()
                },
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduled Tasks.
// ---------------------------------------------------------------------------

/// Parse `schtasks /query /fo LIST /v` output into `(TaskName, TaskToRun)`.
pub fn parse_task_list(out: &str) -> Vec<(String, String)> {
    let mut tasks = Vec::new();
    let mut name: Option<String> = None;
    for line in out.lines() {
        if let Some(v) = field(line, "TaskName:") {
            name = Some(v.to_string());
        } else if let Some(v) = field(line, "Task To Run:") {
            if let Some(n) = name.take() {
                tasks.push((n, v.to_string()));
            }
        }
    }
    tasks
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let t = line.trim_start();
    t.strip_prefix(key).map(|v| v.trim())
}

fn sweep_tasks(dry: bool, out: &mut Vec<Action>) {
    let q = util::run("schtasks", &["/query", "/fo", "LIST", "/v"]);
    if !q.ok {
        return;
    }
    for (name, action) in parse_task_list(&q.stdout) {
        if !command_is_malicious(&action) {
            continue;
        }
        let removed = if dry {
            false
        } else {
            util::run("schtasks", &["/delete", "/tn", &name, "/f"]).ok
        };
        out.push(Action {
            kind: "task",
            name,
            target: action,
            removed,
            detail: if dry {
                "would remove (dry run)".into()
            } else if removed {
                "removed".into()
            } else {
                "removal FAILED - remove by hand".into()
            },
        });
    }
}

/// Find and (unless `dry`) remove the campaign's Windows persistence.
///
/// A no-op on non-Windows: these vectors are Windows-only, and `reg`/`schtasks`
/// do not exist elsewhere.
pub fn sweep(dry: bool) -> Vec<Action> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        sweep_run_keys(dry, &mut out);
        sweep_tasks(dry, &mut out);
    }
    #[cfg(not(windows))]
    {
        let _ = (dry, &mut out, sweep_run_keys as fn(bool, &mut Vec<Action>));
        let _ = sweep_tasks as fn(bool, &mut Vec<Action>);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clr_run_command_is_flagged() {
        let cmd = "wscript.exe //B //Nologo \"C:\\Users\\me\\AppData\\Local\\Microsoft\\CLR_v4.0\\Optimization\\cache\\clr_init.vbs\"";
        assert!(command_is_malicious(cmd));
    }

    #[test]
    fn a_node_loader_with_the_c2_is_flagged() {
        let cmd = "\"C:\\Program Files\\nodejs\\node.exe\" \"C:\\Users\\me\\AppData\\Local\\x.js\" --token \"http://194.11.226.41:4000|tok\"";
        assert!(command_is_malicious(cmd));
    }

    #[test]
    fn an_honest_updater_is_left_alone() {
        // Real VS Code / OneDrive style entries carry no marker and launch no
        // script we can flag.
        assert!(!command_is_malicious(
            "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background"
        ));
        assert!(!command_is_malicious(
            "\"C:\\Users\\me\\AppData\\Local\\Programs\\app\\App.exe\""
        ));
    }

    #[test]
    fn script_path_is_extracted_from_quotes() {
        let cmd = "wscript.exe //B \"C:\\Users\\me\\AppData\\Local\\VSCodeUpdater.vbs\"";
        assert_eq!(
            script_path_in(cmd),
            Some(PathBuf::from("C:\\Users\\me\\AppData\\Local\\VSCodeUpdater.vbs"))
        );
    }

    #[test]
    fn reg_query_output_is_parsed() {
        let out = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    OneDrive    REG_SZ    \"C:\\OneDrive.exe\" /background\r\n    Bad    REG_SZ    wscript //B \"C:\\clr_init.vbs\"\r\n";
        let pairs = parse_reg_query(out);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "OneDrive");
        assert!(pairs[1].1.contains("clr_init.vbs"));
        // The malicious one is flagged, the honest one is not.
        assert!(!command_is_malicious(&pairs[0].1));
        assert!(command_is_malicious(&pairs[1].1));
    }

    #[test]
    fn task_list_output_is_parsed() {
        let out = "\r\nFolder: \\\r\nHostName:      PC\r\nTaskName:      \\VSCodeUpdater\r\nTask To Run:   wscript.exe //B \"C:\\Users\\me\\AppData\\Local\\VSCodeUpdater.vbs\"\r\nTaskName:      \\RealBackup\r\nTask To Run:   C:\\Windows\\System32\\backup.exe\r\n";
        let tasks = parse_task_list(out);
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].0, "\\VSCodeUpdater");
        assert!(tasks[0].1.contains("VSCodeUpdater.vbs"));
        assert_eq!(tasks[1].0, "\\RealBackup");
    }
}
