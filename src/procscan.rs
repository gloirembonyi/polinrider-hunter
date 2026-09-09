//! Finding the loader's running children.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! Cleaning the file on disk stops the *next* build from re-infecting you, but
//! it does nothing about the process already running. Stage 1 ends with:
//!
//! ```text
//! spawn("node", ["-e", env + code], { detached: true, stdio: "ignore", windowsHide: true }).unref()
//! ```
//!
//! which is a hidden, orphaned interpreter with no console and no parent. It
//! survives the build that started it and will not appear in any task list the
//! user habitually looks at. What it *cannot* hide is its own command line: the
//! `env` prelude passed to `node -e` hands its stage-2 globals across verbatim,
//! and those global names are unmistakable.

use crate::util;

/// Substrings that only appear in a PolinRider stage-2 command line.
const PROC_MARKERS: &[&str] = &[
    "global['_V']",
    "global['_H']",
    "global['_t_s']",
    "global['_t_u']",
    "global['r']=require",
    "/0x/cls",
    "/0x/ls",
    "eth_getBlockByNumber",
];

#[derive(Debug, Clone)]
pub struct Suspect {
    pub pid: u32,
    pub marker: String,
    /// Truncated for display; these command lines are enormous.
    pub cmdline: String,
}

/// List running processes that look like a PolinRider stage 2.
pub fn find() -> Vec<Suspect> {
    let listing = list_processes();
    let mut out = Vec::new();
    for (pid, cmd) in listing {
        if let Some(m) = PROC_MARKERS.iter().find(|m| cmd.contains(**m)) {
            let short: String = cmd.chars().take(160).collect();
            out.push(Suspect {
                pid,
                marker: (*m).to_string(),
                cmdline: short,
            });
        }
    }
    out
}

/// `(pid, command line)` for candidate interpreter processes.
#[cfg(windows)]
fn list_processes() -> Vec<(u32, String)> {
    // A separator that will not occur inside a command line, so splitting the
    // output back apart is unambiguous.
    let ps = "Get-CimInstance Win32_Process -Filter \"Name='node.exe' OR Name='wscript.exe' OR Name='cscript.exe'\" \
              | ForEach-Object { \"$($_.ProcessId)|@|$($_.CommandLine)\" }";
    let out = util::run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", ps],
    );
    parse_listing(&out.stdout, "|@|")
}

#[cfg(not(windows))]
fn list_processes() -> Vec<(u32, String)> {
    let out = util::run("ps", &["-eo", "pid=,args="]);
    out.stdout
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let (pid, rest) = l.split_once(char::is_whitespace)?;
            Some((pid.parse::<u32>().ok()?, rest.trim().to_string()))
        })
        .collect()
}

/// Split `pid<sep>cmdline` lines. Separate from the platform call so it is testable.
fn parse_listing(text: &str, sep: &str) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|l| {
            let (pid, cmd) = l.split_once(sep)?;
            Some((pid.trim().parse::<u32>().ok()?, cmd.to_string()))
        })
        .collect()
}

/// Terminate a suspect. Returns true when the kill command succeeded.
pub fn kill(pid: u32) -> bool {
    let pid_s = pid.to_string();
    #[cfg(windows)]
    {
        util::run("taskkill", &["/F", "/PID", &pid_s]).ok
    }
    #[cfg(not(windows))]
    {
        util::run("kill", &["-9", &pid_s]).ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_parses() {
        let text = "1234|@|node -e global['_V']='0';\n99|@|node server.js\nrubbish\n";
        let got = parse_listing(text, "|@|");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, 1234);
        assert_eq!(got[1].1, "node server.js");
    }

    #[test]
    fn markers_identify_only_the_loader() {
        let loader = "node -e global['_V']='A9-4221';global['r']=require;";
        let honest = "node -e console.log('hello')";
        assert!(PROC_MARKERS.iter().any(|m| loader.contains(*m)));
        assert!(!PROC_MARKERS.iter().any(|m| honest.contains(*m)));
    }
}
