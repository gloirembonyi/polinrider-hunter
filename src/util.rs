//! Small helpers we would otherwise pull crates in for: colour, timestamps,
//! and running a child process to completion.

use std::io::Write;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Colour
// ---------------------------------------------------------------------------

pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[36m";
pub const DIM: &str = "\x1b[2m";
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

static mut COLOUR: bool = true;

/// Turn colour off (for `--no-color`, or when piping to a file).
pub fn set_colour(on: bool) {
    unsafe { COLOUR = on }
}

fn colour_on() -> bool {
    unsafe { COLOUR }
}

/// Whether colour is enabled. Needed by callers that build a whole block of
/// pre-formatted text (the help screen) rather than colouring one span.
pub fn colour_enabled() -> bool {
    colour_on()
}

/// Wrap `s` in an ANSI colour, or return it unchanged when colour is off.
pub fn c(colour: &str, s: &str) -> String {
    if colour_on() {
        format!("{colour}{s}{RESET}")
    } else {
        s.to_string()
    }
}

/// Decide whether this terminal can render ANSI escapes.
///
/// This used to shell out to `cmd /c ver` to "nudge" the console into VT mode.
/// That was wrong twice over: the mode change applies to the child, not to us,
/// so it achieved nothing - and it spawned a visible console window on every
/// single invocation. Modern Windows terminals (Windows Terminal, VS Code,
/// Cursor) are in VT mode already; the legacy conhost is not, and there it is
/// better to print no escapes than mojibake.
pub fn enable_ansi() {
    #[cfg(windows)]
    {
        let modern = std::env::var("WT_SESSION").is_ok()
            || std::env::var("TERM_PROGRAM").is_ok()
            || std::env::var("ConEmuANSI").map(|v| v == "ON").unwrap_or(false)
            || std::env::var("TERM").is_ok();
        if !modern {
            set_colour(false);
        }
    }
}

/// Suppress the console window a child process would otherwise flash up.
///
/// Without this, a background service that shells out - and this one calls
/// `powershell` to enumerate processes and `git` to read refs - throws a black
/// window on screen every time, which is both alarming and impossible to work
/// through. `CREATE_NO_WINDOW` keeps the child headless.
#[cfg(windows)]
fn hide_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_window(_cmd: &mut Command) {}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SSZ` for a Unix timestamp, in UTC.
///
/// Hand-rolled so the binary keeps its zero-dependency promise. Uses the
/// standard days-from-civil algorithm, run in reverse.
pub fn fmt_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Compact `YYYYMMDD-HHMMSS`, for filenames.
pub fn fmt_stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        y,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------

pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command, capturing output. Never panics: a missing binary comes back
/// as `ok: false` with the error in `stderr`.
pub fn run(program: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new(program);
    cmd.args(args);
    hide_window(&mut cmd);
    match cmd.output() {
        Ok(o) => Output {
            ok: o.status.success(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => Output {
            ok: false,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

/// Run `git` inside `repo`.
pub fn git(repo: &std::path::Path, args: &[&str]) -> Output {
    let mut full: Vec<&str> = vec!["-C"];
    let repo_s = repo.to_str().unwrap_or(".");
    full.push(repo_s);
    full.extend_from_slice(args);
    run("git", &full)
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Append a line to the hunter log, and echo it when `echo` is set.
pub fn log_line(path: &std::path::Path, msg: &str, echo: bool) {
    let line = format!("{} {}\n", fmt_time(now_secs()), msg);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = f.write_all(line.as_bytes());
    }
    if echo {
        print!("{line}");
        let _ = std::io::stdout().flush();
    }
}

/// Escape a string for embedding in our JSON output.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00Z");
    }

    #[test]
    fn known_timestamp_formats() {
        // 2026-09-09 00:00:00Z
        assert_eq!(fmt_time(1_788_912_000), "2026-09-09 00:00:00Z");
    }

    #[test]
    fn stamp_has_no_separators_that_break_filenames() {
        let s = fmt_stamp(1_788_912_000);
        assert_eq!(s, "20260909-000000");
        assert!(!s.contains(':'));
        assert!(!s.contains(' '));
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
