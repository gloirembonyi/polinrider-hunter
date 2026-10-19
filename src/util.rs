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
        // Ask the console for escape-sequence support directly (Windows 10+).
        // Guessing from environment variables left plain PowerShell and cmd
        // windows colourless, and - worse - unable to redraw a status line.
        let vt = console::enable_vt();
        let modern = vt
            || std::env::var("WT_SESSION").is_ok()
            || std::env::var("TERM_PROGRAM").is_ok()
            || std::env::var("ConEmuANSI").map(|v| v == "ON").unwrap_or(false)
            || std::env::var("TERM").is_ok();
        if !modern {
            set_colour(false);
        }
    }
}

/// The few console calls std does not offer: escape-sequence processing and
/// echo-free input on Windows. Declared by hand against kernel32 so the binary
/// keeps its zero-dependency promise.
pub mod console {
    #[cfg(windows)]
    mod win {
        pub type Handle = *mut core::ffi::c_void;
        pub const STD_INPUT: u32 = -10i32 as u32;
        pub const STD_OUTPUT: u32 = -11i32 as u32;
        pub const STD_ERROR: u32 = -12i32 as u32;
        pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
        pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
        #[link(name = "kernel32")]
        extern "system" {
            pub fn GetStdHandle(which: u32) -> Handle;
            pub fn GetConsoleMode(h: Handle, mode: *mut u32) -> i32;
            pub fn SetConsoleMode(h: Handle, mode: u32) -> i32;
        }
        /// The handle's console mode, or None when it is not a console.
        pub fn mode(which: u32) -> Option<(Handle, u32)> {
            unsafe {
                let h = GetStdHandle(which);
                if h.is_null() || h as isize == -1 {
                    return None;
                }
                let mut m = 0u32;
                (GetConsoleMode(h, &mut m) != 0).then_some((h, m))
            }
        }
    }

    use std::sync::atomic::{AtomicBool, Ordering};
    static VT: AtomicBool = AtomicBool::new(false);

    /// Turn on escape-sequence processing for stdout and stderr. True when the
    /// terminal can now redraw a line in place.
    pub fn enable_vt() -> bool {
        #[cfg(windows)]
        {
            let mut ok = false;
            for which in [win::STD_OUTPUT, win::STD_ERROR] {
                if let Some((h, m)) = win::mode(which) {
                    let want = m | win::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                    ok |= unsafe { win::SetConsoleMode(h, want) } != 0;
                }
            }
            VT.store(ok, Ordering::Relaxed);
            ok
        }
        #[cfg(not(windows))]
        {
            let ok = std::env::var("TERM").map(|t| t != "dumb").unwrap_or(false);
            VT.store(ok, Ordering::Relaxed);
            ok
        }
    }

    /// Escape sequences work on this terminal (after `enable_vt`).
    pub fn vt() -> bool {
        VT.load(Ordering::Relaxed)
    }

    /// Run `f` with keyboard echo switched off, restoring it afterwards even if
    /// `f` fails. Returns whether echo was actually hidden.
    pub fn without_echo<T>(f: impl FnOnce() -> T) -> (T, bool) {
        #[cfg(windows)]
        {
            if let Some((h, m)) = win::mode(win::STD_INPUT) {
                let hidden = unsafe { win::SetConsoleMode(h, m & !win::ENABLE_ECHO_INPUT) } != 0;
                let out = f();
                unsafe { win::SetConsoleMode(h, m) };
                return (out, hidden);
            }
            (f(), false)
        }
        #[cfg(unix)]
        {
            use std::process::{Command, Stdio};
            let hidden = Command::new("stty").arg("-echo").stdin(Stdio::inherit()).status().map(|s| s.success()).unwrap_or(false);
            let out = f();
            if hidden {
                let _ = Command::new("stty").arg("echo").stdin(Stdio::inherit()).status();
            }
            (out, hidden)
        }
        #[cfg(not(any(windows, unix)))]
        {
            (f(), false)
        }
    }
}

/// A one-line "still working" indicator for long runs.
///
/// Redrawn in place once a second on stderr. Anything else that prints while it
/// is active must go through `status::say` (or call `status::clear` first), so
/// the indicator is wiped before the line and redrawn after it instead of the
/// two interleaving.
pub mod status {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static LOCK: Mutex<()> = Mutex::new(());

    /// Start the indicator. `line` builds the text from the elapsed time; it is
    /// only shown when stderr is a terminal that can redraw a line.
    pub fn start(line: impl Fn(Duration) -> String + Send + 'static) {
        use std::io::IsTerminal;
        if !std::io::stderr().is_terminal() || !super::console::vt() || ACTIVE.swap(true, Ordering::SeqCst) {
            return;
        }
        let t0 = Instant::now();
        std::thread::spawn(move || {
            while ACTIVE.load(Ordering::SeqCst) {
                if let Ok(_g) = LOCK.lock() {
                    if ACTIVE.load(Ordering::SeqCst) {
                        let mut text = line(t0.elapsed());
                        let width = super::terminal_width().saturating_sub(1).max(20);
                        if text.chars().count() > width {
                            text = text.chars().take(width.saturating_sub(1)).collect::<String>() + "…";
                        }
                        let mut e = std::io::stderr();
                        let _ = write!(e, "\r\x1b[2K{}{}{}", super::DIM, text, super::RESET);
                        let _ = e.flush();
                    }
                }
                std::thread::sleep(Duration::from_millis(1000));
            }
        });
    }

    /// Wipe the indicator so the next line prints cleanly. Hold the returned
    /// guard while printing.
    pub fn clear() -> Option<std::sync::MutexGuard<'static, ()>> {
        let g = LOCK.lock().ok();
        if ACTIVE.load(Ordering::SeqCst) {
            let mut e = std::io::stderr();
            let _ = write!(e, "\r\x1b[2K");
            let _ = e.flush();
        }
        g
    }

    /// Stop and wipe the indicator.
    pub fn stop() {
        let _g = LOCK.lock();
        if ACTIVE.swap(false, Ordering::SeqCst) {
            let mut e = std::io::stderr();
            let _ = write!(e, "\r\x1b[2K");
            let _ = e.flush();
        }
    }
}

/// Columns in the terminal, from $COLUMNS when set; 100 otherwise.
pub fn terminal_width() -> usize {
    std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok()).unwrap_or(100)
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

/// Start a child and do not wait for it.
///
/// For work whose result we do not need and whose duration we do not control -
/// a desktop notification helper that has to outlive the balloon it shows. The
/// child is detached and windowless so nothing flashes on screen.
pub fn spawn_detached(program: &str, args: &[&str]) -> bool {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    hide_window(&mut cmd);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW);
    }
    cmd.spawn().is_ok()
}

/// Neutralise repository configuration that runs programs.
///
/// Every repo this tool opens is one that might be compromised, and git runs
/// code a repository's own config names: `core.fsmonitor` on anything that
/// refreshes the index (`status`, `diff`), hooks on `push`, a pager on long
/// output. An attacker who can write `.git/config` turns "audit this repo" into
/// "run my program". These overrides come first on the command line, so they
/// beat whatever the repository says.
pub fn harden_git(cmd: &mut Command) {
    #[cfg(windows)]
    const NO_HOOKS: &str = "core.hooksPath=NUL";
    #[cfg(not(windows))]
    const NO_HOOKS: &str = "core.hooksPath=/dev/null";
    cmd.args([
        "-c", "core.fsmonitor=false",
        "-c", NO_HOOKS,
        "-c", "core.pager=cat",
        "-c", "protocol.ext.allow=never",
    ]);
}

/// Run `git` inside `repo`.
pub fn git(repo: &std::path::Path, args: &[&str]) -> Output {
    let mut full: Vec<&str> = vec!["-C"];
    let repo_s = repo.to_str().unwrap_or(".");
    full.push(repo_s);
    full.extend_from_slice(args);
    run_git(&full)
}

/// Run git with every interactive prompt disabled.
///
/// The branch audit fetches remotes, and a background guard has no console. If
/// a stored credential has expired, git would sit waiting for a username that
/// nobody can type - the process stays alive, stops doing anything, and the
/// only symptom is a guard that never reports again. Refusing to prompt turns
/// that into a failed fetch, which is a thing we can report and carry on from.
fn run_git(args: &[&str]) -> Output {
    let mut cmd = Command::new("git");
    harden_git(&mut cmd);
    cmd.args(args);
    // No terminal prompt, no GUI credential helper, no ssh passphrase prompt.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GCM_INTERACTIVE", "never");
    cmd.env("GIT_ASKPASS", "");
    cmd.env("SSH_ASKPASS", "");
    cmd.env("GIT_SSH_COMMAND", "ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new");
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
