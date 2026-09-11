//! Desktop notifications.
//!
//! A guard that finds malware at 02:00 and only writes it to a log file has not
//! really told anybody. This puts a notification in front of the person using
//! the machine, on whichever desktop they are using.
//!
//! Every path shells out to something already present on the platform, so the
//! zero-dependency promise holds. Notifications are best-effort by design: if
//! the desktop is not there - a headless server, a locked session, an SSH
//! shell - the failure is silent and the log still has the detail. A scanner
//! that refused to run because it could not raise a toast would be worse than
//! one that stays quiet.

use crate::util;

/// How the notification should read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Something was found and dealt with.
    Removed,
    /// Something was found that needs a person.
    NeedsYou,
}

impl Level {
    fn title(self) -> &'static str {
        match self {
            Level::Removed => "PolinRider removed",
            Level::NeedsYou => "PolinRider found - action needed",
        }
    }
}

/// Raise a desktop notification. Never blocks, never fails loudly.
pub fn send(level: Level, body: &str) {
    // Keep it short: every platform truncates, and a notification that needs
    // scrolling has failed at its job.
    let body = trim(body, 220);
    let title = level.title();

    #[cfg(windows)]
    windows_toast(title, &body, level);

    #[cfg(target_os = "macos")]
    macos_toast(title, &body);

    #[cfg(all(unix, not(target_os = "macos")))]
    linux_toast(title, &body, level);

    #[cfg(not(any(windows, unix)))]
    {
        let _ = (title, &body, level);
    }
}

/// Cut to `max` characters on a word boundary where possible.
fn trim(s: &str, max: usize) -> String {
    // Collapse whitespace runs rather than substituting them: a CRLF pair would
    // otherwise become two spaces, and a wrapped path list would arrive full of
    // gaps.
    let s: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= max {
        return s;
    }
    let cut: String = s.chars().take(max).collect();
    match cut.rfind(' ') {
        Some(i) if i > max / 2 => format!("{}…", &cut[..i]),
        _ => format!("{cut}…"),
    }
}

/// Escape for embedding in a single-quoted PowerShell string.
#[cfg(windows)]
fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

#[cfg(windows)]
fn windows_toast(title: &str, body: &str, level: Level) {
    // A tray balloon rather than a WinRT toast: WinRT needs a registered
    // AppUserModelID to show anything at all, which a portable binary in a user
    // directory does not have. NotifyIcon works on every supported Windows and
    // needs no registration.
    //
    // The helper has to outlive the balloon, so it sleeps - which is why this is
    // spawned and never waited on.
    let icon = if level == Level::NeedsYou { "Warning" } else { "Info" };
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
         $n = New-Object System.Windows.Forms.NotifyIcon; \
         $n.Icon = [System.Drawing.SystemIcons]::{icon}; \
         $n.BalloonTipIcon = '{icon}'; \
         $n.BalloonTipTitle = '{}'; \
         $n.BalloonTipText = '{}'; \
         $n.Visible = $true; \
         $n.ShowBalloonTip(12000); \
         Start-Sleep -Seconds 13; \
         $n.Dispose()",
        ps_quote(title),
        ps_quote(body),
    );
    util::spawn_detached(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script],
    );
}

#[cfg(target_os = "macos")]
fn macos_toast(title: &str, body: &str) {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        esc(body),
        esc(title)
    );
    util::spawn_detached("osascript", &["-e", &script]);
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_toast(title: &str, body: &str, level: Level) {
    let urgency = if level == Level::NeedsYou { "critical" } else { "normal" };
    // notify-send is part of libnotify and present on essentially every desktop
    // Linux install. On a headless box it simply is not there, and spawn fails
    // quietly, which is the behaviour we want.
    util::spawn_detached(
        "notify-send",
        &["-u", urgency, "-a", "polinrider-hunter", title, body],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_bodies_are_trimmed_on_a_word_boundary() {
        let long = "word ".repeat(100);
        let out = trim(&long, 40);
        assert!(out.chars().count() <= 41, "got {} chars", out.chars().count());
        assert!(out.ends_with('…'));
    }

    #[test]
    fn short_bodies_are_untouched() {
        assert_eq!(trim("all clear", 220), "all clear");
    }

    #[test]
    fn newlines_would_break_a_shell_argument() {
        assert_eq!(trim("a\nb\r\nc", 220), "a b c");
    }

    #[test]
    fn titles_say_whether_a_person_is_needed() {
        assert!(Level::Removed.title().contains("removed"));
        assert!(Level::NeedsYou.title().contains("action needed"));
    }

    #[cfg(windows)]
    #[test]
    fn single_quotes_cannot_escape_the_powershell_string() {
        assert_eq!(ps_quote("it's a 'test'"), "it''s a ''test''");
    }
}
