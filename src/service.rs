//! Making the guard start itself on login, on each supported platform, without
//! ever needing administrator rights.
//!
//! Every mechanism here is a plain text file in a well-known place. That is a
//! deliberate choice: a security tool that installs itself somewhere the user
//! cannot easily find or delete is behaving like the thing it is trying to
//! remove. `status` prints the exact path, and `uninstall` removes it.

use std::path::{Path, PathBuf};

use crate::config;
use crate::util;

/// Where the login hook lives on this platform.
///
/// Exactly one of these bodies survives `cfg`, and it is the function's tail
/// expression — so no `return`, which would leave the signature returning `()`.
#[cfg(windows)]
pub fn autostart_path() -> PathBuf {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    PathBuf::from(appdata)
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
        .join("PolinRiderHunter.vbs")
}

#[cfg(target_os = "macos")]
pub fn autostart_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join("com.polinrider.hunter.plist")
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn autostart_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.config")
    });
    PathBuf::from(base)
        .join("systemd/user")
        .join("polinrider-hunter.service")
}

pub fn is_installed() -> bool {
    autostart_path().exists()
}

/// Register the daemon to start at login.
pub fn install_autostart(exe: &Path) -> std::io::Result<PathBuf> {
    let target = autostart_path();
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let exe_s = exe.display().to_string();

    #[cfg(windows)]
    {
        // A one-line VBS launcher: `Run(..., 0, False)` starts the daemon with
        // no console window, which a Startup-folder shortcut to a console
        // binary cannot do.
        let vbs = format!(
            "' polinrider-hunter background guard.\r\n\
             ' Starts the PolinRider scanner at logon. Delete this file to disable,\r\n\
             ' or run: polinrider-hunter uninstall\r\n\
             CreateObject(\"WScript.Shell\").Run \"\"\"{}\"\" daemon\", 0, False\r\n",
            exe_s
        );
        std::fs::write(&target, vbs)?;
    }

    #[cfg(target_os = "macos")]
    {
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.polinrider.hunter</string>
  <key>ProgramArguments</key>
  <array><string>{exe_s}</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#
        );
        std::fs::write(&target, plist)?;
        let _ = util::run("launchctl", &["load", "-w", target.to_str().unwrap_or("")]);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let unit = format!(
            "[Unit]\n\
             Description=PolinRider Hunter background guard\n\n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe_s} daemon\n\
             Restart=always\n\
             RestartSec=30\n\n\
             [Install]\n\
             WantedBy=default.target\n"
        );
        std::fs::write(&target, unit)?;
        let _ = util::run("systemctl", &["--user", "daemon-reload"]);
        let _ = util::run("systemctl", &["--user", "enable", "polinrider-hunter"]);
    }

    Ok(target)
}

pub fn uninstall_autostart() -> std::io::Result<bool> {
    let target = autostart_path();
    if !target.exists() {
        return Ok(false);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = util::run("launchctl", &["unload", "-w", target.to_str().unwrap_or("")]);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = util::run("systemctl", &["--user", "disable", "polinrider-hunter"]);
        let _ = util::run("systemctl", &["--user", "stop", "polinrider-hunter"]);
    }
    std::fs::remove_file(&target)?;
    Ok(true)
}

/// Start the daemon now, detached from this console.
pub fn spawn_daemon(exe: &Path) -> std::io::Result<u32> {
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon");
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NO_WINDOW
        cmd.creation_flags(0x0000_0008 | 0x0800_0000);
    }

    let child = cmd.spawn()?;
    Ok(child.id())
}

/// Is a daemon alive? Returns the heartbeat age when so.
///
/// Freshness alone is not enough. Kill a daemon and its last heartbeat stays on
/// disk looking recent, which locks out a replacement for the whole grace
/// window - and worse, makes `install` report a guard that is not there. So we
/// require both: a recent beat *and* the process that wrote it still running.
pub fn daemon_alive(interval: u64) -> Option<u64> {
    let text = std::fs::read_to_string(config::heartbeat_path()).ok()?;
    let mut parts = text.trim().split_whitespace();
    let pid: u32 = parts.next()?.parse().ok()?;
    let beat: u64 = parts.next()?.parse().ok()?;
    let age = util::now_secs().saturating_sub(beat);
    // Allow three missed beats before calling it stale.
    if age > interval.saturating_mul(3).max(90) {
        return None;
    }
    // Our own process does not count as "another daemon".
    if pid == std::process::id() {
        return Some(age);
    }
    if pid_alive(pid) {
        Some(age)
    } else {
        None
    }
}

/// Drop this process to a background priority.
///
/// Setting your own priority class needs a platform API call, and this crate
/// carries no dependencies - so it is one shell-out, once, at daemon startup.
/// Worth it: a scanner that makes the machine feel slow gets uninstalled, and
/// at below-normal priority the guard yields to everything the user is doing
/// while still finishing its work promptly on an idle core.
pub fn lower_priority() {
    let pid = std::process::id();
    #[cfg(windows)]
    {
        let script = format!(
            "try {{ (Get-Process -Id {pid}).PriorityClass = 'BelowNormal' }} catch {{}}"
        );
        let _ = util::run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        );
    }
    #[cfg(not(windows))]
    {
        let _ = util::run("renice", &["-n", "10", "-p", &pid.to_string()]);
    }
}

/// The pid currently holding the heartbeat, if any.
pub fn daemon_pid() -> Option<u32> {
    let text = std::fs::read_to_string(config::heartbeat_path()).ok()?;
    text.trim().split_whitespace().next()?.parse().ok()
}

/// Is a process id currently running? Shelled out, to stay dependency-free.
pub fn pid_alive(pid: u32) -> bool {
    let pid_s = pid.to_string();
    #[cfg(windows)]
    {
        let out = util::run(
            "tasklist",
            &["/FI", &format!("PID eq {pid_s}"), "/NH", "/FO", "CSV"],
        );
        // No match prints an INFO line rather than the row, so look for the id.
        out.ok && out.stdout.contains(&pid_s)
    }
    #[cfg(not(windows))]
    {
        // `kill -0` signals nothing; it just reports whether we could.
        util::run("kill", &["-0", &pid_s]).ok
    }
}

/// Wait briefly for a freshly spawned daemon to publish a heartbeat.
///
/// `spawn` succeeding only means the process started, not that it stayed up -
/// it may exit immediately because another instance holds the lock. Claiming
/// "guard running" without checking is how you end up with no guard at all.
pub fn wait_for_daemon(interval: u64, secs: u64) -> bool {
    for _ in 0..(secs * 4) {
        if daemon_alive(interval).is_some() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

/// What happened when we asked a guard to stop.
///
/// "Could not" and "there was nothing to stop" have to be distinguishable. A
/// guard belonging to another session, or started elevated, refuses to die -
/// and reporting that as "no guard was running" while an upgrade overwrites the
/// binary underneath it is exactly the silent failure this tool exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    Stopped(u32),
    /// Alive, but the operating system would not let us end it.
    Denied(u32),
    None,
}

/// End a process, trying harder than one syscall.
///
/// `taskkill /F` is refused for some same-user processes - a detached child
/// whose parent console is gone is the case seen in practice - while the WMI
/// `Win32_Process.Terminate` on the same pid succeeds. Neither is reliable
/// alone, so try the cheap one and fall back.
fn end_process(pid: u32) -> bool {
    let pid_s = pid.to_string();

    #[cfg(windows)]
    {
        if util::run("taskkill", &["/F", "/PID", &pid_s]).ok {
            return true;
        }
        let script = format!(
            "$p = Get-CimInstance Win32_Process -Filter 'ProcessId={pid_s}' \
             -ErrorAction SilentlyContinue; \
             if ($p) {{ (Invoke-CimMethod -InputObject $p -MethodName Terminate).ReturnValue }} \
             else {{ 0 }}"
        );
        let out = util::run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        );
        // Terminate answers 0 for success; anything else is a refusal.
        return out.ok && out.stdout.trim() == "0";
    }

    #[cfg(not(windows))]
    {
        if util::run("kill", &["-TERM", &pid_s]).ok {
            // Give it a moment to leave politely before insisting.
            for _ in 0..20 {
                if !pid_alive(pid) {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        util::run("kill", &["-KILL", &pid_s]).ok
    }
}

/// Stop a running guard, if there is one.
pub fn stop_daemon() -> Stopped {
    let Ok(text) = std::fs::read_to_string(config::heartbeat_path()) else {
        return Stopped::None;
    };
    let Some(pid) = text
        .trim()
        .split_whitespace()
        .next()
        .and_then(|p| p.parse::<u32>().ok())
    else {
        return Stopped::None;
    };
    if pid == std::process::id() {
        return Stopped::None;
    }
    if !pid_alive(pid) {
        // A stale heartbeat from a guard that crashed or was killed. Clearing it
        // is the point: the next install would otherwise defer to a dead pid.
        let _ = std::fs::remove_file(config::heartbeat_path());
        return Stopped::None;
    }
    if !end_process(pid) {
        // Leave the heartbeat alone. It is still accurate - that guard really is
        // running - and deleting it would make `status` claim otherwise.
        return Stopped::Denied(pid);
    }
    let _ = std::fs::remove_file(config::heartbeat_path());
    // taskkill and kill both return as soon as the signal is delivered, not
    // when the process is gone. An installer that overwrites the binary in that
    // gap still hits a file lock, so wait for the handle to actually close.
    for _ in 0..40 {
        if !pid_alive(pid) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if pid_alive(pid) {
        Stopped::Denied(pid)
    } else {
        Stopped::Stopped(pid)
    }
}

/// Stop any guard process that is not the one holding the heartbeat.
///
/// Upgrades are the reason this exists. A build old enough to predate the
/// heartbeat file, or one orphaned when its state directory was purged, still
/// holds an open handle to the executable and still runs its own scan loop.
/// Matching by image name is blunt, so it deliberately excludes this process
/// and anything that is not our own executable name.
pub fn stop_stragglers() -> (usize, Vec<u32>) {
    let me = std::process::id();
    let mut stopped = 0;
    let mut denied = Vec::new();

    #[cfg(windows)]
    {
        // One CSV listing, then a targeted kill each: /IM would take out this
        // process too, and there is no "except pid" filter.
        let out = util::run(
            "tasklist",
            &["/FI", "IMAGENAME eq polinrider-hunter.exe", "/NH", "/FO", "CSV"],
        );
        for line in out.stdout.lines() {
            // "polinrider-hunter.exe","1234","Console","1","4,712 K"
            let Some(pid) = line
                .split(',')
                .nth(1)
                .map(|f| f.trim_matches(['"', ' ']))
                .and_then(|f| f.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == me {
                continue;
            }
            if end_process(pid) {
                stopped += 1;
            } else {
                denied.push(pid);
            }
        }
    }

    #[cfg(not(windows))]
    {
        // pkill would match this process; -o/--older is not portable, so list
        // and filter. `pgrep -x` matches the executable name exactly.
        let out = util::run("pgrep", &["-x", "polinrider-hunter"]);
        for line in out.stdout.lines() {
            let Ok(pid) = line.trim().parse::<u32>() else {
                continue;
            };
            if pid == me {
                continue;
            }
            if end_process(pid) {
                stopped += 1;
            } else {
                denied.push(pid);
            }
        }
    }

    (stopped, denied)
}

/// Take the install directory back off the user's PATH.
///
/// Windows only, and deliberately: there, PATH is a registry value this process
/// can edit precisely. On Unix it lives in whichever shell profile the person
/// hand-edited, and a program that rewrites someone's `.zshrc` unasked is worse
/// than one that tells them which line to delete.
pub fn remove_from_path(dir: &Path) -> bool {
    #[cfg(windows)]
    {
        let target = dir.to_string_lossy().to_string();
        let script = format!(
            "$p = [Environment]::GetEnvironmentVariable('Path','User'); \
             $keep = ($p -split ';' | Where-Object {{ $_ -and $_.TrimEnd('\\') -ne '{}' }}) -join ';'; \
             if ($keep -ne $p) {{ [Environment]::SetEnvironmentVariable('Path', $keep, 'User'); 'removed' }} else {{ 'absent' }}",
            target.trim_end_matches('\\').replace('\'', "''")
        );
        let out = util::run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        );
        return out.ok && out.stdout.contains("removed");
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        false
    }
}

/// Delete the binary that is currently executing.
///
/// A running executable cannot delete itself on Windows, so a detached helper
/// waits for this process to exit and then removes it. Elsewhere the file can
/// simply be unlinked while it runs.
pub fn remove_self(exe: &Path) -> bool {
    #[cfg(windows)]
    {
        let path = exe.to_string_lossy().to_string();
        let dir = exe.parent().map(|p| p.to_string_lossy().to_string());
        // ping is the portable "sleep" available on every Windows install.
        let mut cmd = format!("ping 127.0.0.1 -n 3 >nul & del /f /q \"{path}\"");
        if let Some(d) = dir {
            // Remove the install directory too, but only if it empties.
            cmd.push_str(&format!(" & rmdir \"{d}\" 2>nul"));
        }
        return util::spawn_detached("cmd", &["/c", &cmd]);
    }
    #[cfg(not(windows))]
    {
        std::fs::remove_file(exe).is_ok()
    }
}

pub fn write_heartbeat() {
    let p = config::heartbeat_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(p, format!("{} {}", std::process::id(), util::now_secs()));
}
