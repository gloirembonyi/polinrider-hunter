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

/// Is a daemon alive? Judged by heartbeat freshness, which needs no platform
/// process API and cannot be fooled by PID reuse.
pub fn daemon_alive(interval: u64) -> Option<u64> {
    let text = std::fs::read_to_string(config::heartbeat_path()).ok()?;
    let beat: u64 = text.trim().split_whitespace().last()?.parse().ok()?;
    let age = util::now_secs().saturating_sub(beat);
    // Allow three missed beats before calling it dead.
    if age <= interval.saturating_mul(3).max(90) {
        Some(age)
    } else {
        None
    }
}

pub fn write_heartbeat() {
    let p = config::heartbeat_path();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(p, format!("{} {}", std::process::id(), util::now_secs()));
}
