//! The monitor: a live view of what the guard is doing.
//!
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! This lives in the binary rather than in a script beside it, because the
//! person who most needs it is the one who ran a one-line installer and has no
//! copy of this repository - `python tools/monitor.py` is useless to them. Both
//! views read the same state the guard writes: nothing here is fabricated, and
//! nothing here writes.
//!
//! The web view is a plain `TcpListener` speaking the smallest useful subset of
//! HTTP/1.1. That is a deliberate trade against pulling in a web framework: it
//! serves exactly two routes to exactly one host, and everything it does is
//! visible in one screen of code.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;

use crate::config::{self, Config};
use crate::service;
use crate::util::{self, BOLD, DIM, GREEN, RED, YELLOW};

/// One parsed line of the guard's log.
pub struct Event {
    pub time: String,
    pub kind: &'static str,
    pub detail: String,
    pub iocs: String,
    pub ok: bool,
}

pub struct Snapshot {
    pub generated: String,
    pub home: PathBuf,
    pub running: bool,
    pub pid: Option<u32>,
    pub beat_age: Option<u64>,
    pub cfg_interval: u64,
    pub cfg_full: u64,
    pub cfg_git: u64,
    pub auto_heal: bool,
    pub notify: bool,
    pub kill_procs: bool,
    pub paths: Vec<PathBuf>,
    pub cleaned: usize,
    pub review: usize,
    pub procs_stopped: usize,
    pub quarantined: usize,
    pub events: Vec<Event>,
}

/// Read everything the guard has written down.
pub fn snapshot(cfg: &Config) -> Snapshot {
    let pid = service::daemon_pid();
    let beat_age = service::daemon_alive(cfg.interval);
    let events = read_events(200);

    let cleaned = events.iter().filter(|e| e.kind == "detect" && e.ok).count();
    let review = events
        .iter()
        .filter(|e| (e.kind == "detect" && !e.ok) || e.kind == "notice")
        .count();
    let procs_stopped = events
        .iter()
        .filter(|e| e.kind == "process" && e.detail.contains("killed"))
        .count();

    // Count the index rather than the directory: the directory also holds the
    // sentinel, and a stale file with no index line is not a record of anything.
    let quarantined = std::fs::read_to_string(config::quarantine_index())
        .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);

    Snapshot {
        generated: util::fmt_time(util::now_secs()),
        home: config::home(),
        running: beat_age.is_some(),
        pid,
        beat_age,
        cfg_interval: cfg.interval,
        cfg_full: cfg.full_interval,
        cfg_git: cfg.git_interval,
        auto_heal: cfg.auto_heal,
        notify: cfg.notify,
        kill_procs: cfg.kill_procs,
        paths: cfg.paths.clone(),
        cleaned,
        review,
        procs_stopped,
        quarantined,
        events,
    }
}

/// Parse the tail of the log into events.
fn read_events(limit: usize) -> Vec<Event> {
    let path = config::log_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        // "YYYY-MM-DD HH:MM:SSZ <body>"
        let Some((when, body)) = line.split_once("Z ") else {
            continue;
        };
        let body = body.trim();
        let (kind, detail, iocs, ok) = if let Some(rest) = body.strip_prefix("DETECT ") {
            let (path_part, tail) = rest.split_once(" [").unwrap_or((rest, ""));
            let (iocs, outcome) = tail.split_once("] -> ").unwrap_or((tail, ""));
            let ok = outcome.contains("healed") || outcome.contains("deleted");
            (
                "detect",
                format!("{path_part}  {outcome}"),
                iocs.to_string(),
                ok,
            )
        } else if let Some(rest) = body.strip_prefix("NOTICE ") {
            let (path_part, tail) = rest.split_once(" [").unwrap_or((rest, ""));
            ("notice", path_part.to_string(), tail.trim_end_matches(']').to_string(), false)
        } else if let Some(rest) = body.strip_prefix("PROC ") {
            ("process", rest.to_string(), String::new(), false)
        } else if let Some(rest) = body.strip_prefix("REF ") {
            ("ref", rest.to_string(), String::new(), false)
        } else {
            ("info", body.to_string(), String::new(), true)
        };
        out.push(Event {
            time: when.to_string(),
            kind,
            detail,
            iocs,
            ok,
        });
    }
    if out.len() > limit {
        out.drain(..out.len() - limit);
    }
    out
}

fn human_age(s: Option<u64>) -> String {
    match s {
        None => "never".into(),
        Some(s) if s < 60 => format!("{s}s ago"),
        Some(s) if s < 3600 => format!("{}m ago", s / 60),
        Some(s) => format!("{}h ago", s / 3600),
    }
}

// ---------------------------------------------------------------------------
// Terminal view
// ---------------------------------------------------------------------------

pub fn render(snap: &Snapshot) -> String {
    let mut o = String::new();
    let rule = "-".repeat(78);

    o.push_str(&format!("{}\n", util::c(BOLD, "polinrider-hunter monitor")));
    o.push_str(&format!("{}\n", util::c(DIM, &rule)));

    if snap.running {
        let mut bits = Vec::new();
        if let Some(p) = snap.pid {
            bits.push(format!("pid {p}"));
        }
        bits.push(format!("beat {}", human_age(snap.beat_age)));
        o.push_str(&format!(
            "  guard      {}  {}\n",
            util::c(GREEN, "RUNNING"),
            util::c(DIM, &bits.join(", "))
        ));
    } else {
        o.push_str(&format!(
            "  guard      {}  {}\n",
            util::c(RED, "NOT RUNNING"),
            util::c(DIM, "start it with: polinrider-hunter install")
        ));
    }
    o.push_str(&format!(
        "  cadence    {}\n",
        util::c(
            DIM,
            &format!(
                "quick {}s / full {}s / git {}s",
                snap.cfg_interval, snap.cfg_full, snap.cfg_git
            )
        )
    ));
    o.push_str(&format!(
        "  settings   {}\n",
        util::c(
            DIM,
            &format!(
                "auto-heal {} - notify {} - stop processes {}",
                onoff(snap.auto_heal),
                onoff(snap.notify),
                onoff(snap.kill_procs)
            )
        )
    ));
    o.push_str(&format!("  watching   {} path(s)\n", snap.paths.len()));
    for p in snap.paths.iter().take(10) {
        o.push_str(&format!("{}\n", util::c(DIM, &format!("               {}", p.display()))));
    }
    if snap.paths.len() > 10 {
        o.push_str(&format!(
            "{}\n",
            util::c(DIM, &format!("               ... and {} more", snap.paths.len() - 10))
        ));
    }

    o.push('\n');
    o.push_str(&format!(
        "  {}   {}   {}   {}\n",
        util::c(GREEN, &format!("{} cleaned", snap.cleaned)),
        util::c(YELLOW, &format!("{} need review", snap.review)),
        util::c(RED, &format!("{} processes stopped", snap.procs_stopped)),
        util::c(DIM, &format!("{} quarantined", snap.quarantined)),
    ));
    o.push_str(&format!("{}\n", util::c(DIM, &rule)));

    o.push_str(&format!("{}\n", util::c(BOLD, "  Recent activity")));
    let interesting: Vec<&Event> = snap
        .events
        .iter()
        .filter(|e| e.kind != "info")
        .rev()
        .take(12)
        .collect();
    if interesting.is_empty() {
        o.push_str(&format!(
            "{}\n",
            util::c(DIM, "    nothing yet - a quiet log is the good outcome")
        ));
    }
    for e in interesting.into_iter().rev() {
        let tag = match (e.kind, e.ok) {
            ("detect", true) => util::c(GREEN, "CLEANED "),
            ("detect", false) => util::c(RED, "FAILED  "),
            ("notice", _) => util::c(YELLOW, "REVIEW  "),
            ("process", _) => util::c(RED, "PROCESS "),
            _ => util::c(BLUE_ISH, "BRANCH  "),
        };
        o.push_str(&format!(
            "    {}  {} {}\n",
            util::c(DIM, &e.time[5..16]),
            tag,
            shorten(&e.detail, 52)
        ));
        if !e.iocs.is_empty() {
            o.push_str(&format!("{}\n", util::c(DIM, &format!("                        {}", e.iocs))));
        }
    }
    o.push_str(&format!("{}\n", util::c(DIM, &rule)));
    o.push_str(&format!(
        "{}\n",
        util::c(DIM, &format!("  state: {}", snap.home.display()))
    ));
    o.push_str(&format!("{}\n", util::c(DIM, &format!("  {}", snap.generated))));
    o
}

const BLUE_ISH: &str = "\x1b[35m";

fn onoff(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "OFF"
    }
}

fn shorten(s: &str, limit: usize) -> String {
    let n = s.chars().count();
    if n <= limit {
        return s.to_string();
    }
    let tail: String = s.chars().skip(n - limit + 1).collect();
    format!("…{tail}")
}

/// Redraw in place until interrupted.
pub fn watch(cfg: &Config, interval_secs: u64) -> i32 {
    loop {
        let snap = snapshot(cfg);
        // Home the cursor and clear forward: no flicker, scrollback survives.
        print!("\x1b[H\x1b[J{}", render(&snap));
        println!("{}", util::c(DIM, "  Ctrl+C to stop"));
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_secs(interval_secs.max(1)));
    }
}

// ---------------------------------------------------------------------------
// Web view
// ---------------------------------------------------------------------------

/// The snapshot as JSON, for scripting.
pub fn json_snapshot(cfg: &Config) -> String {
    json(&snapshot(cfg))
}

fn json(snap: &Snapshot) -> String {
    let events: Vec<String> = snap
        .events
        .iter()
        .filter(|e| e.kind != "info")
        .rev()
        .take(50)
        .map(|e| {
            format!(
                r#"{{"time":"{}","kind":"{}","ok":{},"detail":"{}","iocs":"{}"}}"#,
                util::json_escape(&e.time),
                e.kind,
                e.ok,
                util::json_escape(&e.detail),
                util::json_escape(&e.iocs)
            )
        })
        .collect();
    let paths: Vec<String> = snap
        .paths
        .iter()
        .map(|p| format!("\"{}\"", util::json_escape(&p.to_string_lossy())))
        .collect();
    format!(
        r#"{{"generated":"{}","home":"{}","guard":{{"running":{},"pid":{},"beat_age":{}}},
"config":{{"interval":{},"full":{},"git":{},"auto_heal":{},"notify":{},"kill_procs":{},"paths":[{}]}},
"counts":{{"cleaned":{},"review":{},"processes_stopped":{},"quarantined":{}}},
"events":[{}]}}"#,
        util::json_escape(&snap.generated),
        util::json_escape(&snap.home.to_string_lossy()),
        snap.running,
        snap.pid.map(|p| p.to_string()).unwrap_or_else(|| "null".into()),
        snap.beat_age.map(|a| a.to_string()).unwrap_or_else(|| "null".into()),
        snap.cfg_interval,
        snap.cfg_full,
        snap.cfg_git,
        snap.auto_heal,
        snap.notify,
        snap.kill_procs,
        paths.join(","),
        snap.cleaned,
        snap.review,
        snap.procs_stopped,
        snap.quarantined,
        events.join(",")
    )
}

const PAGE: &str = include_str!("monitor.html");

fn respond(mut stream: TcpStream, cfg: &Config) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    // "GET /path HTTP/1.1"
    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
    // Drain headers so the client does not see a reset before we reply.
    for line in reader.lines() {
        match line {
            Ok(l) if l.is_empty() => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    let (status, ctype, body) = match path.split('?').next().unwrap_or("/") {
        "/api/state" => (
            "200 OK",
            "application/json",
            json(&snapshot(cfg)),
        ),
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", PAGE.to_string()),
        _ => ("404 Not Found", "text/plain", "not found".to_string()),
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// Serve the dashboard on localhost. Blocks until interrupted.
pub fn serve(cfg: &Config, port: u16) -> i32 {
    // 127.0.0.1 and nothing else. This page lists where malware was found on
    // this disk; it has no business being reachable from the network.
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "{}",
                util::c(RED, &format!("could not listen on 127.0.0.1:{port}: {e}"))
            );
            eprintln!("  try another port: polinrider-hunter monitor --web --port 8899");
            return 1;
        }
    };
    println!(
        "{} {}",
        util::c(BOLD, "monitor:"),
        util::c(GREEN, &format!("http://127.0.0.1:{port}"))
    );
    println!(
        "{}",
        util::c(
            DIM,
            "  open that in a browser - it refreshes itself every 5 seconds\n  \
             bound to localhost only, and read-only. Ctrl+C to stop."
        )
    );
    for stream in listener.incoming() {
        match stream {
            Ok(s) => respond(s, cfg),
            Err(_) => continue,
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_lines_parse_into_events() {
        // Exactly the shape the guard writes.
        let line = "2026-09-09 13:38:57Z DETECT C:\\x\\tailwind.config.js [padding-run,campaign-id] -> healed (-746 bytes)";
        let (when, body) = line.split_once("Z ").unwrap();
        assert_eq!(when, "2026-09-09 13:38:57");
        assert!(body.starts_with("DETECT "));
    }

    #[test]
    fn shorten_keeps_the_end_of_a_path() {
        let s = shorten("/very/long/path/to/a/file/postcss.config.mjs", 20);
        assert!(s.ends_with("postcss.config.mjs"));
        assert!(s.chars().count() <= 20);
    }

    #[test]
    fn short_strings_are_untouched() {
        assert_eq!(shorten("abc", 20), "abc");
    }

    #[test]
    fn age_reads_naturally() {
        assert_eq!(human_age(None), "never");
        assert_eq!(human_age(Some(5)), "5s ago");
        assert_eq!(human_age(Some(120)), "2m ago");
        assert_eq!(human_age(Some(7200)), "2h ago");
    }
}
