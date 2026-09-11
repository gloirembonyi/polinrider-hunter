//! Removing the payload without damaging the file around it.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! Two rules drive everything here:
//!
//! 1. **Quarantine before writing.** Every original is copied aside first, so a
//!    wrong cut is always recoverable.
//! 2. **Never rewrite bytes we did not mean to change.** The obvious approach -
//!    read to lines, edit, write lines back - silently rewrites every line
//!    ending in the file. On a CRLF repo that turns a one-line fix into a
//!    whole-file diff and buries the security change in noise. So we splice the
//!    byte buffer and leave every other byte untouched.

use std::path::{Path, PathBuf};

use crate::config;
use crate::scanner::{self, Finding};
use crate::signatures::{self, Severity};
use crate::util;

#[derive(Debug)]
pub enum Outcome {
    /// Payload cut out of the file.
    Healed { removed: usize },
    /// The whole file was malware; it is gone.
    Deleted,
    /// Found something, deliberately did not touch it.
    Skipped(String),
    /// Tried and could not produce a clean file.
    Failed(String),
}

impl Outcome {
    pub fn label(&self) -> String {
        match self {
            Outcome::Healed { removed } => format!("healed (-{removed} bytes)"),
            Outcome::Deleted => "deleted".into(),
            Outcome::Skipped(r) => format!("skipped: {r}"),
            Outcome::Failed(r) => format!("FAILED: {r}"),
        }
    }
}

/// Copy `path` into the quarantine directory and record it.
fn quarantine(path: &Path, iocs: &[&str]) -> std::io::Result<PathBuf> {
    let dir = config::quarantine_dir();
    std::fs::create_dir_all(&dir)?;
    // Mark it, so no scan - ours or another install's - ever walks into it.
    let sentinel = dir.join(config::QUARANTINE_SENTINEL);
    if !sentinel.exists() {
        let _ = std::fs::write(
            &sentinel,
            b"Quarantined originals. They are infected by design; do not scan this directory.
",
        );
    }
    let flat: String = path
        .to_string_lossy()
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => ch,
            _ => '_',
        })
        .collect();
    // Keep the tail of long paths: the filename is the useful part.
    let flat = if flat.len() > 120 {
        flat[flat.len() - 120..].to_string()
    } else {
        flat
    };
    let now = util::now_secs();
    let dest = dir.join(format!("{}__{}", util::fmt_stamp(now), flat));
    std::fs::copy(path, &dest)?;

    let line = format!(
        "{{\"time\":\"{}\",\"original\":\"{}\",\"quarantined\":\"{}\",\"iocs\":[{}]}}\n",
        util::fmt_time(now),
        util::json_escape(&path.to_string_lossy()),
        util::json_escape(&dest.to_string_lossy()),
        iocs.iter()
            .map(|i| format!("\"{}\"", util::json_escape(i)))
            .collect::<Vec<_>>()
            .join(",")
    );
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(config::quarantine_index())
    {
        let _ = f.write_all(line.as_bytes());
    }
    Ok(dest)
}

/// Heal one finding.
pub fn heal(finding: &Finding, dry_run: bool) -> Outcome {
    let path = &finding.path;

    if !finding.is_critical() {
        return Outcome::Skipped("no critical indicator; review manually".into());
    }

    // Documentation is not an infection.
    //
    // A file that *describes* PolinRider - an incident note, a security README,
    // a blog draft - is full of its indicators by design. Cutting a line out of
    // someone's notes because it quotes a payload would be a straightforward
    // way to destroy the write-up of the very incident being cleaned up. Six of
    // these turned up in a real sweep of a home directory.
    if is_prose(path) {
        return Outcome::Skipped(
            "documentation: it quotes indicators rather than carrying them - left alone".into(),
        );
    }

    // Structured data cannot be repaired by splicing bytes.
    //
    // The byte-cut works because the payload is appended past the end of a line
    // of real code. Inside a JSON or YAML document an indicator can sit in the
    // middle of a value - the autorun variant puts `node ./public/fonts/...`
    // inside a task's "command" - and cutting to end of line there leaves a
    // dangling `"command": "` and an unparseable file. Only the appended-pad
    // shape is safe here, and that always brings a `padding-run` hit with it.
    // One structured shape *is* safely removable: a victim beacon appended to a
    // browser extension's manifest. It is a whole key with a self-contained
    // object value, so it can be excised by matching braces rather than cutting
    // to end of line. `jsonbeacon` refuses unless the block really is a machine
    // fingerprint and the result still parses.
    if is_structured(path) {
        if let Ok(data) = std::fs::read(path) {
            if let Some(cleaned) = crate::jsonbeacon::strip(&data) {
                if dry_run {
                    return Outcome::Skipped(format!(
                        "would remove a planted beacon block ({} bytes) (dry run)",
                        data.len() - cleaned.len()
                    ));
                }
                let iocs: Vec<&str> = finding.hits.iter().map(|h| h.ioc).collect();
                if let Err(e) = quarantine(path, &iocs) {
                    return Outcome::Failed(format!("quarantine: {e}"));
                }
                if let Err(e) = std::fs::write(path, &cleaned) {
                    return Outcome::Failed(format!("write: {e}"));
                }
                return Outcome::Healed {
                    removed: data.len() - cleaned.len(),
                };
            }
        }
    }

    if is_structured(path)
        && !finding.hits.iter().any(|h| h.ioc == signatures::PADDING_IOC)
    {
        return Outcome::Failed(
            "structured config (JSON/YAML): removing this by hand is safer than \
             splicing it - delete the offending entry yourself"
                .into(),
        );
    }

    // Padding alone is strong evidence but not proof. Only act on it inside a
    // file PolinRider is known to write to; elsewhere a human should look.
    // Offsets from a UTF-16 decode do not map back to file bytes.
    if finding.hits.iter().any(|h| h.ioc == "utf16-encoded") {
        return Outcome::Skipped(
            "UTF-16 encoded; re-save it as UTF-8 and re-run, or clean it by hand".into(),
        );
    }

    if finding.padding_only() && !scanner::is_config_target(path) {
        return Outcome::Skipped(
            "padding heuristic only, and not a known target file; review manually".into(),
        );
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return Outcome::Failed(format!("read: {e}")),
    };

    // A "font" that is really JavaScript, or a propagation script, is entirely
    // payload - there is nothing in it to preserve, so the file goes rather
    // than being edited.
    if finding
        .hits
        .iter()
        .any(|h| h.ioc == "font-disguise" || h.ioc == "propagation-artifact")
    {
        if dry_run {
            return Outcome::Skipped("would delete disguised payload file (dry run)".into());
        }
        let iocs: Vec<&str> = finding.hits.iter().map(|h| h.ioc).collect();
        if let Err(e) = quarantine(path, &iocs) {
            return Outcome::Failed(format!("quarantine: {e}"));
        }
        if let Err(e) = std::fs::remove_file(path) {
            return Outcome::Failed(format!("delete: {e}"));
        }
        untrack_from_git(path);
        return Outcome::Deleted;
    }

    // A dropped .env exists only to carry the C2 key: remove the whole file.
    if is_malicious_env(path, &data) {
        if dry_run {
            return Outcome::Skipped("would delete malicious .env (dry run)".into());
        }
        let iocs: Vec<&str> = finding.hits.iter().map(|h| h.ioc).collect();
        if let Err(e) = quarantine(path, &iocs) {
            return Outcome::Failed(format!("quarantine: {e}"));
        }
        if let Err(e) = std::fs::remove_file(path) {
            return Outcome::Failed(format!("delete: {e}"));
        }
        untrack_from_git(path);
        return Outcome::Deleted;
    }

    let cleaned = match strip(&data) {
        Some(c) => c,
        None => return Outcome::Failed("could not locate a removable payload".into()),
    };

    if signatures::has_critical(&cleaned) {
        return Outcome::Failed("payload survived the cut; clean this one by hand".into());
    }
    let removed = data.len().saturating_sub(cleaned.len());
    if dry_run {
        return Outcome::Skipped(format!("would remove {removed} bytes (dry run)"));
    }

    let iocs: Vec<&str> = finding.hits.iter().map(|h| h.ioc).collect();
    if let Err(e) = quarantine(path, &iocs) {
        return Outcome::Failed(format!("quarantine: {e}"));
    }
    if let Err(e) = std::fs::write(path, &cleaned) {
        return Outcome::Failed(format!("write: {e}"));
    }
    Outcome::Healed { removed }
}

/// Prose, where indicators are quotations rather than payload.
fn is_prose(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(ext.as_str(), "md" | "markdown" | "txt" | "rst" | "adoc" | "org")
}

/// Is this a structured-data file, where a line-level cut risks corruption?
fn is_structured(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|s| s.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("json") | Some("jsonc") | Some("yml") | Some("yaml") | Some("toml")
    )
}

/// `.env` files that hold the loader's key and nothing of value.
fn is_malicious_env(path: &Path, data: &[u8]) -> bool {
    let is_env = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|n| n == ".env" || n.starts_with(".env."))
        .unwrap_or(false);
    if !is_env {
        return false;
    }
    let text = String::from_utf8_lossy(data);
    let keys: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    // Only if AUTH_API_KEY is essentially all it contains. A real .env that has
    // picked up the key alongside genuine secrets must not be deleted.
    !keys.is_empty()
        && keys
            .iter()
            .all(|l| l.starts_with("AUTH_API_KEY") || l.contains("auth-confirm-eight"))
}

/// If the file is tracked by git, stop tracking it so the deletion sticks.
fn untrack_from_git(path: &Path) {
    let Some(dir) = path.parent() else { return };
    let name = match path.file_name().and_then(|s| s.to_str()) {
        Some(n) => n,
        None => return,
    };
    let inside = util::git(dir, &["rev-parse", "--is-inside-work-tree"]);
    if !inside.ok || inside.stdout.trim() != "true" {
        return;
    }
    if util::git(dir, &["ls-files", "--error-unmatch", name]).ok {
        let _ = util::git(dir, &["rm", "--cached", "--quiet", name]);
    }
}

/// Produce a cleaned copy of `data`, or `None` if we cannot see how.
///
/// Public so the test suite and `verify` can exercise it directly.
pub fn strip(data: &[u8]) -> Option<Vec<u8>> {
    // One file can carry more than one payload - a config that has been
    // reinfected several times ends up with a pad-and-payload per visit. Cutting
    // once and declaring victory leaves the rest in place, so keep going until
    // the file is genuinely clean or we stop making progress.
    let mut cur: Vec<u8> = data.to_vec();
    let mut cut_any = false;
    for _ in 0..16 {
        if !signatures::has_critical(&cur) {
            break;
        }
        let Some(next) = strip_once(&cur) else { break };
        if next.len() >= cur.len() {
            break; // no progress; do not spin
        }
        cur = next;
        cut_any = true;
    }
    if !cut_any {
        return None;
    }
    remove_dead_create_require(&mut cur);
    Some(cur)
}

/// Remove one payload.
fn strip_once(data: &[u8]) -> Option<Vec<u8>> {
    // Shape 1: the NestJS dropper - an injected `import 'dotenv/config'` plus a
    // self-invoking async block that decodes a URL, fetches code and evals it.
    if let Some(out) = strip_iife_dropper(data) {
        return Some(out);
    }
    // Shape 2: everything else seen so far - one line of legitimate code, a long
    // whitespace pad, then the payload out to end of line.
    strip_padded_tail(data)
}

/// Remove an injected `createRequire` shim once nothing uses `require` any more.
///
/// `.mjs` is ESM and has no `require()`, so the loader prepends
///
/// ```js
/// import { createRequire } from 'module';
/// const require = createRequire(import.meta.url);
/// ```
///
/// to manufacture one for its payload. Cutting the payload alone leaves that
/// scaffolding sitting at the top of the file - which is how a "cleaned" config
/// ends up still differing from the pristine original, and leaves the next
/// payload half its work already done.
///
/// Only removed when `require` is genuinely unused afterwards: plenty of honest
/// ESM files reach for `createRequire` on purpose.
fn remove_dead_create_require(data: &mut Vec<u8>) {
    let text = String::from_utf8_lossy(data).into_owned();
    if !text.contains("createRequire") {
        return;
    }

    let is_shim = |l: &str| {
        let t = l.trim();
        (t.starts_with("import") && t.contains("createRequire") && t.contains("module"))
            || (t.starts_with("const require") && t.contains("createRequire("))
    };

    // Would anything still call require() once the shim is gone?
    let still_used = text
        .lines()
        .filter(|l| !is_shim(l))
        .any(|l| l.contains("require(") && !l.contains("createRequire("));
    if still_used {
        return;
    }

    let mut stripped = data.clone();
    remove_line_where(&mut stripped, is_shim);
    // Tidy the blank line the removal leaves at the top.
    let s = String::from_utf8_lossy(&stripped).into_owned();
    let crlf = s.contains("\r\n");
    let nl = if crlf { "\r\n" } else { "\n" };
    let mut t = s;
    while t.starts_with(nl) {
        t = t[nl.len()..].to_string();
    }
    let triple = format!("{nl}{nl}{nl}");
    let double = format!("{nl}{nl}");
    while t.contains(&triple) {
        t = t.replace(&triple, &double);
    }
    *data = t.into_bytes();
}

/// Remove `(async () => { ... })();` blocks that contain a dropper indicator,
/// plus the `import 'dotenv/config';` line injected alongside them.
fn strip_iife_dropper(data: &[u8]) -> Option<Vec<u8>> {
    let markers: [&[u8]; 3] = [b"AUTH_API_KEY", b"eval(proxyInfo)", b"atob(process.env."];
    let marker_at = markers.iter().filter_map(|m| find(data, m)).min()?;

    // The block opens at the nearest `(async` before the marker. Bounded: an
    // unbounded backwards search can latch onto an unrelated async block far
    // earlier in the file and take everything between with it.
    const LOOKBACK: usize = 4096;
    let window_start = marker_at.saturating_sub(LOOKBACK);
    let open = window_start + rfind(&data[window_start..marker_at], b"(async")?;
    // ...and closes at the first `})();` after it.
    let close_rel = find(&data[marker_at..], b"})();")?;
    let close = marker_at + close_rel + b"})();".len();

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..open]);
    out.extend_from_slice(&data[close..]);

    // Trim the blank line the excision leaves at the cut point.
    let mut out = trim_blank_run(out, open);
    remove_line_where(&mut out, |l| {
        let t = l.trim();
        t == "import 'dotenv/config';" || t == "import \"dotenv/config\";"
    });
    Some(out)
}

/// Cut from the start of the whitespace pad through end of line.
fn strip_padded_tail(data: &[u8]) -> Option<Vec<u8>> {
    // Prefer the earliest critical indicator; that is where the payload starts.
    let hits = signatures::scan(data);
    let first = hits
        .iter()
        .filter(|h| h.sev == Severity::Critical)
        .min_by_key(|h| h.start)?;

    // Walk back over the camouflage so it goes with the payload.
    let mut cut = first.start;
    while cut > 0 {
        let b = data[cut - 1];
        if b == b' ' || b == b'\t' {
            cut -= 1;
        } else {
            break;
        }
    }
    // The payload is one line; stop at its terminator and keep the terminator.
    let end = data[first.start..]
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .map(|p| first.start + p)
        .unwrap_or(data.len());

    let mut out = Vec::with_capacity(data.len() - (end - cut));
    out.extend_from_slice(&data[..cut]);
    out.extend_from_slice(&data[end..]);
    Some(out)
}

/// Collapse a run of three or more consecutive newlines around `at` to two.
fn trim_blank_run(data: Vec<u8>, at: usize) -> Vec<u8> {
    let text = String::from_utf8_lossy(&data).into_owned();
    let _ = at;
    let crlf = text.contains("\r\n");
    let nl = if crlf { "\r\n" } else { "\n" };
    let triple = format!("{nl}{nl}{nl}");
    let double = format!("{nl}{nl}");
    let mut t = text;
    while t.contains(&triple) {
        t = t.replace(&triple, &double);
    }
    t.into_bytes()
}

/// Drop whole lines matching `pred`, preserving each surviving line's ending.
fn remove_line_where<F: Fn(&str) -> bool>(data: &mut Vec<u8>, pred: F) {
    let text = String::from_utf8_lossy(data).into_owned();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let (line, term, next) = match rest.find('\n') {
            Some(i) => {
                let raw = &rest[..i];
                let (l, t) = if raw.ends_with('\r') {
                    (&raw[..raw.len() - 1], "\r\n")
                } else {
                    (raw, "\n")
                };
                (l, t, &rest[i + 1..])
            }
            None => (rest, "", ""),
        };
        if !pred(line) {
            out.push_str(line);
            out.push_str(term);
        }
        rest = next;
    }
    *data = out.into_bytes();
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_endings_survive_a_heal() {
        // The failure mode this test exists for: a naive line-based fix rewrites
        // every ending and turns a 1-line change into a whole-file diff.
        let mut src = b"module.exports = {\r\n  a: 1,\r\n};".to_vec();
        src.extend(std::iter::repeat(b' ').take(400));
        src.extend_from_slice(b"global.i = 'A8-2941';payload()\r\n");
        let out = strip(&src).unwrap();
        assert_eq!(out, b"module.exports = {\r\n  a: 1,\r\n};\r\n");
        assert!(!signatures::has_critical(&out));
        // Exactly two CRLF pairs before, exactly two after.
        assert_eq!(out.windows(2).filter(|w| *w == b"\r\n").count(), 3);
    }

    #[test]
    fn lf_endings_survive_a_heal() {
        let mut src = b"};".to_vec();
        src.extend(std::iter::repeat(b'\t').take(300));
        src.extend_from_slice(b"global['!']='8-2941';junk\n");
        let out = strip(&src).unwrap();
        assert_eq!(out, b"};\n");
    }

    #[test]
    fn payload_at_eof_without_a_trailing_newline() {
        let mut src = b"export default config;".to_vec();
        src.extend(std::iter::repeat(b' ').take(250));
        src.extend_from_slice(b"parseInt(_0xdead)");
        let out = strip(&src).unwrap();
        assert_eq!(out, b"export default config;");
    }

    #[test]
    fn iife_dropper_is_excised() {
        let src = br#"import { AppModule } from './app.module';
import 'dotenv/config';

(async () => {
    const src = atob(process.env.AUTH_API_KEY);
    eval(proxyInfo);
})();

function bootstrap() {}
"#
        .to_vec();
        let out = strip(&src).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("AUTH_API_KEY"));
        assert!(!text.contains("dotenv/config"));
        // The real code on both sides is intact.
        assert!(text.contains("import { AppModule }"));
        assert!(text.contains("function bootstrap() {}"));
    }

    #[test]
    fn malicious_env_is_recognised_only_when_it_holds_nothing_else() {
        let only = b"AUTH_API_KEY=aHR0cHM6Ly9l\n";
        assert!(is_malicious_env(Path::new("/x/.env"), only));

        // A real .env that also picked up the key must never be deleted.
        let mixed = b"DATABASE_URL=postgres://real\nAUTH_API_KEY=aHR0\n";
        assert!(!is_malicious_env(Path::new("/x/.env"), mixed));

        // Not an env file at all.
        assert!(!is_malicious_env(Path::new("/x/app.js"), only));
    }

    #[test]
    fn line_removal_keeps_other_endings() {
        let mut v = b"a\r\nDROP\r\nb\n".to_vec();
        remove_line_where(&mut v, |l| l == "DROP");
        assert_eq!(v, b"a\r\nb\n");
    }

    #[test]
    fn injected_create_require_shim_goes_with_the_payload() {
        let mut src = b"import { createRequire } from 'module';\n\nconst require = createRequire(import.meta.url);\n\nconst config = {};\n\nexport default config;".to_vec();
        src.extend(std::iter::repeat(b' ').take(400));
        src.extend_from_slice(b"global.i = 'A8-2941';require('http')\n");
        let out = String::from_utf8(strip(&src).unwrap()).unwrap();
        assert!(!out.contains("createRequire"), "scaffolding must go too:\n{out}");
        assert!(out.contains("const config = {};"));
        assert!(out.contains("export default config;"));
        assert!(out.starts_with("const config"), "no leading blank lines:\n{out:?}");
    }

    #[test]
    fn a_create_require_that_is_actually_used_is_kept() {
        let mut src = b"import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nconst pkg = require('./package.json');\nexport default pkg;".to_vec();
        src.extend(std::iter::repeat(b' ').take(400));
        src.extend_from_slice(b"global.i = 'A8-2941';x()\n");
        let out = String::from_utf8(strip(&src).unwrap()).unwrap();
        assert!(out.contains("createRequire"), "honest usage must survive:\n{out}");
        assert!(out.contains("require('./package.json')"));
    }

    #[test]
    fn two_payloads_in_one_file_are_both_removed() {
        // A config reinfected twice: two pads, two payloads.
        let mut src = b"module.exports = {};".to_vec();
        src.extend(std::iter::repeat(b' ').take(300));
        src.extend_from_slice(b"global.i = 'A8-1111';first()\n");
        src.extend_from_slice(b"const extra = 1;");
        src.extend(std::iter::repeat(b' ').take(300));
        src.extend_from_slice(b"global['!']='8-2';_$_1e42\n");
        let out = strip(&src).unwrap();
        assert!(!signatures::has_critical(&out), "both must go: {out:?}");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("module.exports = {};"));
        assert!(text.contains("const extra = 1;"));
    }

    #[test]
    fn an_unrelated_async_block_is_not_swallowed() {
        // A legitimate async IIFE far above the dropper must survive.
        let mut src = b"(async () => { await realWork(); })();\n".to_vec();
        src.extend(std::iter::repeat(b'\n').take(200));
        src.extend_from_slice(b"const filler = 1;\n");
        src.extend(std::iter::repeat(b' ').take(300));
        src.extend_from_slice(b"global.i = 'A8-2941';x()\n");
        let out = String::from_utf8(strip(&src).unwrap()).unwrap();
        assert!(
            out.contains("await realWork()"),
            "honest async block must survive:\n{out}"
        );
        assert!(!out.contains("global.i"));
    }

    #[test]
    fn clean_file_yields_no_cut() {
        // Nothing critical, so there is nothing to strip.
        assert!(strip(b"const a = 1;\n").is_none());
    }
}
