//! Walking the filesystem and deciding what to read.
//!
//! The interesting problem here is not detection, it is *not* flagging the
//! detectors. Malware scanners, CI gates and this program all necessarily
//! contain the strings they hunt for. Any file carrying `DETECTOR_MARKER` is
//! skipped, which lets a project opt its own gate out explicitly rather than us
//! maintaining a list of everybody's filenames.

use std::path::{Path, PathBuf};

use crate::signatures::{self, Hit, Severity};

/// Put this token in a file that legitimately contains malware signatures and
/// the hunter will leave it alone.
pub const DETECTOR_MARKER: &str = "POLINRIDER-HUNTER-DETECTOR";

/// Directories that never contain source worth scanning, or that are so large
/// that walking them would dominate runtime.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".expo",
    ".turbo",
    ".cache",
    "target",
    "vendor",
    "__pycache__",
    "venv",
    ".venv",
    "env",
    ".gradle",
    "Pods",
    ".terraform",
    "coverage",
    ".svelte-kit",
];

/// Directories that belong to the operating system or another vendor, which a
/// machine-wide hunt must not spend hours walking. PolinRider lives in project
/// trees; none of these are project trees.
const SKIP_SYSTEM_DIRS: &[&str] = &[
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "$Recycle.Bin",
    "System Volume Information",
    "WindowsApps",
    "Microsoft",
    "MicrosoftEdge",
    "OneDrive",
    "Packages",
    "CrashDumps",
    "WebCache",
    "INetCache",
    "GPUCache",
    "Code Cache",
    "ShaderCache",
    "Service Worker",
    "IndexedDB",
    "Local Storage",
    "workspaceStorage",
    "globalStorage",
    "CachedExtensionVSIXs",
    "logs",
    "Crashpad",
    "proc",
    "sys",
    "dev",
    "snap",
    "Library",
    // Package and toolchain caches. Enormous, not project code, and a hunt that
    // walks a Rust registry or an npm cache takes hours instead of minutes.
    ".cargo",
    ".rustup",
    ".npm",
    ".nuget",
    ".m2",
    ".gem",
    ".pub-cache",
    ".deno",
    ".bun",
    ".android",
    ".docker",
    ".conda",
    ".pyenv",
    ".nvm",
    ".rbenv",
    ".stack",
    ".ivy2",
    ".sbt",
];

/// Is this directory a quarantine - ours, another install's, or a test's?
///
/// Cheap: one `exists()` per directory entered, which is nothing next to
/// reading the files inside it.
pub fn is_quarantine(dir: &Path) -> bool {
    dir.join(crate::config::QUARANTINE_SENTINEL).exists()
}

/// Is this path inside our own state directory?
///
/// The quarantine holds the *originals* of what we removed, so every file in it
/// still matches. Scanning it means healing a quarantined copy, quarantining a
/// copy of that first, and doing it again next pass - which is exactly what
/// happened: 6,561 files, each a slightly longer filename than the last, until
/// somebody looked. Nothing under the state directory is ever a target.
pub fn is_own_state(path: &Path) -> bool {
    use std::sync::OnceLock;
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    let home = HOME.get_or_init(crate::config::home);
    path.starts_with(home)
}

/// Should the walker skip a directory with this name?
pub fn skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name) || SKIP_SYSTEM_DIRS.contains(&name)
}

/// Was the read refused only because something else has the file open?
///
/// Distinguished from a genuine denial by the operating system's own code:
/// a sharing or lock violation means "busy", where access-denied and the
/// antivirus refusal mean "you may not look at this", which is worth saying.
fn is_merely_in_use(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
        return matches!(e.raw_os_error(), Some(32) | Some(33));
    }
    #[cfg(not(windows))]
    {
        // POSIX has no equivalent refusal: a file being open elsewhere does not
        // stop us reading it. EAGAIN on a mandatory lock is the nearest thing.
        return e.kind() == std::io::ErrorKind::WouldBlock;
    }
}

/// Files whose presence is itself the finding.
///
/// `temp_auto_push.bat` is the propagation script: it reads the last commit's
/// metadata, moves the system clock back to match it, amends the commit with
/// `--no-verify` and force-pushes, so the poisoned tree keeps its original
/// author and timestamp. It was found in 101 victim repositories with no false
/// positives, which makes the filename alone a better signal than anything in
/// its contents. `spellright.dict` is another binary-looking payload carrier.
///
/// `temp_interactive_push.bat` is the same propagation script with a prompt in
/// front of it, and `branch_structure.json` is the manifest it writes to decide
/// which branches to poison - attacker bookkeeping that no honest project has.
/// Both were seen alongside `temp_auto_push.bat` in the same incident, and the
/// originals are quarantined before removal, so a mistaken match stays
/// recoverable via `quarantine`.
const ARTIFACT_NAMES: &[&str] = &[
    "temp_auto_push.bat",
    "temp_interactive_push.bat",
    "branch_structure.json",
    "config.bat",
    "spellright.dict",
];

/// Fixed filenames the AppData loader campaign drops. Each is a shim or stage
/// that is nothing but malware, so - like the propagation artefacts above - the
/// name alone is the finding, and the whole file is removed. `NativeImageGen`
/// has no extension (it rides a renamed pythonw), so name-matching is the only
/// way it is ever read at all. The random per-victim loader (`tg14xq.js` on the
/// machine this was found on) is caught by its contents, not this list.
const LOADER_ARTIFACT_NAMES: &[&str] = &[
    "clr_init.vbs",
    "clr_task.xml",
    "VSCodeUpdater.vbs",
    "NativeImageGen",
    // The npm-loader variant: a scheduled-task definition and its `npx -y
    // runtimedev-link` shim, dropped under ~/.local/share/runtimedev-link.
    "runtimedev-link.task.xml",
    // Shai-Hulud v2's bootstrap pair.
    "setup_bun.js",
    "bun_environment.js",
];

/// npm packages that are malware by name. A copy in the npx cache or the global
/// modules directory is an infection waiting to be re-run.
pub const MALICIOUS_PACKAGES: &[&str] = &[
    "runtimedev-link",
    "tailwindcss-style-animate",
    "tailwind-mainanimation",
    "tailwind-autoanimation",
    "tailwindcss-typography-style",
    "tailwindcss-style-modify",
    "tailwindcss-animate-style",
];

/// Data files that should never contain executable code.
const DISGUISE_EXTS: &[&str] = &["woff2", "woff", "ttf", "otf", "eot", "dict", "dat", "bin"];

/// Known third-party malware gates. They contain signatures by design.
const KNOWN_DETECTORS: &[&str] = &[
    "check-malware.ps1",
    "check-malware.mjs",
    "check-malware.js",
    "security-malware-scan.yml",
    "scan-supply-chain.mjs",
    "pre-commit",
    "pre-push",
];

/// The files PolinRider actually writes to. The daemon's quick pass looks only
/// at these, which keeps a 30-second loop essentially free.
pub const CONFIG_TARGETS: &[&str] = &[
    "postcss.config.js",
    "postcss.config.mjs",
    "postcss.config.cjs",
    "postcss.config.ts",
    "tailwind.config.js",
    "tailwind.config.mjs",
    "tailwind.config.cjs",
    "tailwind.config.ts",
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
    "vite.config.js",
    "vite.config.ts",
    "vite.config.mjs",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "metro.config.js",
    "babel.config.js",
    // Every build config the campaign has been seen appending to.
    "webpack.config.js",
    "webpack.config.mjs",
    "webpack.config.cjs",
    "webpack.config.ts",
    "rollup.config.js",
    "rollup.config.mjs",
    "svelte.config.js",
    "astro.config.mjs",
    "astro.config.js",
    "astro.config.ts",
    "nuxt.config.js",
    "nuxt.config.ts",
    "vue.config.js",
    "gridsome.config.js",
    "gatsby-config.js",
    "remix.config.js",
    "craco.config.js",
    "truffle.js",
    "truffle-config.js",
    "eslint.config.ts",
    "App.js",
    "src/App.js",
    "app.config.js",
    "app.config.ts",
    "nest-cli.json",
    "package.json",
    "Dockerfile",
    "index.js",
    ".vscode/tasks.json",
    ".vscode/settings.json",
    "src/main.ts",
    "src/bootstrap-env.ts",
    "frontend/postcss.config.mjs",
    "frontend/tailwind.config.js",
    ".env",
];

/// Extensions worth reading during a full scan. Anything else is skipped, which
/// is what keeps a full sweep of a developer home directory tolerable.
const SCAN_EXTS: &[&str] = &[
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "json", "jsonc", "yml", "yaml", "toml",
    "sh", "bash", "ps1", "psm1", "bat", "cmd", "vbs", "py", "rb", "php", "vue", "svelte", "env",
    // `xml` is here for the loader campaign's scheduled-task definition
    // (`clr_task.xml`), which launches a .vbs shim; without it the task file is
    // never read.
    "config", "lock", "md", "xml",
    // Editor extensions (GlassWorm) ship as plain .js, already covered; their
    // manifests and the VSIX unpack directory are read for the same reason.
    "mjs", "vsixmanifest",
];

/// Hooks and other extensionless scripts that Git or an editor executes.
fn is_extensionless_script(path: &Path) -> bool {
    if path.extension().is_some() {
        return false;
    }
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("");
    matches!(parent, "hooks" | ".husky" | "_" | "bin" | ".githooks")
}

/// Font extensions. PolinRider's autorun variant drops its payload as
/// `public/fonts/fa-solid-400.woff2` and runs it with `node`, betting that
/// nobody opens a webfont in a text editor.
/// Is this a file whose very name means compromise?
pub fn is_artifact(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|n| ARTIFACT_NAMES.iter().any(|a| a.eq_ignore_ascii_case(n)))
        .unwrap_or(false)
}

/// Is this one of the AppData loader campaign's fixed-name shims/stages?
pub fn is_loader_artifact(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|n| LOADER_ARTIFACT_NAMES.iter().any(|a| a.eq_ignore_ascii_case(n)))
        .unwrap_or(false)
}

/// Magic bytes a genuine font begins with.
const FONT_MAGIC: &[&[u8]] = &[
    b"wOF2",           // woff2
    b"wOFF",           // woff
    b"\x00\x01\x00\x00", // truetype
    b"true",
    b"ttcf",
    b"OTTO",           // opentype
];

/// A font that is not a font.
///
/// Cheap and very hard to evade: the payload has to be valid JavaScript for
/// `node` to run it, and valid JavaScript cannot also start with a font's magic
/// bytes. Checking the signature rather than the extension is the whole point.
fn disguised_font(path: &Path, data: &[u8]) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if !DISGUISE_EXTS.contains(&ext.as_str()) || data.len() < 8 {
        return false;
    }
    if FONT_MAGIC.iter().any(|m| data.starts_with(m)) {
        return false;
    }
    // Not a font. But "not a font" is not "malware", and this rule used to
    // conclude the second from the first. It deleted two files from a project
    // that were GitHub's "Page not found" page saved as .ttf - a `curl` of a raw
    // URL that 404'd. `function`, `=>` and `module` all appear in any web page.
    //
    // A mislabelled file is still worth knowing about, so it is still reported.
    // What changed is that it is no longer reported as *the payload* unless it
    // carries a PolinRider indicator: see `disguised_font_is_payload`.
    if looks_like_web_page(data) {
        return false;
    }
    let js = [
        &b"require("[..],
        &b"function"[..],
        &b"=>"[..],
        &b"global"[..],
        &b"eval("[..],
        &b"process."[..],
        &b"module"[..],
    ];
    js.iter().filter(|m| find_lit_ci(data, m).is_some()).count() >= 2
}

/// An HTML document, which is what a failed download leaves behind.
///
/// A CDN 404, a login redirect, a Git LFS pointer page: all of them arrive with
/// a 200 and get written to whatever filename was asked for. It is a broken
/// asset, not an attack.
fn looks_like_web_page(data: &[u8]) -> bool {
    let head = &data[..data.len().min(512)];
    let start = head
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    let head = &head[start..];
    let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
    lower.starts_with(b"<!doctype html")
        || lower.starts_with(b"<html")
        || lower.starts_with(b"<?xml")
}

/// Hard ceiling: nothing this large is read, whatever it is called.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Ceiling for a file that is *not* one of PolinRider's target filenames.
///
/// The attack appends to a hand-maintained build config, and those are
/// kilobytes. Anything past a megabyte is a bundle, a minified vendor blob or a
/// lockfile - and reading a few hundred megabytes of editor-extension bundles,
/// then running every indicator over each one, is what turned a machine-wide
/// hunt from seconds into many minutes.
///
/// This is a deliberate, documented trade-off rather than a silent one: a
/// payload appended to a multi-megabyte bundle would be missed. Target
/// filenames are exempt from this cap and always read in full, up to
/// `MAX_FILE_BYTES`.
const MAX_INCIDENTAL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Finding {
    pub path: PathBuf,
    pub hits: Vec<Hit>,
    /// Extra context that is not an indicator, e.g. why a read failed.
    pub note: Option<String>,
}

impl Finding {
    pub fn is_critical(&self) -> bool {
        self.hits.iter().any(|h| h.sev == Severity::Critical)
    }
    /// True when the only critical evidence is the padding heuristic.
    ///
    /// The healer treats this case more carefully: padding alone is strong but
    /// not conclusive, so it only cuts inside a file PolinRider is known to
    /// target.
    pub fn padding_only(&self) -> bool {
        let crit: Vec<&Hit> = self
            .hits
            .iter()
            .filter(|h| h.sev == Severity::Critical)
            .collect();
        !crit.is_empty() && crit.iter().all(|h| h.ioc == "padding-run")
    }
}

/// Is `path` one of the filenames PolinRider targets?
///
/// Called for every file the walker sees, so it must not allocate. The previous
/// version normalised the whole path and then built a `format!("/{t}")` string
/// for each of the thirty-odd targets - roughly a hundred allocations per file.
pub fn is_config_target(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    // The common case: the target is a bare filename.
    if CONFIG_TARGETS
        .iter()
        .any(|t| !t.contains('/') && *t == name)
    {
        return true;
    }
    // The few targets that carry a directory (`src/main.ts`, `.vscode/tasks.json`).
    let nested: bool = CONFIG_TARGETS.iter().any(|t| t.contains('/'));
    if !nested {
        return false;
    }
    // Only now is normalising the path worth it, and only its tail is needed.
    let full = path.to_string_lossy();
    let norm: String = full.chars().map(|c| if c == '\\' { '/' } else { c }).collect();
    CONFIG_TARGETS.iter().any(|t| {
        t.contains('/') && {
            let want = t.len() + 1;
            norm.len() > want && norm.ends_with(t) && norm.as_bytes()[norm.len() - want] == b'/'
        }
    })
}

fn is_gitignore(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|n| n.eq_ignore_ascii_case(".gitignore"))
        .unwrap_or(false)
}

/// Propagation artefacts hidden in a `.gitignore`.
///
/// Part of this campaign is an edit to `.gitignore` that adds its own dropped
/// files - `temp_auto_push.bat`, `branch_structure.json` - so that `git status`
/// stops mentioning them. The payload then sits in the working tree
/// indefinitely without ever appearing in a diff, which is how the same repo
/// got re-infected after being cleaned. Nothing honest ignores these names, and
/// the ignore file is the only artefact of that step.
///
/// Reported, never healed: a `.gitignore` holds no executable code, so there is
/// nothing to cut, and the useful outcome is a human looking at the repository
/// it belongs to. `Suspicious` is what guarantees that - `heal` returns early on
/// any finding without a critical hit.
fn scan_gitignore(path: &Path, data: &[u8]) -> Option<Finding> {
    let text = String::from_utf8_lossy(data);
    let mut hits: Vec<Hit> = Vec::new();
    let mut offset = 0usize;
    for (n, raw) in text.lines().enumerate() {
        let start = offset;
        // `lines()` drops the terminator; +1 tracks it so offsets stay file
        // offsets. A CRLF file is one byte out per line, which is why these are
        // only ever used to point a human at a line number.
        offset += raw.len() + 1;
        let entry = raw
            .trim()
            .trim_start_matches('\u{feff}')
            .trim_start_matches('/');
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let mut hostile = ARTIFACT_NAMES.iter().chain(LOADER_ARTIFACT_NAMES.iter());
        if hostile.any(|a| a.eq_ignore_ascii_case(entry)) {
            hits.push(Hit {
                ioc: "gitignore-hides-artifact",
                sev: Severity::Suspicious,
                why: "`.gitignore` entry hides a known propagation artefact from `git status`",
                start,
                end: start + raw.len(),
                line: n + 1,
            });
        }
    }
    if hits.is_empty() {
        return None;
    }
    Some(Finding {
        path: path.to_path_buf(),
        hits,
        note: Some(
            "remove the entry and run `git status` - the file it was hiding may still be here"
                .into(),
        ),
    })
}

pub fn is_known_detector(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|n| KNOWN_DETECTORS.contains(&n))
        .unwrap_or(false)
}

fn has_scannable_ext(path: &Path) -> bool {
    // Extensionless names we still care about (Dockerfile, .env variants), and
    // the artefacts whose filename alone is the finding.
    if let Some(n) = path.file_name().and_then(|s| s.to_str()) {
        if n == "Dockerfile" || n.starts_with(".env") {
            return true;
        }
    }
    // `.gitignore` has no extension, and the step of the attack it records -
    // hiding the propagation artefacts from `git status` - is visible nowhere
    // else. See `scan_gitignore`.
    if is_gitignore(path) {
        return true;
    }
    if is_artifact(path) || is_loader_artifact(path) || is_extensionless_script(path) {
        return true;
    }
    path.extension()
        .and_then(|s| s.to_str())
        .map(|e| {
            let e = e.to_ascii_lowercase();
            SCAN_EXTS.contains(&e.as_str()) || DISGUISE_EXTS.contains(&e.as_str())
        })
        .unwrap_or(false)
}

/// Binary content is never a hand-edited config; a NUL in the first 8 KiB is a
/// good enough test and avoids reading megabytes to find out.
fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
}

/// Decode a UTF-16 file to UTF-8, if that is what it is.
///
/// A UTF-16 source file is half NUL bytes, so `looks_binary` calls it binary and
/// the scan skips it entirely. That is a blind spot worth closing: a config
/// re-saved as UTF-16 (which some editors and `Out-File` do by default on
/// Windows) would carry a payload right past us. Found in the wild as a
/// UTF-16LE `eslint.config.mjs` - benign in that instance, but invisible.
fn decode_utf16(data: &[u8]) -> Option<String> {
    let (body, big_endian) = match data {
        [0xFF, 0xFE, rest @ ..] => (rest, false),
        [0xFE, 0xFF, rest @ ..] => (rest, true),
        _ => return None,
    };
    if body.len() < 2 {
        return None;
    }
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| {
            if big_endian {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16(&units).ok()
}

/// Phrases that only appear in a scanner: the signatures are sitting inside a
/// search pattern, not inside executable payload.
const DETECTOR_IDIOMS: &[&str] = &[
    "grep -rE",
    "grep -rqE",
    "grep -qE",
    "grep -rIE",
    "PATTERN=",
    "$pattern =",
    "Select-String -Pattern",
    "const PATTERN",
    "malware",
];

/// Is this content exempt from reporting - a declared detector, or a scanner
/// whose own pattern strings tripped the matcher?
pub fn is_exempt(data: &[u8]) -> bool {
    crate::signatures::contains_marker(data, DETECTOR_MARKER) || looks_like_detector_logic(data)
}

/// Does this file look like malware *detection* rather than malware?
///
/// A backstop for the explicit `DETECTOR_MARKER`, which only helps once every
/// branch has the commit that adds it. A CI gate carries the signatures inside a
/// grep pattern, and ships the grep alongside them; a payload does not.
///
/// This is a content heuristic, so in principle a payload could bait it by
/// including the word "malware". That is equally true of the marker, and the
/// alternative - blanket-skipping `.github/workflows/`, as the older scanners
/// did - creates a much larger blind spot, since a malicious workflow is a real
/// exfiltration route. Requiring two independent idioms keeps it tight.
fn looks_like_detector_logic(data: &[u8]) -> bool {
    let n = DETECTOR_IDIOMS
        .iter()
        .filter(|idiom| find_lit_ci(data, idiom.as_bytes()).is_some())
        .count();
    n >= 2
}

fn find_lit_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len())
        .position(|w| w.iter().zip(needle).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

/// Prose and type declarations, where a long whitespace run means table
/// alignment or sloppy formatting rather than camouflage.
const NON_EXECUTING_EXTS: &[&str] = &["md", "markdown", "txt", "rst", "adoc", "csv", "lock"];

/// Files an interpreter or the editor will execute, where invisible Unicode is
/// camouflage rather than content.
const CODE_EXTS: &[&str] = &[
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "vue", "svelte", "py", "rb", "php",
    "sh", "bash", "ps1", "psm1", "bat", "cmd", "vbs",
];

/// npm lifecycle scripts that run on `npm install` without anyone asking.
const LIFECYCLE_KEYS: &[&str] = &[
    "preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish",
];

/// Read `"key": "value"` string values for the given keys out of raw JSON text.
///
/// A dedicated parser would be more correct; this is enough for `package.json`
/// as npm itself writes it, and it never has to *modify* the file.
fn json_string_values<'a>(data: &'a str, key: &str) -> Vec<(usize, &'a str)> {
    let mut out = Vec::new();
    let needle = format!("\"{key}\"");
    let mut from = 0usize;
    while let Some(rel) = data[from..].find(&needle) {
        let at = from + rel;
        let mut j = at + needle.len();
        let bytes = data.as_bytes();
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r' || bytes[j] == b'\n') { j += 1; }
        if j < bytes.len() && bytes[j] == b':' {
            j += 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r' || bytes[j] == b'\n') { j += 1; }
            if j < bytes.len() && bytes[j] == b'"' {
                let vs = j + 1;
                let mut k = vs;
                while k < bytes.len() {
                    if bytes[k] == b'\\' { k += 2; continue; }
                    if bytes[k] == b'"' { break; }
                    k += 1;
                }
                if k <= bytes.len() {
                    if let Some(v) = data.get(vs..k.min(bytes.len())) {
                        out.push((at, v));
                    }
                }
            }
        }
        from = at + needle.len();
    }
    out
}

/// `package.json`: an install-time script that fetches, decodes or spawns.
///
/// This is how every npm worm of 2025-26 runs - Shai-Hulud's `postinstall:
/// node bundle.js`, its v2 `preinstall: node setup_bun.js`, the fake-interview
/// packages' `postinstall` droppers. The script text is small and the shape is
/// unmistakable, so it is worth a dedicated look rather than the generic matcher.
fn scan_package_json(data: &[u8]) -> Vec<Hit> {
    let text = String::from_utf8_lossy(data);
    let mut hits = Vec::new();
    for key in LIFECYCLE_KEYS {
        for (at, value) in json_string_values(&text, key) {
            let v = value.to_ascii_lowercase();
            let line = data[..at.min(data.len())].iter().filter(|&&b| b == b'\n').count() + 1;
            let mk = |ioc: &'static str, sev: Severity, why: &'static str| Hit { ioc, sev, why, start: at, end: at + value.len(), line };
            if v.contains("bundle.js") || v.contains("setup_bun.js") || v.contains("bun_environment") {
                hits.push(mk("shai-hulud-lifecycle", Severity::Critical, "install-time script runs the worm's bundle (Shai-Hulud shape)"));
            } else if crate::persist::is_fetch_exec(value).is_some() {
                hits.push(mk("lifecycle-fetch-exec", Severity::Critical, "install-time script downloads (or decodes) and executes code"));
            } else if v.contains("node -e") || v.contains("node --eval") || v.contains("eval(") || v.contains("atob(")
                || v.contains("base64") || v.contains("powershell") || v.contains("curl ") || v.contains("wget ")
                || v.contains("child_process") || v.contains("bash -c") || v.contains("sh -c") || v.contains("certutil")
                || v.contains("mshta") || v.contains("bitsadmin") || v.contains("| sh") || v.contains("|sh") {
                hits.push(mk("lifecycle-script-suspicious", Severity::Suspicious, "install-time script spawns a shell, decodes data or evaluates code - look at it before installing"));
            }
        }
    }
    hits
}

/// GitHub Actions workflows that run untrusted pull-request code with secrets
/// ("pwn request"), or fetch-and-execute in a step. Reported, never edited.
fn scan_workflow(data: &[u8]) -> Vec<Hit> {
    let text = String::from_utf8_lossy(data);
    let mut hits = Vec::new();
    let lower = text.to_ascii_lowercase();
    if lower.contains("pull_request_target") && lower.contains("actions/checkout") && lower.contains("github.event.pull_request.head") {
        let at = lower.find("pull_request_target").unwrap_or(0);
        hits.push(Hit { ioc: "workflow-pwn-request", sev: Severity::Suspicious, why: "pull_request_target + checkout of the PR head: a fork's code runs with this repo's secrets", start: at, end: at + 19, line: text[..at].matches('\n').count() + 1 });
    }
    let mut offset = 0usize;
    for line in text.lines() {
        if crate::persist::is_fetch_exec(line).is_some() {
            hits.push(Hit { ioc: "workflow-fetch-exec", sev: Severity::Suspicious, why: "a workflow step downloads and executes code in one line", start: offset, end: offset + line.len(), line: text[..offset].matches('\n').count() + 1 });
            break;
        }
        offset += line.len() + 1;
    }
    hits
}

fn is_workflow(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/");
    s.contains("/.github/workflows/") && (s.ends_with(".yml") || s.ends_with(".yaml"))
}

fn is_package_json(path: &Path) -> bool {
    path.file_name().and_then(|s| s.to_str()) == Some("package.json")
}

/// Findings that need the file's *shape*, not just its bytes.
fn structural_hits(path: &Path, data: &[u8]) -> Vec<Hit> {
    if is_package_json(path) {
        return scan_package_json(data);
    }
    if is_workflow(path) {
        return scan_workflow(data);
    }
    Vec::new()
}

/// Apply file context to a raw hit list.
///
/// Two adjustments the matcher cannot make on its own, because it only sees
/// bytes:
///
/// * The padding heuristic is powerful but it is a heuristic. In a file
///   PolinRider actually targets, a 200-character pad followed by code is
///   damning. In a README it is a markdown table, and in a `.d.ts` it is
///   generated formatting - so drop it there, and elsewhere keep it only as a
///   suspicion rather than grounds to cut.
/// * Corroborating indicators are dropped when nothing else fired.
fn refine(path: &Path, mut hits: Vec<Hit>) -> Vec<Hit> {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    let is_prose = NON_EXECUTING_EXTS.contains(&ext.as_str()) || name.ends_with(".d.ts");
    let target = is_config_target(path);

    if is_prose {
        hits.retain(|h| h.ioc != signatures::PADDING_IOC);
    } else if !target {
        for h in hits.iter_mut() {
            if h.ioc == signatures::PADDING_IOC {
                h.sev = Severity::Suspicious;
            }
        }
    }

    // Invisible Unicode is only camouflage where something will *execute* the
    // file. In prose, JSON or a lockfile it is odd but not an infection.
    let is_code = CODE_EXTS.contains(&ext.as_str());
    for h in hits.iter_mut() {
        if h.ioc == signatures::INVISIBLE_IOC && !is_code {
            h.sev = Severity::Suspicious;
        }
    }

    // The fake-interview backdoor's tell is the *pair*: a global keylogger and
    // a screenshotter in the same manifest. Either alone has honest uses.
    let has_key = hits.iter().any(|h| h.ioc == "keylogger-dep");
    let has_shot = hits.iter().any(|h| h.ioc == "screenshot-dep");
    if has_key && has_shot {
        let at = hits.iter().find(|h| h.ioc == "keylogger-dep").map(|h| (h.start, h.line)).unwrap_or((0, 0));
        hits.push(Hit {
            ioc: "keylogger-kit",
            sev: Severity::Critical,
            why: "keystroke capture + screen capture in one package: the Contagious-Interview backdoor's toolkit",
            start: at.0,
            end: at.0,
            line: at.1,
        });
    }

    // Corroborating indicators only count in company. Outside a file PolinRider
    // targets, the padding heuristic joins them: a long whitespace run in a
    // lockfile or an installer script is untidy formatting, and reporting it on
    // its own trains people to ignore the tool.
    let corroborating = |ioc: &str| {
        signatures::CORROBORATING.contains(&ioc) || (!target && ioc == signatures::PADDING_IOC)
    };
    let has_standalone = hits.iter().any(|h| !corroborating(h.ioc));
    if !has_standalone {
        hits.retain(|h| !corroborating(h.ioc));
    }
    hits
}

/// Read a file and match it. `None` when the file should not be considered.
pub fn scan_file(path: &Path) -> Option<Finding> {
    if is_known_detector(path) || is_own_state(path) {
        return None;
    }
    // Some files need no reading: the name is the whole finding.
    if is_artifact(path) {
        return Some(Finding {
            path: path.to_path_buf(),
            hits: vec![Hit {
                ioc: "propagation-artifact",
                sev: Severity::Critical,
                why: "a PolinRider propagation/carrier file - its presence is the finding",
                start: 0,
                end: 0,
                line: 0,
            }],
            note: Some(
                "rewrites commit history with a back-dated --no-verify force-push".into(),
            ),
        });
    }
    // The AppData loader campaign's fixed-name shims and stages: the name is
    // the finding, and the whole file is payload.
    if is_loader_artifact(path) {
        return Some(Finding {
            path: path.to_path_buf(),
            hits: vec![Hit {
                ioc: "loader-artifact",
                sev: Severity::Critical,
                why: "a known AppData loader shim/stage - its presence is the finding",
                start: 0,
                end: 0,
                line: 0,
            }],
            note: Some("dropped loader/persistence shim; the whole file is malware".into()),
        });
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    // An empty file holds nothing. Worth saying because the common empty file
    // on a running machine is a lock - Firefox's `parent.lock`, and its like -
    // which is also the common file we are refused a read on. Checking the
    // length first keeps those out of the results entirely.
    if meta.len() == 0 {
        return None;
    }
    // Large files that are not a known target are not worth the read.
    if meta.len() > MAX_INCIDENTAL_BYTES && !is_config_target(path) {
        return None;
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            // "Another program has this open" is not a signal. A live database,
            // a browser profile, a log being written: normal machines are full
            // of them, and reporting each one buries the findings that matter.
            if is_merely_in_use(&e) {
                return None;
            }
            // A file we cannot read for any other reason is not a file we can
            // call clean. Antivirus that has already identified the payload will
            // deny the read outright ("the file contains a virus"), and treating
            // that as "nothing found" is exactly backwards - it hides the
            // strongest signal available behind a silent skip.
            return Some(Finding {
                path: path.to_path_buf(),
                hits: vec![Hit {
                    ioc: "read-blocked",
                    sev: Severity::Suspicious,
                    why: "could not be read; antivirus may have quarantined it, or it is locked",
                    start: 0,
                    end: 0,
                    line: 0,
                }],
                note: Some(e.to_string()),
            });
        }
    };
    // An ignore file carries no code, so the generic matchers have nothing to
    // find in it; it needs its own reading.
    if is_gitignore(path) {
        return scan_gitignore(path, &data);
    }
    if looks_binary(&data) {
        // Might be UTF-16 rather than genuinely binary.
        let text = decode_utf16(&data)?;
        let bytes = text.as_bytes();
        let mut hits = refine(path, signatures::scan(bytes));
        if hits.is_empty() {
            return None;
        }
        if is_exempt(bytes) {
            return None;
        }
        // Offsets refer to the decoded text, not the file, so the byte-splicing
        // healer must not touch it. Flag that explicitly instead of guessing.
        hits.push(Hit {
            ioc: "utf16-encoded",
            sev: Severity::Suspicious,
            why: "UTF-16 source; indicators found in the decoded text, so clean this one by hand",
            start: 0,
            end: 0,
            line: 0,
        });
        return Some(Finding {
            path: path.to_path_buf(),
            hits,
            note: Some("file is UTF-16 encoded; automatic removal is disabled for it".into()),
        });
    }
    // Match first, ask about exemptions afterwards.
    //
    // The marker check and the detector-idiom check are full searches over the
    // file - ten of them between them. Running those before the matcher meant
    // every clean file in the tree paid for ten scans to learn nothing, which
    // was most of the cost of a sweep. Nothing needs suppressing until there is
    // a hit to suppress.
    let mut hits = refine(path, signatures::scan(&data));
    hits.extend(structural_hits(path, &data));
    if !hits.is_empty() && is_exempt(&data) {
        return None;
    }
    if disguised_font(path, &data) {
        // Critical - meaning "delete it" - only when the contents are also
        // recognisably PolinRider. Script in a font file is a strong shape, but
        // deleting somebody's file on a shape alone is the one mistake this tool
        // must not make: a mislabelled asset is a broken build, not an incident.
        let carries_payload = hits.iter().any(|h| h.sev == Severity::Critical);
        hits.insert(
            0,
            if carries_payload {
                Hit {
                    ioc: "font-disguise",
                    sev: Severity::Critical,
                    why: "a .woff2/.ttf whose contents are the payload, not a font",
                    start: 0,
                    end: 0,
                    line: 1,
                }
            } else {
                Hit {
                    ioc: "font-mislabelled",
                    sev: Severity::Suspicious,
                    why: "a font file whose contents are script, but with no PolinRider                           indicator - look before deleting it",
                    start: 0,
                    end: 0,
                    line: 1,
                }
            },
        );
    }
    if hits.is_empty() {
        None
    } else {
        Some(Finding {
            path: path.to_path_buf(),
            hits,
            note: None,
        })
    }
}

/// Match bytes that came from somewhere other than the filesystem - a git blob,
/// say - applying the same detector exemptions as `scan_file`.
pub fn scan_blob(name: &Path, data: &[u8]) -> Option<Finding> {
    if is_known_detector(name) || looks_binary(data) {
        return None;
    }
    let mut hits = refine(name, signatures::scan(data));
    hits.extend(structural_hits(name, data));
    if !hits.is_empty() && is_exempt(data) {
        return None;
    }
    if hits.is_empty() {
        None
    } else {
        Some(Finding {
            path: name.to_path_buf(),
            hits,
            note: None,
        })
    }
}

/// Recursively scan `root`, collecting findings.
pub fn scan_tree(root: &Path, quick: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    scan_tree_cb(root, quick, &mut |f| out.push(f));
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Recursively scan `root`, handing each finding to `on_finding` as it is
/// discovered.
///
/// Streaming matters for a machine-wide sweep. Collecting everything first means
/// a long walk shows no progress and, worse, an interrupted run cleans nothing
/// at all - the caller can act on each hit the moment it is found instead.
pub fn scan_tree_cb(root: &Path, quick: bool, on_finding: &mut dyn FnMut(Finding)) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                // Do not follow directory symlinks: that is how you walk in circles.
                if std::fs::symlink_metadata(&path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    continue;
                }
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if skip_dir(&name) || is_own_state(&path) || is_quarantine(&path) {
                    continue;
                }
                stack.push(path);
            } else if meta.is_file() {
                let interesting = if quick {
                    is_config_target(&path)
                } else {
                    has_scannable_ext(&path) || is_config_target(&path)
                };
                if interesting {
                    if let Some(f) = scan_file(&path) {
                        on_finding(f);
                    }
                }
            }
        }
    }
}

/// Scan the AppData hideouts the normal machine walk skips.
///
/// A full sweep skips `Microsoft`, `Packages` and the other vendor caches under
/// %LOCALAPPDATA% for speed - which is exactly where the loader campaign hides
/// its bundled-Python stage, in a fake `Microsoft\CLR_v4.0\Optimization` (the
/// real .NET NGEN never lives under a user profile). These few known-bad
/// locations are small and are scanned explicitly, skip list or not, so `hunt`
/// reaches the stage the ordinary walk steps over.
pub fn scan_hideouts_cb(on_finding: &mut dyn FnMut(Finding)) {
    let home = crate::config::user_home();
    let mut spots: Vec<PathBuf> = vec![
        // The npm-loader variant's drop sites (unix-style dirs, even on Windows).
        home.join(".config").join("runtimedev-link"),
        home.join(".local").join("share").join("runtimedev-link"),
    ];
    if let Some(local) = local_appdata() {
        spots.push(local.join("Microsoft").join("CLR_v4.0"));
        spots.push(
            local
                .join("Microsoft")
                .join("Windows")
                .join("Caches")
                .join("cversions"),
        );
    }
    for spot in spots {
        walk_unrestricted(&spot, on_finding);
    }
    // Cached copies of malicious npm packages: `npx -y <pkg>` leaves the
    // package under ~/.npm/_npx/<hash>/node_modules/<pkg>, and a global install
    // puts it in the global modules dir. Both are outside every project tree
    // and inside directories the walk skips, so they are named here.
    for dir in cached_malicious_packages() {
        on_finding(Finding {
            path: dir,
            hits: vec![Hit {
                ioc: "malicious-package-cached",
                sev: Severity::Critical,
                why: "a known-malicious npm package sitting in a package cache, ready to be re-run",
                start: 0,
                end: 0,
                line: 0,
            }],
            note: Some("directory of a malicious npm package; remove the whole directory".into()),
        });
    }
}

/// Directories of known-malicious npm packages in the npx cache and the global
/// node_modules. Each entry is a directory, not a file.
pub fn cached_malicious_packages() -> Vec<PathBuf> {
    let home = crate::config::user_home();
    let mut out = Vec::new();
    let mut roots: Vec<PathBuf> = Vec::new();
    // ~/.npm/_npx/<hash>/node_modules
    if let Ok(entries) = std::fs::read_dir(home.join(".npm").join("_npx")) {
        for e in entries.flatten() {
            roots.push(e.path().join("node_modules"));
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        roots.push(PathBuf::from(appdata).join("npm").join("node_modules"));
    }
    roots.push(home.join(".npm-global").join("lib").join("node_modules"));
    roots.push(PathBuf::from("/usr/local/lib/node_modules"));
    roots.push(PathBuf::from("/usr/lib/node_modules"));
    for r in roots {
        for pkg in MALICIOUS_PACKAGES {
            let p = r.join(pkg);
            if p.is_dir() {
                out.push(p);
            }
        }
    }
    out
}

/// %LOCALAPPDATA%, or the conventional path under the user profile.
fn local_appdata() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("LOCALAPPDATA") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()?;
    Some(PathBuf::from(base).join("AppData").join("Local"))
}

/// Walk `dir` in full, ignoring the skip list. Only ever pointed at a small,
/// specific known-bad location by `scan_hideouts_cb`, never at a broad tree.
fn walk_unrestricted(dir: &Path, on_finding: &mut dyn FnMut(Finding)) {
    if !dir.exists() || is_own_state(dir) || is_quarantine(dir) {
        return;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                if std::fs::symlink_metadata(&path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    continue;
                }
                if !is_own_state(&path) && !is_quarantine(&path) {
                    stack.push(path);
                }
            } else if meta.is_file() {
                if let Some(f) = scan_file(&path) {
                    on_finding(f);
                }
            }
        }
    }
}

/// Where a target file would sit if it existed, directly under `root`.
///
/// No directory walking: just `root` joined with each known target name. In
/// practice this is where almost every one of them lives, so it is what makes a
/// cheap 30-second pass possible.
pub fn direct_target_paths(root: &Path) -> Vec<PathBuf> {
    CONFIG_TARGETS.iter().map(|t| root.join(t)).collect()
}

/// Every file under `root` whose name is one PolinRider targets - infected or
/// not.
///
/// This is the discovery half of the watch list: it catches targets nested
/// somewhere unexpected (a monorepo's `packages/*/postcss.config.mjs`, say).
/// Reads nothing; it only looks at names, so it is far cheaper than a scan.
pub fn find_target_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            let path = entry.path();
            if meta.is_dir() {
                if std::fs::symlink_metadata(&path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    continue;
                }
                let name = entry.file_name();
                if !skip_dir(&name.to_string_lossy())
                    && !is_own_state(&path)
                    && !is_quarantine(&path)
                {
                    stack.push(path);
                }
            } else if meta.is_file() && is_config_target(&path) {
                out.push(path);
            }
        }
    }
    out
}

/// Scan several roots.
pub fn scan_paths(roots: &[PathBuf], quick: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in roots {
        out.extend(scan_tree(r, quick));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quarantine_anywhere_is_skipped() {
        // A quarantine left by another install, or by the test suite under a
        // temporary POLINRIDER_HOME, is still full of infected originals.
        let tmp = std::env::temp_dir().join(format!("prh-q-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        assert!(!is_quarantine(&tmp));
        let _ = std::fs::write(tmp.join(crate::config::QUARANTINE_SENTINEL), b"x");
        assert!(is_quarantine(&tmp));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn our_own_state_directory_is_never_scanned() {
        // Guards against re-quarantining the quarantine, which compounds every
        // pass until the directory has thousands of files in it.
        let home = crate::config::home();
        assert!(is_own_state(&home.join("quarantine").join("anything.mjs")));
        assert!(is_own_state(&home.join("hunter.log")));
        assert!(!is_own_state(Path::new("/some/project/postcss.config.mjs")));
    }

    #[test]
    fn config_targets_match_by_name_and_suffix() {
        assert!(is_config_target(Path::new("/a/b/postcss.config.mjs")));
        assert!(is_config_target(Path::new(r"C:\x\frontend\postcss.config.mjs")));
        assert!(is_config_target(Path::new("/a/.vscode/tasks.json")));
        assert!(!is_config_target(Path::new("/a/b/readme.md")));
    }

    #[test]
    fn detectors_are_skipped_by_name() {
        assert!(is_known_detector(Path::new("/x/scripts/check-malware.mjs")));
        assert!(!is_known_detector(Path::new("/x/src/index.js")));
    }

    #[test]
    fn binary_detection() {
        assert!(looks_binary(&[0x7f, 0x45, 0x00, 0x01]));
        assert!(!looks_binary(b"plain text config"));
    }

    #[test]
    fn extension_filter_covers_extensionless_targets() {
        assert!(has_scannable_ext(Path::new("/a/Dockerfile")));
        assert!(has_scannable_ext(Path::new("/a/.env.production")));
        assert!(has_scannable_ext(Path::new("/a/x.mjs")));
        assert!(!has_scannable_ext(Path::new("/a/logo.png")));
    }

    fn hit(ioc: &'static str, sev: Severity) -> Hit {
        Hit { ioc, sev, why: "", start: 0, end: 1, line: 1 }
    }

    #[test]
    fn utf16_is_decoded_not_dismissed_as_binary() {
        // UTF-16LE with BOM: "global.i = 'A8-2941';"
        let text = "global.i = 'A8-2941';";
        let mut data = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            data.extend_from_slice(&u.to_le_bytes());
        }
        assert!(looks_binary(&data), "half of it is NUL bytes");
        let decoded = decode_utf16(&data).expect("should decode");
        assert_eq!(decoded, text);
        assert!(signatures::has_critical(decoded.as_bytes()));
    }

    #[test]
    fn utf16_big_endian_decodes_too() {
        let mut data = vec![0xFE, 0xFF];
        for u in "abc".encode_utf16() {
            data.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(decode_utf16(&data).as_deref(), Some("abc"));
    }

    #[test]
    fn genuine_binary_is_not_mistaken_for_utf16() {
        assert!(decode_utf16(&[0x7f, 0x45, 0x4c, 0x46, 0x00]).is_none());
    }

    #[test]
    fn size_caps_are_ordered_sensibly() {
        // A target filename may be read well past the incidental cap.
        assert!(MAX_INCIDENTAL_BYTES < MAX_FILE_BYTES);
    }

    #[test]
    fn propagation_artifacts_are_flagged_by_name() {
        assert!(is_artifact(Path::new("/repo/temp_auto_push.bat")));
        assert!(is_artifact(Path::new(r"C:\repo\TEMP_AUTO_PUSH.BAT")));
        assert!(is_artifact(Path::new("/repo/config.bat")));
        assert!(!is_artifact(Path::new("/repo/build.bat")));
        // The rest of the same propagation kit.
        assert!(is_artifact(Path::new("/repo/temp_interactive_push.bat")));
        assert!(is_artifact(Path::new("/repo/branch_structure.json")));
        // Names that merely read alike stay clean.
        assert!(!is_artifact(Path::new("/repo/structure.json")));
        assert!(!is_artifact(Path::new("/repo/push.bat")));
    }

    #[test]
    fn a_gitignore_hiding_the_propagation_kit_is_reported() {
        let ignore = b"node_modules\n.env*\n\n# build\n/dist\nbranch_structure.json\ntemp_auto_push.bat\n";
        let f = scan_gitignore(Path::new("/repo/.gitignore"), ignore)
            .expect("hidden artefacts must be reported");
        let iocs: Vec<&str> = f.hits.iter().map(|h| h.ioc).collect();
        assert_eq!(iocs, vec!["gitignore-hides-artifact"; 2]);
        assert_eq!(f.hits[0].line, 6);
        assert_eq!(f.hits[1].line, 7);
        // Report-only: `heal` refuses anything without a critical hit, and an
        // ignore file must never be spliced.
        assert!(!f.is_critical());
    }

    #[test]
    fn an_honest_gitignore_is_left_alone() {
        // Including the `.env*` rule whose removal is itself part of the
        // compromise - its presence must never read as a finding.
        let ignore = b"node_modules\n.env*\n*.tsbuildinfo\n# temp_auto_push.bat was here\n/dist\n";
        assert!(scan_gitignore(Path::new("/repo/.gitignore"), ignore).is_none());
    }

    #[test]
    fn gitignore_is_read_despite_having_no_extension() {
        assert!(has_scannable_ext(Path::new("/repo/.gitignore")));
    }

    #[test]
    fn a_dictionary_carrying_javascript_is_a_disguise() {
        let js = b"const m = require('http'); module.exports = function(){};";
        assert!(disguised_font(Path::new("/x/spellright.dict"), js));
    }

    #[test]
    fn a_real_font_is_left_alone() {
        let mut woff2 = b"wOF2".to_vec();
        woff2.extend_from_slice(b"\x00\x01\x02\x03 function require global");
        assert!(!disguised_font(Path::new("/x/fonts/a.woff2"), &woff2));
    }

    #[test]
    fn javascript_wearing_a_font_extension_is_caught() {
        let js = b"const m = require('http'); module.exports = function(){};";
        assert!(disguised_font(Path::new("/x/public/fonts/fa-solid-400.woff2"), js));
    }

    #[test]
    fn a_non_font_extension_is_not_judged_this_way() {
        let js = b"const m = require('http'); module.exports = function(){};";
        assert!(!disguised_font(Path::new("/x/src/index.js"), js));
    }

    #[test]
    fn short_files_are_not_guessed_at() {
        assert!(!disguised_font(Path::new("/x/a.woff2"), b"tiny"));
    }

    #[test]
    fn ci_gates_are_recognised_as_detection_logic() {
        let gate = br#"      - name: malware scan
        run: |
          PATTERN="AUTH_API_KEY|global\.i[[:space:]]*=|A[89]-[0-9]{4}"
          if grep -rE "$PATTERN" src; then exit 1; fi"#;
        assert!(looks_like_detector_logic(gate));
    }

    #[test]
    fn a_payload_is_not_mistaken_for_a_gate() {
        let payload = b"};                    global.i = 'A8-2941';require('http').request(x)";
        assert!(!looks_like_detector_logic(payload));
    }

    #[test]
    fn one_idiom_alone_is_not_enough() {
        // The word "malware" in a comment must not buy an exemption.
        assert!(!looks_like_detector_logic(b"// not malware, honest
global.i = 'A8-1111';"));
    }

    #[test]
    fn padding_in_prose_is_dropped() {
        // A markdown table is not an infection.
        let out = refine(
            Path::new("/x/README.md"),
            vec![hit("padding-run", Severity::Critical)],
        );
        assert!(out.is_empty());
        let out = refine(
            Path::new("/x/types/plugin-api.d.ts"),
            vec![hit("padding-run", Severity::Critical)],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn a_crypto_wallet_extension_is_not_reported() {
        // Exactly what a browser wallet's provider.js looks like. Two real
        // sweeps flagged these before the RPC indicators became corroborating.
        let wallet = br#"const RPC=["https://eth.drpc.org","https://1rpc.io/eth"];
async function n(){return rpc("eth_getBlockByNumber",[t,!0])}
async function c(){return rpc("eth_getTransactionCount",[a])}"#;
        assert!(scan_blob(Path::new("/x/ext/web3/provider.js"), wallet).is_none());
    }

    #[test]
    fn but_an_rpc_call_beside_a_payload_marker_still_shows() {
        let both = br#"global.i = 'A8-2941'; rpc("eth_getBlockByNumber")"#;
        let f = scan_blob(Path::new("/x/postcss.config.mjs"), both).expect("flagged");
        let ids: Vec<&str> = f.hits.iter().map(|h| h.ioc).collect();
        assert!(ids.contains(&"global-i-assign"));
        assert!(ids.contains(&"eth-rpc-block"), "context should survive: {ids:?}");
    }

    #[test]
    fn lone_padding_outside_a_target_is_not_reported() {
        let mut installer = b"@echo off".to_vec();
        installer.extend(std::iter::repeat(b' ').take(300));
        installer.extend_from_slice(b"goto :eof");
        assert!(scan_blob(Path::new("/x/install.bat"), &installer).is_none());
    }

    #[test]
    fn padding_outside_a_target_is_demoted_and_needs_company() {
        // Alone it is dropped: a long whitespace run in an ordinary source file
        // is formatting, not evidence.
        let alone = refine(
            Path::new("/x/src/random.js"),
            vec![hit("padding-run", Severity::Critical)],
        );
        assert!(alone.is_empty());

        // Beside a real indicator it survives, demoted, as context.
        let together = refine(
            Path::new("/x/src/random.js"),
            vec![
                hit("padding-run", Severity::Critical),
                hit("global-i-assign", Severity::Critical),
            ],
        );
        assert_eq!(together.len(), 2);
        let pad = together.iter().find(|h| h.ioc == "padding-run").unwrap();
        assert_eq!(pad.sev, Severity::Suspicious);
    }

    #[test]
    fn padding_in_a_target_stays_critical() {
        let out = refine(
            Path::new("/x/postcss.config.mjs"),
            vec![hit("padding-run", Severity::Critical)],
        );
        assert_eq!(out[0].sev, Severity::Critical);
    }

    #[test]
    fn lone_corroborating_hits_are_dropped() {
        // windowsHide is ordinary in honest tooling.
        let out = refine(
            Path::new("/x/scripts/dev.cjs"),
            vec![hit("hidden-spawn", Severity::Suspicious)],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn corroborating_hits_survive_alongside_a_real_one() {
        let out = refine(
            Path::new("/x/tailwind.config.js"),
            vec![
                hit("hidden-spawn", Severity::Suspicious),
                hit("global-i-assign", Severity::Critical),
            ],
        );
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn padding_only_classification() {
        let f = Finding {
            path: PathBuf::from("x"),
            hits: vec![Hit {
                ioc: "padding-run",
                sev: Severity::Critical,
                why: "",
                start: 0,
                end: 1,
                line: 1,
            }],
            note: None,
        };
        assert!(f.is_critical());
        assert!(f.padding_only());
    }
}
