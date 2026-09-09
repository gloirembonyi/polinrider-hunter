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
    "config", "lock", "md",
];

/// Font extensions. PolinRider's autorun variant drops its payload as
/// `public/fonts/fa-solid-400.woff2` and runs it with `node`, betting that
/// nobody opens a webfont in a text editor.
const FONT_EXTS: &[&str] = &["woff2", "woff", "ttf", "otf", "eot"];

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
    if !FONT_EXTS.contains(&ext.as_str()) || data.len() < 8 {
        return false;
    }
    if FONT_MAGIC.iter().any(|m| data.starts_with(m)) {
        return false;
    }
    // Not a font. Is it code?
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

fn is_known_detector(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|n| KNOWN_DETECTORS.contains(&n))
        .unwrap_or(false)
}

fn has_scannable_ext(path: &Path) -> bool {
    // Extensionless names we still care about (Dockerfile, .env variants).
    if let Some(n) = path.file_name().and_then(|s| s.to_str()) {
        if n == "Dockerfile" || n.starts_with(".env") {
            return true;
        }
    }
    path.extension()
        .and_then(|s| s.to_str())
        .map(|e| {
            let e = e.to_ascii_lowercase();
            SCAN_EXTS.contains(&e.as_str()) || FONT_EXTS.contains(&e.as_str())
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
fn is_exempt(data: &[u8]) -> bool {
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

    let has_standalone = hits
        .iter()
        .any(|h| !signatures::CORROBORATING.contains(&h.ioc));
    if !has_standalone {
        hits.retain(|h| !signatures::CORROBORATING.contains(&h.ioc));
    }
    hits
}

/// Read a file and match it. `None` when the file should not be considered.
pub fn scan_file(path: &Path) -> Option<Finding> {
    if is_known_detector(path) || is_own_state(path) {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    // Large files that are not a known target are not worth the read.
    if meta.len() > MAX_INCIDENTAL_BYTES && !is_config_target(path) {
        return None;
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            // A file we cannot read is not a file we can call clean. Antivirus
            // that has already identified the payload will deny the read
            // outright ("the file contains a virus"), and treating that as
            // "nothing found" is exactly backwards — it hides the strongest
            // signal available behind a silent skip.
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
    if !hits.is_empty() && is_exempt(&data) {
        return None;
    }
    if disguised_font(path, &data) {
        hits.insert(
            0,
            Hit {
                ioc: "font-disguise",
                sev: Severity::Critical,
                why: "a .woff2/.ttf whose contents are JavaScript, not a font - the dropped payload",
                start: 0,
                end: 0,
                line: 1,
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

/// Match bytes that came from somewhere other than the filesystem — a git blob,
/// say — applying the same detector exemptions as `scan_file`.
pub fn scan_blob(name: &Path, data: &[u8]) -> Option<Finding> {
    if is_known_detector(name) || looks_binary(data) {
        return None;
    }
    let hits = refine(name, signatures::scan(data));
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
                if skip_dir(&name) || is_own_state(&path) {
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
                if !skip_dir(&name.to_string_lossy()) && !is_own_state(&path) {
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
    fn padding_outside_a_target_is_only_suspicious() {
        let out = refine(
            Path::new("/x/src/random.js"),
            vec![hit("padding-run", Severity::Critical)],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sev, Severity::Suspicious);
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
