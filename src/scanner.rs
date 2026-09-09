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

/// Files this big are not hand-written config; skip them.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

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
pub fn is_config_target(path: &Path) -> bool {
    let name = match path.file_name().and_then(|s| s.to_str()) {
        Some(n) => n,
        None => return false,
    };
    let norm = path.to_string_lossy().replace('\\', "/");
    CONFIG_TARGETS
        .iter()
        .any(|t| *t == name || norm.ends_with(&format!("/{t}")))
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
        .map(|e| SCAN_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Binary content is never a hand-edited config; a NUL in the first 8 KiB is a
/// good enough test and avoids reading megabytes to find out.
fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
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
    if is_known_detector(path) {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
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
        return None;
    }
    // A file that declares itself a detector is exempt, wherever it lives.
    if crate::signatures::contains_marker(&data, DETECTOR_MARKER) {
        return None;
    }
    let hits = refine(path, signatures::scan(&data));
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
    if crate::signatures::contains_marker(data, DETECTOR_MARKER) {
        return None;
    }
    let hits = refine(name, signatures::scan(data));
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

/// Recursively scan `root`. `quick` restricts reads to `CONFIG_TARGETS`.
pub fn scan_tree(root: &Path, quick: bool) -> Vec<Finding> {
    let mut out = Vec::new();
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
                if SKIP_DIRS.contains(&name.as_ref()) {
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
                        out.push(f);
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
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
