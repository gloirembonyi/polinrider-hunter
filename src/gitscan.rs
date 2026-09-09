//! Auditing git repositories, including every branch, without checking anything
//! out.
//!
//! `git grep` can search any ref straight out of the object database, so a
//! remote-tracking branch can be audited after a plain `fetch` — no pull, no
//! merge, no touching the working tree. That matters when the thing you are
//! looking for is malware: you want to know what is on a branch *before* it
//! reaches your disk in a form anything might execute.

use std::path::{Path, PathBuf};

use crate::scanner;
use crate::signatures::GIT_GREP_ERE;
use crate::util;

#[derive(Debug, Clone)]
pub struct RefHit {
    pub repo: PathBuf,
    pub git_ref: String,
    pub file: String,
    pub iocs: Vec<String>,
}

/// The work-tree root of the repo containing `p`, if any.
pub fn repo_root(p: &Path) -> Option<PathBuf> {
    let out = util::git(p, &["rev-parse", "--show-toplevel"]);
    if !out.ok {
        return None;
    }
    let t = out.stdout.trim();
    if t.is_empty() {
        None
    } else {
        Some(PathBuf::from(t))
    }
}

pub fn is_repo(p: &Path) -> bool {
    let out = util::git(p, &["rev-parse", "--is-inside-work-tree"]);
    out.ok && out.stdout.trim() == "true"
}

/// Refresh remote refs. This is `fetch`, never `pull`: it updates
/// `refs/remotes/*` and leaves local branches and the working tree alone.
pub fn fetch(repo: &Path) -> bool {
    util::git(repo, &["fetch", "--all", "--prune", "--quiet"]).ok
}

/// Every local and remote-tracking ref.
pub fn refs(repo: &Path) -> Vec<String> {
    let out = util::git(
        repo,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/",
            "refs/remotes/",
        ],
    );
    out.stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        // origin/HEAD is a symbolic alias for another ref we already scan.
        .filter(|l| !l.ends_with("/HEAD"))
        .map(str::to_string)
        .collect()
}

/// Candidate files on `git_ref`, per `git grep`.
fn grep_ref(repo: &Path, git_ref: &str) -> Vec<String> {
    let out = util::git(
        repo,
        &[
            "grep",
            "-I",
            "-l",
            "-E",
            GIT_GREP_ERE,
            git_ref,
            "--",
            ":(exclude)*package-lock.json",
            ":(exclude)*yarn.lock",
            ":(exclude)*pnpm-lock.yaml",
            ":(exclude)node_modules/*",
        ],
    );
    out.stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix(&format!("{git_ref}:")))
        .map(str::to_string)
        .collect()
}

/// Read one file's contents at `git_ref`.
///
/// Goes via `ls-tree` for the blob id rather than `cat-file blob <ref>:<path>`,
/// because the `ref:path` form contains a colon and Git-for-Windows will
/// occasionally mangle such an argument into a path list.
fn blob_at(repo: &Path, git_ref: &str, file: &str) -> Option<Vec<u8>> {
    let ls = util::git(repo, &["ls-tree", git_ref, "--", file]);
    if !ls.ok {
        return None;
    }
    // `<mode> <type> <sha>\t<path>`
    let sha = ls
        .stdout
        .split_whitespace()
        .nth(2)
        .filter(|s| s.len() >= 7)?
        .to_string();
    let out = std::process::Command::new("git")
        .args(["-C", repo.to_str()?, "cat-file", "blob", &sha])
        .output()
        .ok()?;
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

/// Audit every ref in `repo`. `do_fetch` refreshes remotes first.
pub fn scan_repo(repo: &Path, do_fetch: bool) -> Vec<RefHit> {
    let mut out = Vec::new();
    if !is_repo(repo) {
        return out;
    }
    if do_fetch {
        fetch(repo);
    }
    for git_ref in refs(repo) {
        for file in grep_ref(repo, &git_ref) {
            // `git grep` runs an approximation of our indicator set; confirm
            // each candidate with the real matcher so detectors and CI gates
            // do not show up as infections.
            let Some(data) = blob_at(repo, &git_ref, &file) else {
                continue;
            };
            if let Some(f) = scanner::scan_blob(Path::new(&file), &data) {
                if f.is_critical() {
                    out.push(RefHit {
                        repo: repo.to_path_buf(),
                        git_ref: git_ref.clone(),
                        file: file.clone(),
                        iocs: f.hits.iter().map(|h| h.ioc.to_string()).collect(),
                    });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Pre-commit protection
// ---------------------------------------------------------------------------

/// Install a pre-commit hook that runs the hunter before every commit.
///
/// Written to `.git/hooks/`, which is deliberate: it protects the repo without
/// modifying a single tracked file, so nobody has to review or merge it, and it
/// cannot itself be tampered with by a malicious commit.
pub fn install_hook(repo: &Path, exe: &Path) -> std::io::Result<PathBuf> {
    let dir_out = util::git(repo, &["rev-parse", "--git-dir"]);
    if !dir_out.ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not a git repository",
        ));
    }
    let git_dir = {
        let raw = dir_out.stdout.trim();
        let p = PathBuf::from(raw);
        if p.is_absolute() {
            p
        } else {
            repo.join(p)
        }
    };
    let hooks = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks)?;
    let hook = hooks.join("pre-commit");

    if hook.exists() {
        let existing = std::fs::read_to_string(&hook).unwrap_or_default();
        if !existing.contains("polinrider-hunter") {
            // Keep whatever was there; back it up so nothing is lost.
            let _ = std::fs::copy(&hook, hooks.join("pre-commit.pre-polinrider"));
        }
    }

    let script = format!(
        "#!/bin/sh\n\
         # Installed by polinrider-hunter. Blocks a commit that would introduce\n\
         # PolinRider, healing the payload first where it safely can.\n\
         # Remove with: polinrider-hunter unprotect .\n\
         exec \"{}\" hook\n",
        exe.display().to_string().replace('\\', "/")
    );
    std::fs::write(&hook, script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&hook)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&hook, perm)?;
    }
    Ok(hook)
}

pub fn uninstall_hook(repo: &Path) -> std::io::Result<bool> {
    let dir_out = util::git(repo, &["rev-parse", "--git-dir"]);
    if !dir_out.ok {
        return Ok(false);
    }
    let git_dir = {
        let p = PathBuf::from(dir_out.stdout.trim());
        if p.is_absolute() {
            p
        } else {
            repo.join(p)
        }
    };
    let hook = git_dir.join("hooks").join("pre-commit");
    if !hook.exists() {
        return Ok(false);
    }
    let text = std::fs::read_to_string(&hook).unwrap_or_default();
    if !text.contains("polinrider-hunter") {
        return Ok(false);
    }
    std::fs::remove_file(&hook)?;
    // Put back anything we displaced.
    let saved = git_dir.join("hooks").join("pre-commit.pre-polinrider");
    if saved.exists() {
        std::fs::rename(&saved, &hook)?;
    }
    Ok(true)
}

/// Stage a file after healing it, so the clean version is what gets committed.
pub fn stage(repo: &Path, file: &Path) -> bool {
    let rel = file.strip_prefix(repo).unwrap_or(file);
    let rel_s = rel.to_string_lossy().replace('\\', "/");
    util::git(repo, &["add", "--", &rel_s]).ok
}
