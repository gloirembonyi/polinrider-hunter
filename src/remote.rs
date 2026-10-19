//! Auditing a repository from nothing but its URL.
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR (the tests below build a
//! poisoned fixture, which would otherwise trip the hunter's own branch audit).
//!
//! `repos https://github.com/org/repo` has no clone to work from, and making
//! one the ordinary way would put the infected tree on disk - exactly the thing
//! an audit exists to avoid. So the URL is fetched into a temporary *bare*
//! repository: an object database and refs, no working tree, nothing that any
//! editor, package manager or folder-open task could ever run. The remote's
//! branches land under `refs/remotes/origin/*`, the same layout a working clone
//! has, so every audit and repair that works on a clone works on the mirror
//! unchanged - including pushing a repair back. The directory is deleted when
//! the mirror is dropped.

use std::path::{Path, PathBuf};

use crate::gitscan;

/// How long a fetch may take before it is killed.
pub const FETCH_TIMEOUT_SECS: u64 = 900;

/// A temporary bare mirror of a remote repository.
pub struct Mirror {
    /// What the user typed.
    pub url: String,
    /// The bare repository on disk.
    pub dir: PathBuf,
}

impl Drop for Mirror {
    fn drop(&mut self) {
        remove_tree(&self.dir);
    }
}

/// Whether a `repos` argument is a repository URL rather than a path.
pub fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("https://")
        || l.starts_with("http://")
        || l.starts_with("git@")
        || l.starts_with("ssh://")
        || l.starts_with("git://")
        || l.starts_with("git+ssh://")
        || l.starts_with("file://")
}

/// Fetch `url` into a fresh bare repository under the temp directory.
///
/// `git init --bare` + `git remote add origin` + `git fetch` rather than
/// `git clone --bare`: a bare clone copies the branches to `refs/heads/*`
/// with no fetch refspec, so a later fetch would refresh nothing and a repair
/// could not confirm its own push. This way the branches are remote-tracking
/// refs from the start. Hooks, fsmonitor and `ext::` transports are disabled
/// for every git call, prompts are off, and the fetch is killed if it exceeds
/// `FETCH_TIMEOUT_SECS`.
pub fn mirror(url: &str) -> Result<Mirror, String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("empty URL".into());
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("prh-remote-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let m = Mirror { url: url.to_string(), dir: dir.clone() };
    let dir_s = dir.to_string_lossy().to_string();
    let init = gitscan::git_timeout(None, &["init", "--quiet", "--bare", &dir_s], &[], 60);
    if !init.ok {
        return Err(format!("git init --bare failed: {}", init.stderr.trim()));
    }
    let add = gitscan::git_timeout(Some(&dir), &["remote", "add", "origin", url], &[], 60);
    if !add.ok {
        return Err(format!("git remote add failed: {}", add.stderr.trim()));
    }
    let fetch = gitscan::git_timeout(Some(&dir), &["fetch", "--quiet", "--prune", "origin"], &[], FETCH_TIMEOUT_SECS);
    if !fetch.ok {
        let why = fetch.stderr.trim();
        let why = why.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ");
        return Err(format!("could not fetch {url}: {why}"));
    }
    Ok(m)
}

/// Delete a directory tree, best effort.
///
/// Git marks its object files read-only, and on Windows `remove_dir_all`
/// refuses a read-only file; clear the bit and try again.
pub fn remove_tree(dir: &Path) {
    if !dir.exists() {
        return;
    }
    if std::fs::remove_dir_all(dir).is_ok() {
        return;
    }
    fn writable(p: &Path) {
        if let Ok(md) = std::fs::symlink_metadata(p) {
            let mut perm = md.permissions();
            if perm.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                perm.set_readonly(false);
                let _ = std::fs::set_permissions(p, perm);
            }
            if md.is_dir() {
                if let Ok(rd) = std::fs::read_dir(p) {
                    for e in rd.flatten() {
                        writable(&e.path());
                    }
                }
            }
        }
    }
    writable(dir);
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=T", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git");
        assert!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A bare "origin" whose main branch carries a padded payload, built the
    /// way the campaign builds one, plus the sandbox it lives in.
    fn poisoned_origin(tag: &str) -> (PathBuf, PathBuf) {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("prh-remote-test-{tag}-{}-{stamp}", std::process::id()));
        let bare = root.join("origin.git");
        let work = root.join("work");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        git(&bare, &["init", "-q", "--bare", "-b", "main"]);
        git(&work, &["init", "-q", "-b", "main"]);
        let pad: String = std::iter::repeat('\t').take(300).collect();
        std::fs::write(
            work.join("postcss.config.mjs"),
            format!("export default {{ plugins: {{}} }};{pad}global['!']='x';\n"),
        )
        .unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", "feat: x"]);
        git(&work, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git(&work, &["push", "-q", "origin", "main"]);
        (root, bare)
    }

    #[test]
    fn url_detection() {
        assert!(is_url("https://github.com/org/repo"));
        assert!(is_url("http://example.com/x.git"));
        assert!(is_url("git@github.com:org/repo.git"));
        assert!(is_url("ssh://git@gitlab.com/g/r.git"));
        assert!(is_url("file:///C:/x/origin.git"));
        assert!(!is_url("C:\\work\\repo"));
        assert!(!is_url("./repo"));
        assert!(!is_url("repo"));
    }

    #[test]
    fn a_bare_mirror_of_a_local_origin_audits_its_branches_without_a_work_tree() {
        let (root, bare) = poisoned_origin("mirror");
        let url = format!("file:///{}", bare.to_string_lossy().replace('\\', "/").trim_start_matches('/'));
        let m = mirror(&url).expect("mirror a file:// URL");
        assert!(gitscan::is_bare(&m.dir), "the mirror is bare");
        assert!(!gitscan::is_repo(&m.dir), "a bare mirror is not a work tree");
        assert!(!m.dir.join("postcss.config.mjs").exists(), "nothing is checked out");
        let hits = gitscan::scan_bare(&m.dir);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].git_ref, "refs/remotes/origin/main");
        assert_eq!(hits[0].file, "postcss.config.mjs");
        // The mirror's remote is the origin we can write to, and the person
        // who pushed the infection is named.
        let acc = gitscan::write_access(&m.dir, "origin");
        assert_eq!(acc.can_write, Some(true), "{}", acc.how);
        assert_eq!(acc.owner, "", "a local path names no owner");
        let who = gitscan::who_pushed(&m.dir, "refs/remotes/origin/main", &["postcss.config.mjs".to_string()]);
        assert_eq!(who.len(), 1);
        assert_eq!(who[0].email, "t@example.com");
        let dir = m.dir.clone();
        drop(m);
        assert!(!dir.exists(), "the temporary mirror is deleted");
        remove_tree(&root);
    }

    #[test]
    fn a_plain_path_to_a_bare_repository_works_as_a_url_too() {
        let (root, bare) = poisoned_origin("plainpath");
        let m = mirror(bare.to_str().unwrap()).expect("mirror a plain path");
        let hits = gitscan::scan_bare(&m.dir);
        assert_eq!(hits.len(), 1, "{hits:?}");
        drop(m);
        remove_tree(&root);
    }

    #[test]
    fn an_unreachable_url_is_an_error_not_a_hang() {
        let bad = std::env::temp_dir().join("prh-remote-does-not-exist-anywhere.git");
        let err = mirror(bad.to_str().unwrap()).err().expect("no such repository");
        assert!(err.contains("could not fetch"), "{err}");
    }

    /// Deleting a whole file (a dropper, a committed artefact) needs
    /// `update-index --force-remove`, which git refuses in a bare repository
    /// unless it is given a work tree. The first real URL repair failed on every
    /// branch that carried `api.js` or `spellright.dict` for exactly this reason.
    #[test]
    fn a_url_repair_can_delete_whole_payload_files_from_a_bare_mirror() {
        let (root, bare) = poisoned_origin("delete");
        let work = root.join("work");
        let pad: String = std::iter::repeat('\t').take(300).collect();
        let body: String = (1..=200).map(|i| format!("var _fake={i};")).collect();
        std::fs::write(work.join("api.js"), format!("{pad}{body}")).unwrap();
        std::fs::create_dir_all(work.join(".vscode")).unwrap();
        std::fs::write(work.join(".vscode").join("spellright.dict"), "x\n").unwrap();
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", "chore: y"]);
        git(&work, &["push", "-q", "origin", "main"]);

        let m = mirror(bare.to_str().unwrap()).expect("mirror");
        let hits = gitscan::scan_bare(&m.dir);
        let mut plans = gitscan::plan_repairs(&m.dir, &hits);
        assert_eq!(plans.len(), 1, "{hits:?}");
        let new = gitscan::build_repair(&mut plans[0]).expect("repair builds in a bare mirror");
        let tree = git(&m.dir, &["ls-tree", "-r", "--name-only", &new]);
        assert!(!tree.contains("api.js"), "{tree}");
        assert!(!tree.contains("spellright.dict"), "{tree}");
        assert!(tree.contains("postcss.config.mjs"), "the honest config is kept: {tree}");
        assert!(gitscan::scan_bare(&m.dir).iter().all(|h| h.git_ref != new), "nothing flagged on the repair");
        drop(m);
        remove_tree(&root);
    }
}
