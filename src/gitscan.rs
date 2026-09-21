//! Auditing git repositories, including every branch, without checking anything
//! out.
//!
//! `git grep` can search any ref straight out of the object database, so a
//! remote-tracking branch can be audited after a plain `fetch` - no pull, no
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
    // Not via util::run because blob contents are bytes, not UTF-8 text.
    let mut cmd = std::process::Command::new("git");
    cmd.args(["-C", repo.to_str()?, "cat-file", "blob", &sha]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd.output().ok()?;
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
// Repairing a poisoned remote branch
// ---------------------------------------------------------------------------

/// A plan to replace an infected remote branch with the clean local one.
#[derive(Debug, Clone)]
pub struct RemotePlan {
    pub repo: PathBuf,
    pub remote: String,
    pub branch: String,
    /// `refs/heads/<name>` of the local branch that will be pushed.
    pub local_ref: String,
    pub local_sha: String,
    pub remote_sha: String,
    pub infected_files: Vec<String>,
    /// Commits the remote has that the local branch does not.
    pub divergent: Vec<String>,
    /// Why this cannot be done automatically. `None` means it can.
    pub blocked: Option<String>,
}

impl RemotePlan {
    /// The exact command `apply` runs.
    pub fn command(&self) -> String {
        format!(
            "git push --force-with-lease=refs/heads/{}:{} {} {}:refs/heads/{}",
            self.branch, self.remote_sha, self.remote, self.local_ref, self.branch
        )
    }
}

fn rev_parse(repo: &Path, r: &str) -> Option<String> {
    let out = util::git(repo, &["rev-parse", "--verify", "--quiet", r]);
    if out.ok && !out.stdout.trim().is_empty() {
        Some(out.stdout.trim().to_string())
    } else {
        None
    }
}

/// The local branch that tracks `remote_ref`, else a local branch of the same name.
fn local_branch_for(repo: &Path, remote_ref: &str, branch: &str) -> Option<String> {
    let out = util::git(repo, &["for-each-ref", "--format=%(refname) %(upstream)", "refs/heads/"]);
    if out.ok {
        for line in out.stdout.lines() {
            let mut it = line.split_whitespace();
            let (Some(local), Some(up)) = (it.next(), it.next()) else { continue };
            if up == remote_ref {
                return Some(local.to_string());
            }
        }
    }
    let same = format!("refs/heads/{branch}");
    rev_parse(repo, &same).map(|_| same)
}

/// Files a ref carries that the matcher calls critical.
fn infected_files_on(repo: &Path, git_ref: &str) -> Vec<String> {
    let mut out = Vec::new();
    for file in grep_ref(repo, git_ref) {
        let Some(data) = blob_at(repo, git_ref, &file) else { continue };
        if let Some(f) = scanner::scan_blob(Path::new(&file), &data) {
            if f.is_critical() {
                out.push(file);
            }
        }
    }
    out
}

/// One payload blob still reachable somewhere in history.
#[derive(Debug, Clone)]
pub struct HistoryHit {
    pub repo: PathBuf,
    /// Blob object id. This is what `git filter-repo --strip-blobs-with-ids` takes.
    pub blob: String,
    /// A path the blob was stored at. The same bytes can appear at several
    /// paths; one is enough to recognise it.
    pub path: String,
    pub size: u64,
    pub iocs: Vec<String>,
}

/// Audit every blob reachable from any ref, not just the ref tips.
///
/// `scan_repo` answers "is there malware on this branch *now*", which is the
/// question that matters for anything that might execute. It is not the same
/// question as "is there malware in this repository". Cleaning a branch tip
/// leaves every earlier version of the poisoned file sitting in the object
/// database, reachable by checking out an old commit, by `git show`, and -
/// once pushed - by anyone with the object id. On the repositories this tool
/// was written for, the tips audited clean while seven payload blobs, three of
/// them a dropper in `src/main.ts` and one a committed `.env`, were still
/// there. Nothing reported them, because nothing looked.
///
/// Every blob is read through a single `git cat-file --batch`, so this costs
/// one child process rather than one per object, and the real matcher runs on
/// the bytes - which means the detector exemption applies and a repository's
/// own `check-malware.mjs` is not mistaken for the thing it hunts.
pub fn scan_history(repo: &Path, do_fetch: bool) -> Vec<HistoryHit> {
    if !is_repo(repo) {
        return Vec::new();
    }
    if do_fetch {
        fetch(repo);
    }
    // `<sha> <path>` for every object reachable from any ref; trees and commits
    // come through with no path and are dropped by the type check below.
    let listing = util::git(repo, &["rev-list", "--objects", "--all"]);
    let mut want: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in listing.stdout.lines() {
        let line = line.trim_end();
        let Some((sha, path)) = line.split_once(' ') else { continue };
        if sha.len() < 40 || path.is_empty() || !seen.insert(sha.to_string()) {
            continue;
        }
        if is_noise_path(path) {
            continue;
        }
        want.push((sha.to_string(), path.to_string()));
    }
    if want.is_empty() {
        return Vec::new();
    }
    let by_sha: std::collections::HashMap<&str, &str> =
        want.iter().map(|(s, p)| (s.as_str(), p.as_str())).collect();
    let mut out = Vec::new();
    for (sha, kind, data) in batch_cat_file(repo, want.iter().map(|(s, _)| s.as_str())) {
        if kind != "blob" || data.is_empty() {
            continue;
        }
        if !crate::signatures::has_critical(&data) || scanner::is_exempt(&data) {
            continue;
        }
        let path = by_sha.get(sha.as_str()).copied().unwrap_or("").to_string();
        let mut iocs: Vec<String> = crate::signatures::scan(&data).into_iter().map(|h| h.ioc.to_string()).collect();
        iocs.dedup();
        out.push(HistoryHit { repo: repo.to_path_buf(), size: data.len() as u64, blob: sha, path, iocs });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.blob.cmp(&b.blob)));
    out
}

/// Paths whose contents are never worth a full match: dependency lockfiles and
/// vendored trees, which are large, minified, and dominate the object count.
fn is_noise_path(path: &str) -> bool {
    path.contains("node_modules/")
        || path.ends_with("package-lock.json")
        || path.ends_with("yarn.lock")
        || path.ends_with("pnpm-lock.yaml")
}

/// Read many objects through one `git cat-file --batch`.
///
/// The batch protocol is `<sha> <type> <size>\n<size bytes>\n` per record, so
/// the payload is read by length and never by line - blobs are arbitrary bytes
/// and frequently are not UTF-8. Stdin is fed from its own thread: git starts
/// answering long before the request list is finished, and writing it all up
/// front would deadlock on a full pipe as soon as a repository is big enough to
/// matter.
fn batch_cat_file<'a>(repo: &Path, shas: impl Iterator<Item = &'a str>) -> Vec<(String, String, Vec<u8>)> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command, Stdio};

    let Some(dir) = repo.to_str() else { return Vec::new() };
    let mut cmd = Command::new("git");
    cmd.args(["-C", dir, "cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let Ok(mut child) = cmd.spawn() else { return Vec::new() };
    let Some(mut stdin) = child.stdin.take() else { return Vec::new() };
    let request: Vec<String> = shas.map(str::to_string).collect();
    let writer = std::thread::spawn(move || {
        for sha in request {
            if writeln!(stdin, "{sha}").is_err() {
                return;
            }
        }
        let _ = stdin.flush();
        // Dropping stdin closes it, which is what ends the batch.
    });

    let mut out = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let mut r = BufReader::new(stdout);
        let mut header = String::new();
        loop {
            header.clear();
            match r.read_line(&mut header) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let head = header.trim_end();
            if head.is_empty() {
                continue;
            }
            let mut parts = head.split(' ');
            let (Some(sha), Some(kind), Some(size)) = (parts.next(), parts.next(), parts.next()) else {
                // "<sha> missing" - no body follows.
                continue;
            };
            let Ok(size) = size.parse::<usize>() else { continue };
            let mut body = vec![0u8; size];
            if r.read_exact(&mut body).is_err() {
                break;
            }
            let mut nl = [0u8; 1];
            let _ = r.read_exact(&mut nl);
            out.push((sha.to_string(), kind.to_string(), body));
        }
    }
    let _ = writer.join();
    let _ = child.wait();
    out
}

/// Commits whose tree still holds `blob`, newest first, capped at `max`.
pub fn commits_holding_blob(repo: &Path, blob: &str, max: usize) -> Vec<String> {
    let out = util::git(repo, &["log", "--all", "--format=%h %s", &format!("--find-object={blob}")]);
    out.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).take(max).collect()
}

/// Work out, for every infected remote-tracking ref in `hits`, whether the
/// clean local branch can simply be pushed over it.
///
/// The bar is deliberately high. A force-push discards whatever the remote had,
/// so it is only planned when *every* commit the remote has beyond the local
/// branch touches an infected file - i.e. the remote's extra history *is* the
/// infection (the campaign re-pushes a victim's own commit with the payload
/// appended, so the remote is typically one rewritten commit "ahead"). A remote
/// commit that changes anything else is real work, and gets a `blocked` reason
/// instead of a push.
pub fn plan_remote_fixes(repo: &Path, hits: &[RefHit]) -> Vec<RemotePlan> {
    let mut by_ref: Vec<(String, Vec<String>)> = Vec::new();
    for h in hits {
        if h.repo != repo || !h.git_ref.starts_with("refs/remotes/") {
            continue;
        }
        match by_ref.iter_mut().find(|(r, _)| *r == h.git_ref) {
            Some((_, files)) => files.push(h.file.clone()),
            None => by_ref.push((h.git_ref.clone(), vec![h.file.clone()])),
        }
    }
    let mut plans = Vec::new();
    for (remote_ref, mut files) in by_ref {
        files.sort();
        files.dedup();
        let short = remote_ref.trim_start_matches("refs/remotes/");
        let Some((remote, branch)) = short.split_once('/') else { continue };
        let remote_sha = rev_parse(repo, &remote_ref).unwrap_or_default();
        let mut plan = RemotePlan {
            repo: repo.to_path_buf(),
            remote: remote.to_string(),
            branch: branch.to_string(),
            local_ref: String::new(),
            local_sha: String::new(),
            remote_sha,
            infected_files: files.clone(),
            divergent: Vec::new(),
            blocked: None,
        };
        let Some(local_ref) = local_branch_for(repo, &remote_ref, branch) else {
            plan.blocked = Some(format!("no local branch tracks {short} (and none is named {branch}) - nothing clean to restore from"));
            plans.push(plan);
            continue;
        };
        plan.local_ref = local_ref.clone();
        plan.local_sha = rev_parse(repo, &local_ref).unwrap_or_default();
        // The local branch must itself be clean, or we would be pushing malware.
        let local_infected = infected_files_on(repo, &local_ref);
        if !local_infected.is_empty() {
            plan.blocked = Some(format!("the local branch is infected too ({}) - run `clean`, commit, then retry", local_infected.join(", ")));
            plans.push(plan);
            continue;
        }
        // Every commit the remote has beyond local must be part of the infection.
        let range = format!("{local_ref}..{remote_ref}");
        let list = util::git(repo, &["rev-list", &range]);
        let divergent: Vec<String> = list.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        plan.divergent = divergent.clone();
        // Ask what the remote's extra history changes *as a whole*, relative to
        // the merge base, rather than walking commits one at a time.
        //
        // The per-commit walk this replaces ran `diff-tree` on each divergent
        // commit - which prints nothing at all for a merge commit unless it is
        // given `-m`/`--cc`. Every branch whose extra history contained a merge
        // therefore looked like it touched no files, failed the
        // "does it touch the infection?" test, and was refused with the
        // self-contradicting reason "changes 0 file(s) that are not part of the
        // infection". That is the common case, not a corner: the campaign
        // re-pushes through a merge.
        //
        // The three-dot form is also a stricter reading of the rule this
        // function documents. The old test passed a commit that touched an
        // infected file *and* fifty real ones; this one requires every file the
        // remote adds to be an infected file, so real work can never be on the
        // discard side of a force-push.
        let spec = format!("{local_ref}...{remote_ref}");
        let names = util::git(repo, &["diff", "--name-only", &spec]);
        let extra: Vec<String> = names
            .stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !files.contains(l))
            .collect();
        if !extra.is_empty() {
            // Name the files. "3 file(s)" tells a maintainer nothing about
            // whether the work on the other side matters.
            let shown: Vec<&str> = extra.iter().take(5).map(|s| s.as_str()).collect();
            let more = extra.len().saturating_sub(shown.len());
            let list = if more > 0 {
                format!("{} (+{more} more)", shown.join(", "))
            } else {
                shown.join(", ")
            };
            plan.blocked = Some(format!(
                "the remote has {} file(s) beyond your local branch that are not part of the infection: {list} - merge or rebase by hand first",
                extra.len()
            ));
        }
        plans.push(plan);
    }
    plans
}

/// Push the clean local branch over the poisoned remote branch.
///
/// `--force-with-lease` pins the push to the exact remote commit that was
/// audited, so if anyone pushed in between the push fails instead of erasing
/// their work. Afterwards the ref is fetched and re-audited; success means the
/// remote branch now carries no critical indicator.
pub fn apply_remote_fix(plan: &RemotePlan, dry: bool) -> Result<String, String> {
    if let Some(b) = &plan.blocked {
        return Err(b.clone());
    }
    if dry {
        return Ok(format!("would run: {}", plan.command()));
    }
    let lease = format!("--force-with-lease=refs/heads/{}:{}", plan.branch, plan.remote_sha);
    let spec = format!("{}:refs/heads/{}", plan.local_ref, plan.branch);
    let push = util::git(&plan.repo, &["push", &lease, &plan.remote, &spec]);
    if !push.ok {
        return Err(format!("push failed: {}", push.stderr.trim()));
    }
    let _ = util::git(&plan.repo, &["fetch", &plan.remote, "--prune", "--quiet"]);
    let remote_ref = format!("refs/remotes/{}/{}", plan.remote, plan.branch);
    let still = infected_files_on(&plan.repo, &remote_ref);
    if !still.is_empty() {
        return Err(format!("pushed, but {remote_ref} still carries: {}", still.join(", ")));
    }
    let now = rev_parse(&plan.repo, &remote_ref).unwrap_or_default();
    Ok(format!("{}/{} now at {} (was {}) - clean", plan.remote, plan.branch, &now[..now.len().min(10)], &plan.remote_sha[..plan.remote_sha.len().min(10)]))
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
    // Only if git already tracks it. `git add` on an untracked file does not
    // "re-stage" anything - it adds a brand-new entry to the index, which is
    // not the guard's business and surfaces as a change the user never made.
    // Caught doing exactly that while testing: healing a planted file left it
    // staged as a new addition.
    if !util::git(repo, &["ls-files", "--error-unmatch", "--", &rel_s]).ok {
        return false;
    }
    util::git(repo, &["add", "--", &rel_s]).ok
}
