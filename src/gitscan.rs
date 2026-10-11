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
        for (file, iocs) in critical_on(repo, &git_ref) {
            out.push(RefHit {
                repo: repo.to_path_buf(),
                git_ref: git_ref.clone(),
                file,
                iocs,
            });
        }
    }
    out
}

/// Every file on `git_ref` that is part of an infection, with the indicators.
///
/// Content alone is not enough. `git grep` only finds what the payload *says*,
/// and three of the campaign's shapes say nothing it can match:
///
/// * a dropped artefact (`config.bat`, `branch_structure.json`) is recognised
///   by its name, not its bytes;
/// * the autorun variant arms itself with `.vscode` settings that are valid,
///   ordinary JSON - `"runOn": "folderOpen"` plus either
///   `task.allowAutomaticTasks` switched on or a command that runs a hidden
///   script. Each half has honest uses; together they execute code the moment
///   the folder is opened, which is how this machine was infected on
///   2026-10-08 (a fresh clone of proposal_auto, opened in Cursor);
/// * its payload is JavaScript saved under a font name
///   (`public/fonts/fa-solid-300.llf`) that the task above runs with `node`.
///
/// Before this, `repos` passed a branch carrying all three as clean.
pub fn critical_on(repo: &Path, git_ref: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let push = |out: &mut Vec<(String, Vec<String>)>, file: &str, ioc: Vec<String>| {
        if !out.iter().any(|(f, _)| f == file) {
            out.push((file.to_string(), ioc));
        }
    };
    for file in grep_ref(repo, git_ref) {
        // `git grep` runs an approximation of our indicator set; confirm
        // each candidate with the real matcher so detectors and CI gates
        // do not show up as infections.
        let Some(data) = blob_at(repo, git_ref, &file) else { continue };
        if let Some(f) = scanner::scan_blob(Path::new(&file), &data) {
            if f.is_critical() {
                push(&mut out, &file, f.hits.iter().map(|h| h.ioc.to_string()).collect());
            }
        }
    }
    let names = tree_names(repo, git_ref);
    let mut armed_targets: Vec<String> = Vec::new();
    for file in &names {
        let p = Path::new(file);
        if scanner::is_artifact(p) {
            push(&mut out, file, vec!["dropped-artifact".to_string()]);
        } else if is_vscode_task_file(file) {
            let Some(data) = blob_at(repo, git_ref, file) else { continue };
            if armed_autorun(&data) {
                push(&mut out, file, vec!["vscode-armed-autorun".to_string()]);
                armed_targets.push(String::from_utf8_lossy(&data).to_ascii_lowercase());
            }
        }
    }
    // A font-named file that is really a script, and that an armed task runs.
    for file in &names {
        if !is_font_name(file) || file.contains("node_modules/") {
            continue;
        }
        let base = file.rsplit('/').next().unwrap_or(file).to_ascii_lowercase();
        if !armed_targets.iter().any(|t| t.contains(&base)) {
            continue;
        }
        let Some(data) = blob_at(repo, git_ref, file) else { continue };
        if !scanner::looks_like_font(&data) {
            push(&mut out, file, vec!["script-disguised-as-font".to_string()]);
        }
    }
    out
}

/// Every path in `git_ref`'s tree.
fn tree_names(repo: &Path, git_ref: &str) -> Vec<String> {
    let out = util::git(repo, &["-c", "core.quotepath=off", "ls-tree", "-r", "--name-only", git_ref]);
    out.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
}

fn is_vscode_task_file(file: &str) -> bool {
    let f = file.to_ascii_lowercase();
    f.ends_with(".vscode/tasks.json") || f.ends_with(".vscode/settings.json") || f == ".vscode/tasks.json" || f.ends_with(".code-workspace")
}

fn is_font_name(file: &str) -> bool {
    let ext = file.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(ext.as_str(), "woff" | "woff2" | "ttf" | "otf" | "eot" | "llf" | "lkf")
}

/// Commands an honest open-the-folder task has no reason to run.
const AUTORUN_TELLS: &[&str] = &[
    "node ", "node.exe", "\"node\"", ".woff", ".llf", ".lkf", ".ttf", "/fonts/", "curl", "wget", "powershell",
    "pwsh", "iwr ", "invoke-", "mshta", "certutil", "bitsadmin", "bash -c", "sh -c", "cmd /c", "start /b",
    "-windowstyle", "hidden", "base64",
];

/// A `.vscode` file that runs something on folder open, armed so it will run.
///
/// `folderOpen` alone is how plenty of honest projects start a dev watcher, and
/// it does nothing until the user allows automatic tasks. It is armed when the
/// same file also switches `task.allowAutomaticTasks` on, or when the task runs
/// one of the commands in `AUTORUN_TELLS`.
pub fn armed_autorun(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    if !text.contains("folderopen") {
        return false;
    }
    let enabled = text
        .split("allowautomatictasks")
        .skip(1)
        .any(|rest| {
            let v = rest.trim_start_matches(|c: char| c == '"' || c == ':' || c.is_whitespace());
            v.starts_with("true") || v.starts_with("on")
        });
    enabled || AUTORUN_TELLS.iter().any(|t| text.contains(t))
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
    critical_on(repo, git_ref).into_iter().map(|(f, _)| f).collect()
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
        //
        // A file the remote changed is only work at risk if the remote *tip*
        // still differs from the local tip there. The campaign's usual shape is
        // the victim's own latest commit replayed with the payload added (same
        // message, same author date) on top of the shared parent: the three-dot
        // diff then lists every file of that honest commit, although the local
        // branch already holds each one byte for byte. Intersecting with the
        // tip-to-tip diff drops those, and still blocks any file the remote
        // added or changed that local does not have.
        //
        // Files that are the attack's own bookkeeping - a propagation artefact
        // such as `branch_structure.json`, or a `.gitignore` whose only change
        // is entries hiding those artefacts - are part of the infection, not
        // work, and are discarded with it.
        let spec = format!("{local_ref}...{remote_ref}");
        let names = util::git(repo, &["diff", "--name-only", &spec]);
        let tips = util::git(repo, &["diff", "--name-only", &local_ref, &remote_ref]);
        let differs_at_tip: Vec<&str> = tips.stdout.lines().map(|l| l.trim()).collect();
        let extra: Vec<String> = names
            .stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !files.contains(l))
            .filter(|l| differs_at_tip.contains(&l.as_str()))
            .filter(|l| !is_campaign_bookkeeping(repo, &local_ref, &remote_ref, l))
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

/// Whether the remote's version of `file` is only the attack's bookkeeping.
fn is_campaign_bookkeeping(repo: &Path, local_ref: &str, remote_ref: &str, file: &str) -> bool {
    let path = Path::new(file);
    if scanner::is_artifact(path) {
        return true;
    }
    let is_ignore = path.file_name().and_then(|n| n.to_str()).map(|n| n.eq_ignore_ascii_case(".gitignore")).unwrap_or(false);
    if !is_ignore {
        return false;
    }
    let (Some(local), Some(remote)) = (blob_at(repo, local_ref, file), blob_at(repo, remote_ref, file)) else {
        return false;
    };
    scanner::gitignore_without_hidden_artifacts(&local) == scanner::gitignore_without_hidden_artifacts(&remote)
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
// Excising the poisoned commits themselves
// ---------------------------------------------------------------------------

/// How far back along a branch's first-parent line `plan_excise` looks.
pub const EXCISE_DEPTH: usize = 15;

/// A plan to cut the infection out of a remote branch's recent history.
///
/// `repos --fix` needs a clean local branch to push. Most branches have none:
/// the campaign rewrites *every* branch of *every* repository the stolen token
/// can reach, and nobody has all of them checked out. It also cannot help once
/// someone has "cleaned" a branch by committing a fix on top - the tip is clean
/// but the poisoned commit is still the one everybody pulls, and still the one
/// a `git checkout HEAD~1` runs.
///
/// The campaign's shape makes the original recoverable without a local copy.
/// The poisoned commit `C` is the victim's own commit replayed with the payload
/// added, on the victim's real parent `P`. So the original is `C`'s tree with
/// every infected file put back the way `P` had it, under `C`'s own message,
/// author and dates. Any later commits that only undo the payload (a cleanup)
/// are folded away. The branch then reads as if the attack never happened.
#[derive(Debug, Clone)]
pub struct ExcisePlan {
    pub repo: PathBuf,
    pub remote: String,
    pub branch: String,
    pub remote_sha: String,
    /// The commit that introduced the payload.
    pub poisoned: String,
    pub poisoned_subject: String,
    /// Cleanup commits after `poisoned` that are folded away.
    pub folded: Vec<String>,
    /// Files restored from the parent (or removed, if the parent lacked them).
    pub restored: Vec<String>,
    /// The rebuilt clean commit, once `build_excise` has run.
    pub rebuilt: Option<String>,
    pub blocked: Option<String>,
}

fn first_parent_line(repo: &Path, git_ref: &str, n: usize) -> Vec<String> {
    let out = util::git(repo, &["rev-list", "--first-parent", "-n", &n.to_string(), git_ref]);
    out.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
}

fn changed_files(repo: &Path, a: &str, b: &str) -> Vec<String> {
    let out = util::git(repo, &["-c", "core.quotepath=off", "diff", "--name-only", "--no-renames", a, b]);
    out.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
}

/// Plan an excision for every remote-tracking branch of `repo`.
pub fn plan_excisions(repo: &Path) -> Vec<ExcisePlan> {
    refs(repo)
        .into_iter()
        .filter(|r| r.starts_with("refs/remotes/"))
        .filter_map(|r| plan_excise(repo, &r))
        .collect()
}

/// Find the commit that brought the payload onto `remote_ref`, if it is recent.
///
/// Walks back from the tip until it finds a commit whose tree is infected while
/// its first parent's is not. Returns `None` when the last `EXCISE_DEPTH`
/// commits are all clean.
pub fn plan_excise(repo: &Path, remote_ref: &str) -> Option<ExcisePlan> {
    let short = remote_ref.trim_start_matches("refs/remotes/");
    let (remote, branch) = short.split_once('/')?;
    let line = first_parent_line(repo, remote_ref, EXCISE_DEPTH + 1);
    let tip = line.first()?.clone();
    // A commit is "touched" if it carries the payload, or if it changes a file
    // the payload lives in (a cleanup).
    let mut infected_at: Vec<Vec<String>> = Vec::new();
    for c in &line {
        infected_at.push(infected_files_on(repo, c));
    }
    // A clean tip whose old infection has real work on top is history, not a
    // branch to repair: `--history` reports it and nothing here can fix it.
    let tip_clean = infected_at[0].is_empty();
    // The newest introduction point: infected, on a clean parent.
    let idx = (0..line.len().saturating_sub(1)).find(|&i| !infected_at[i].is_empty() && infected_at[i + 1].is_empty())?;
    let poisoned = line[idx].clone();
    let parent = line[idx + 1].clone();
    let payload: Vec<String> = infected_at[idx].clone();
    let mut plan = ExcisePlan {
        repo: repo.to_path_buf(),
        remote: remote.to_string(),
        branch: branch.to_string(),
        remote_sha: tip.clone(),
        poisoned: poisoned.clone(),
        poisoned_subject: util::git(repo, &["log", "-1", "--format=%s", &poisoned]).stdout.trim().to_string(),
        folded: line[..idx].to_vec(),
        restored: Vec::new(),
        rebuilt: None,
        blocked: None,
    };

    // The files to put back: the payload, the attack's bookkeeping, and
    // anything a later cleanup commit touched.
    let mut fix: Vec<String> = payload.clone();
    for f in changed_files(repo, &parent, &poisoned) {
        let p = Path::new(&f);
        let bookkeeping = scanner::is_artifact(p) || (is_gitignore(&f) && gitignore_only_hides(repo, &parent, &poisoned, &f));
        if bookkeeping && !fix.contains(&f) {
            fix.push(f);
        }
    }
    // Every commit folded away must be a cleanup: it may only touch files that
    // are part of the infection. Real work landing after the infection cannot
    // be carried across automatically.
    for c in &plan.folded {
        let parents = util::git(repo, &["rev-list", "--parents", "-n", "1", c]);
        if parents.stdout.split_whitespace().count() > 2 {
            plan.blocked = Some(format!("{} is a merge made after the infection - rebase by hand", &c[..10.min(c.len())]));
            return if tip_clean { None } else { Some(plan) };
        }
        for f in changed_files(repo, &format!("{c}^"), c) {
            let p = Path::new(&f);
            let ok = fix.contains(&f)
                || scanner::is_artifact(p)
                || is_gitignore(&f)
                || is_vscode_task_file(&f)
                || scanner::is_config_target(p)
                || f.eq_ignore_ascii_case("package.json")
                || f.ends_with("/package.json");
            if !ok {
                plan.blocked = Some(format!(
                    "real work landed after the infection ({} changes {f}) - rebase it onto {} by hand",
                    &c[..10.min(c.len())],
                    &parent[..10.min(parent.len())]
                ));
                return if tip_clean { None } else { Some(plan) };
            }
            if !fix.contains(&f) {
                fix.push(f);
            }
        }
    }
    fix.sort();
    fix.dedup();
    plan.restored = fix;
    Some(plan)
}

fn is_gitignore(f: &str) -> bool {
    f.rsplit('/').next().map(|n| n.eq_ignore_ascii_case(".gitignore")).unwrap_or(false)
}

fn gitignore_only_hides(repo: &Path, a: &str, b: &str, file: &str) -> bool {
    match (blob_at(repo, a, file), blob_at(repo, b, file)) {
        (Some(x), Some(y)) => scanner::gitignore_without_hidden_artifacts(&x) == scanner::gitignore_without_hidden_artifacts(&y),
        (None, Some(y)) => scanner::gitignore_without_hidden_artifacts(&y).trim().is_empty(),
        _ => false,
    }
}

/// Run git with extra environment and optional stdin.
fn git_env(repo: &Path, args: &[&str], env: &[(&str, &str)], stdin: Option<&[u8]>) -> util::Output {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args);
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let fail = |e: String| util::Output { ok: false, stdout: String::new(), stderr: e };
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(e.to_string()),
    };
    if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
        let _ = si.write_all(data);
    }
    match child.wait_with_output() {
        Ok(o) => util::Output {
            ok: o.status.success(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => fail(e.to_string()),
    }
}

/// Build the clean replacement commit. Writes objects, moves no ref.
pub fn build_excise(plan: &mut ExcisePlan) -> Result<String, String> {
    if let Some(b) = &plan.blocked {
        return Err(b.clone());
    }
    let repo = plan.repo.clone();
    let c = plan.poisoned.clone();
    let parent = format!("{c}^");
    let index = std::env::temp_dir().join(format!("prh-excise-{}-{}.idx", std::process::id(), &c[..10.min(c.len())]));
    let idx = index.to_string_lossy().to_string();
    let env = [("GIT_INDEX_FILE", idx.as_str())];
    let r = git_env(&repo, &["read-tree", &c], &env, None);
    if !r.ok {
        return Err(format!("read-tree: {}", r.stderr.trim()));
    }
    let mut info = String::new();
    let mut removed: Vec<String> = Vec::new();
    for f in &plan.restored {
        let ls = util::git(&repo, &["ls-tree", &parent, "--", f]);
        let line = ls.stdout.lines().next().unwrap_or("").trim().to_string();
        if line.is_empty() {
            removed.push(f.clone());
        } else {
            info.push_str(&line);
            info.push('\n');
        }
    }
    if !info.is_empty() {
        let r = git_env(&repo, &["update-index", "--index-info"], &env, Some(info.as_bytes()));
        if !r.ok {
            return Err(format!("update-index: {}", r.stderr.trim()));
        }
    }
    for f in &removed {
        let r = git_env(&repo, &["update-index", "--force-remove", "--", f], &env, None);
        if !r.ok {
            return Err(format!("remove {f}: {}", r.stderr.trim()));
        }
    }
    let tree = git_env(&repo, &["write-tree"], &env, None);
    let _ = std::fs::remove_file(&index);
    if !tree.ok {
        return Err(format!("write-tree: {}", tree.stderr.trim()));
    }
    let tree = tree.stdout.trim().to_string();

    // C's identity, dates and exact message.
    let meta = util::git(&repo, &["log", "-1", "--format=%P%x00%an%x00%ae%x00%ad%x00%cn%x00%ce%x00%cd", "--date=raw", &c]);
    let m: Vec<&str> = meta.stdout.trim_end_matches(['\r', '\n']).split('\0').collect();
    if m.len() < 7 {
        return Err("could not read the poisoned commit's metadata".into());
    }
    let raw = util::git(&repo, &["cat-file", "commit", &c]).stdout;
    let message = raw.split_once("\n\n").map(|(_, b)| b).unwrap_or("");
    let mut args: Vec<String> = vec!["commit-tree".into(), tree.clone()];
    for p in m[0].split_whitespace() {
        args.push("-p".into());
        args.push(p.into());
    }
    let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let env = [
        ("GIT_AUTHOR_NAME", m[1]),
        ("GIT_AUTHOR_EMAIL", m[2]),
        ("GIT_AUTHOR_DATE", m[3]),
        ("GIT_COMMITTER_NAME", m[4]),
        ("GIT_COMMITTER_EMAIL", m[5]),
        ("GIT_COMMITTER_DATE", m[6]),
    ];
    let made = git_env(&repo, &argv, &env, Some(message.as_bytes()));
    if !made.ok {
        return Err(format!("commit-tree: {}", made.stderr.trim()));
    }
    let new = made.stdout.trim().to_string();
    // Never push something that is still infected.
    let still = infected_files_on(&repo, &new);
    if !still.is_empty() {
        return Err(format!("rebuilt commit still carries {} - not pushing", still.join(", ")));
    }
    plan.rebuilt = Some(new.clone());
    Ok(new)
}

/// Build and force-push the clean commit over the poisoned branch.
///
/// The lease pins the push to the tip that was audited: if anyone pushed in the
/// meantime, nothing is overwritten.
pub fn apply_excise(plan: &mut ExcisePlan, dry: bool) -> Result<String, String> {
    let new = build_excise(plan)?;
    let short = |s: &str| s[..10.min(s.len())].to_string();
    if dry {
        return Ok(format!(
            "would replace {}/{} {} with {} ('{}', {} file(s) restored, {} cleanup commit(s) folded)",
            plan.remote,
            plan.branch,
            short(&plan.remote_sha),
            short(&new),
            plan.poisoned_subject,
            plan.restored.len(),
            plan.folded.len()
        ));
    }
    let lease = format!("--force-with-lease=refs/heads/{}:{}", plan.branch, plan.remote_sha);
    let spec = format!("{new}:refs/heads/{}", plan.branch);
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
    Ok(format!("{}/{} now at {} (was {}) - poisoned commit removed", plan.remote, plan.branch, short(&new), short(&plan.remote_sha)))
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
