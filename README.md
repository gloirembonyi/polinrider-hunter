# polinrider-hunter

<!-- POLINRIDER-HUNTER-DETECTOR: this file documents malware signatures. Not malware. -->

Finds and removes the **PolinRider** supply-chain malware from developer machines
and git repositories, then keeps watching so it cannot come back quietly.

Since 1.1 it also covers the other developer-targeted campaigns of 2025–26 —
the **Shai-Hulud** npm worm, **GlassWorm**'s invisible-Unicode payloads in editor
extensions, the **npm-loader** (`runtimedev-link`) variant of the AppData
campaign, **Contagious Interview** keylogger kits, injected **git config**
(`core.fsmonitor`, hooks, nested bare repositories — "GitSpawn"), install-script
droppers, pwn-request workflows and **ClickFix** run history — and it can repair
a **poisoned remote branch** (`repos --fix`). Since 1.2 there is an **AI
incident-response agent** (`agent`): a Gemini model with all of the above as
tools, plus file reading, git history, process/persistence listing, web search
and hash lookups — every change to your machine shown to you for a `y` first.
The step-by-step is in [`docs/GUIDE.md`](docs/GUIDE.md).

One binary. No runtime to install, no dependencies to audit - the whole thing is
Rust standard library, on purpose.

## Install

The page at [`docs/`](docs/) carries the installers and a prebuilt Windows
binary, so once it is deployed the one-liner works with no GitHub release
involved.

**Windows** (PowerShell):

```powershell
irm https://gloirembonyi.github.io/polinrider-hunter/install.ps1 | iex
```

**Linux / macOS**:

```sh
curl -fsSL https://gloirembonyi.github.io/polinrider-hunter/install.sh | sh
```

Either puts the binary in a user directory (no administrator or root), sweeps the
whole machine and cleans what it finds, then registers the background guard. Run
it once.

Each prefers the prebuilt binary published next to the script, falls back to a
GitHub release when `POLINRIDER_REPO` is set, and finally to building from source
with `cargo` - and when none of those is possible it says which, rather than
failing quietly. It also verifies that what it downloaded is genuinely an
executable, because a static host answers `200` with an HTML error page for a
missing path and piping that into place would be worse than failing.

Environment overrides:

| | |
|---|---|
| `POLINRIDER_SITE` | where to fetch the binary from (default: the deployed site) |
| `POLINRIDER_REPO` | `owner/repo` for the release and source-build paths (default: `gloirembonyi/polinrider-hunter`) |
| `POLINRIDER_NO_HUNT=1` | install the binary but skip the initial sweep |
| `POLINRIDER_NO_INSTALL=1` | install the binary but do not start the guard |
| `POLINRIDER_BIN` | install directory (unix; default `~/.local/bin`) |

No binary yet, or building it yourself?

```
cargo build --release
./target/release/polinrider-hunter hunt      # clean this machine now
./target/release/polinrider-hunter install   # then keep it clean
```

Already have it on PATH?

```
polinrider-hunter hunt             # clean this machine now, no setup needed
polinrider-hunter install          # then keep it clean
polinrider-hunter status           # what the guard is doing
```

---

## What PolinRider does

Worth understanding, because it explains every design decision below.

**1. It hides in a build config.** The payload is appended to *one line* of a
file like `postcss.config.mjs`, `tailwind.config.js`, `eslint.config.mjs`,
`vite.config.ts` or `nest-cli.json`, behind roughly 500 characters of spaces or
tabs. In an editor the code sits far off the right edge; in a diff the line looks
untouched. It runs on any `dev`, `build` or `lint` that loads the config - and
also inside your editor, since extensions like ESLint and Tailwind IntelliSense
execute the project config in their own Node process.

**2. It resolves its C2 from the Ethereum blockchain.** Rather than a domain that
can be taken down, stage 1 reads the most recent transaction from a hardcoded
sender address using public RPC endpoints, and decodes two IPv4 addresses out of
the transaction's `to` field - bytes 0-3 and 4-7. The operator moves the C2 by
sending a cheap transaction. Nothing to seize, nothing to blocklist. This
technique is generally called *EtherHiding*.

**3. It fetches stage 2 over plain HTTP on port 443.** Port 443 carrying
cleartext looks like TLS to anything counting ports. The request wears a spoofed
Chrome `User-Agent` and carries the campaign id in a `Sec-V` header; the response
can deliver the payload in an `X-Payload-B64` header so a `HEAD` request leaves
no body to inspect. It is XOR-encrypted with a key baked into stage 1.

**4. It runs stage 2 twice - once visibly, once not.** In-process via `eval`, and
again as:

```js
spawn("node", ["-e", env + code], { detached: true, stdio: "ignore", windowsHide: true }).unref()
```

A hidden, detached interpreter with no console and no parent, which outlives the
build that started it. `require` and `module` are handed across through globals,
so stage 2 has the full run of Node.

**Other shapes seen:** a NestJS `src/main.ts` with an injected
`import 'dotenv/config'` plus an IIFE that `atob`-decodes `AUTH_API_KEY` into a
URL, fetches code and `eval`s it - fed by a dropped `.env` containing only that
key; and a `.vscode/tasks.json` that auto-runs a payload disguised as a webfont
on `folderOpen`, armed by `task.allowAutomaticTasks`.

---

## Why it kept coming back

The scanners already guarding these repos matched `global\.i=`. The live variant
writes `global.i = '...'` **with spaces**, and pads with tabs instead of spaces.
That one character of whitespace walked it past every gate - local pre-commit
hook, CI job, and Docker build check - for months, while each of them reported
"clean".

So this tool does not rely on a string list alone.

---

## How detection works

Three layers, deliberately independent:

| Layer | Catches | Weakness it covers |
|---|---|---|
| **Signatures** | Known strings: the sender address, `/0x/cls`, `X-Payload-B64`, `global['!']`, `_$_1e42`, `AUTH_API_KEY`, campaign tags | Fast and precise, but only for variants we have seen |
| **Structure** | A run of ≥200 spaces/tabs followed by code | Variant-agnostic. A new build can change every string it contains, but not this - the padding *is* the camouflage, and dropping it means showing up in the editor |
| **Process** | Running `node -e` whose command line carries the stage-2 globals (`global['_V']`, `global['_t_s']`, …) | Finds an infection whose file you already cleaned, or that arrived by another route entirely |

The process layer is not theoretical: it is what found a live stage 2 on the
machine this tool was written on - parented by the editor, C2 already resolved,
long after the repositories themselves were clean.

**Severity matters.** `Critical` means unambiguous, and is safe to remove
automatically. `Suspicious` means consistent with PolinRider but plausible in
honest code - Ethereum RPC hostnames, `windowsHide` - and is only ever reported.
Padding alone is treated as critical *but only inside a file PolinRider is known
to target*; elsewhere it asks a human to look.

### Not flagging the detectors

Every malware scanner contains the strings it hunts for, so any file containing

```
POLINRIDER-HUNTER-DETECTOR
```

is skipped wherever it lives. That is better than us maintaining a list of
everyone's filenames - a project opts its own gate out explicitly, and the
exemption travels with the file. A short list of well-known gate filenames
(`check-malware.mjs`, `security-malware-scan.yml`, …) is skipped too.

---

## How removal works

Two rules:

**Quarantine before writing.** Every original is copied to
`<home>/quarantine/` and indexed in `index.jsonl` before anything is modified. A
wrong cut is always recoverable. `polinrider-hunter quarantine` lists them.

**Never rewrite bytes we did not mean to change.** The obvious implementation -
read to lines, edit, write lines back - silently rewrites every line ending in
the file. On a CRLF repository that turns a one-line security fix into a
whole-file diff, and buries the actual change in noise. So the healer splices the
byte buffer and leaves every other byte untouched. This is verified against real
samples: healing the live payload out of an infected `postcss.config.mjs`
produces a file **byte-identical** to the hand-reviewed fix.

The cut point is the *start of the whitespace pad*, so the camouflage goes with
the payload. For the `src/main.ts` shape it excises the `(async () => { … })();`
block and the injected `dotenv/config` import. A `.env` is deleted outright -
and untracked from git - but only when `AUTH_API_KEY` is essentially all it
contains; a real `.env` that merely picked up the key is never destroyed.

---

## Every technique, and what happens to it

| PolinRider technique | Detected by | Removal |
|---|---|---|
| Payload appended to a build config behind ~500 chars of space/tab padding (`postcss.config.mjs`, `tailwind.config.js`, `eslint.config.mjs`, `vite.config.ts`, `nest-cli.json`) | signatures + the padding heuristic | cut from the start of the pad to end of line, byte-exact |
| The same, re-applied several times (reinfection) | as above | cut repeatedly until the file is clean; a second pass must find nothing |
| Injected `createRequire` shim that manufactures `require()` for an ESM config | correlated with the payload | removed with the payload, but only when nothing else uses `require` |
| `global.i = '...'` written **with spaces**, tab padding | `global\.i\s*=`, and the padding heuristic regardless of spelling | as above |
| Obfuscated variant: `global['!']`, `_$_1e42` shuffle decoder, modulus `4573868` | signatures | as above |
| Ethereum dead-drop C2 (`0xa322…`, public RPC hosts, `eth_getBlockByNumber`) | signatures; RPC hosts are corroborating-only | n/a - evidence, not a payload |
| Stage-2 fetch over plain HTTP on port 443, `X-Payload-B64`, `/0x/cls`, `/0x/ls` | signatures | as above |
| NestJS `src/main.ts` dropper: injected `import 'dotenv/config'` + `(async () => { atob(AUTH_API_KEY) … eval })();` | signatures | the IIFE block and the injected import are excised; the bootstrap either side is untouched |
| Dropped `.env` carrying only `AUTH_API_KEY` | signatures | file deleted and untracked from git - but only if the key is essentially all it holds |
| Payload disguised as a webfont (`public/fonts/*.woff2` that is really JavaScript) | font magic bytes vs. extension | file deleted |
| `.vscode/tasks.json` auto-running the payload on `folderOpen` | signatures (`node ./public/fonts`) | **reported, never auto-edited** - splicing JSON would corrupt it, so it names the entry for you to delete |
| `task.allowAutomaticTasks` arming that task | value-aware check | reported; `"off"` is the hardened setting and is never flagged |
| Config re-saved as **UTF-16** to slip past NUL-based "binary" checks | BOM detected and the text decoded | reported; automatic removal disabled, because the offsets belong to the decoded text |
| Hidden, detached stage 2 (`node -e` with `windowsHide`, `detached`, `.unref()`) | its command line carries the stage-2 globals | process terminated |

Anything the tool will not clean automatically is reported with the reason,
rather than guessed at. Two of those decisions - JSON and UTF-16 - exist because
a byte-level cut is the right tool for an appended payload and the wrong tool for
structured or wide-character text. There are tests holding both lines.

---

## Resource use

Measured on the machine it was built on, guarding seven repositories:

| | |
|---|---|
| Quick pass (every 30s) | **0.020s CPU**, no directory walking at all |
| Full pass (every 15m) | ~1.3s CPU |
| Resident memory | **4.7 MB** |
| Priority | **BelowNormal** - it yields to whatever you are doing |

Three things get it there:

- **The quick pass never walks.** It `stat`s a precomputed list of concrete
  target paths and reads a file only when its mtime has actually moved. An
  earlier version re-walked every repository twice a minute - thousands of
  directory reads to discover nothing had changed.
- **One indexed pass, not twenty-five.** Each indicator is bucketed by the byte
  it can start on, so at any position only the one or two that could match are
  tested. It used to run a separate full search per indicator.
- **Exemption checks come last.** Deciding "is this file a scanner rather than
  malware?" costs ten full searches, so it now runs only when there is a hit to
  suppress. Clean files - almost all of them - cost exactly one pass.

Together those took a sweep of a JavaScript-heavy tree (1,768 candidate files)
from **66.8s to 1.6s**, a 40x improvement, with identical results.

---

## Commands

```
hunt                   Sweep this whole machine: stop any running loader, find
                       every infected file under your home directory, clean it.
                       No setup required. --drives covers every drive.
install [paths...]     Watch these directories, install a pre-commit hook in each
                       repo, sweep them now, and start a guard at every login.
status                 Where everything lives; whether the guard is alive.
uninstall              Stop the guard, remove the hooks.

agent [paths...]       AI investigation with human approval of every change
                       (needs a free Gemini key: `set-key <KEY>`). --task "…"
                       for one job, --yes to pre-approve.
report [paths...]      Written incident report (AI root-cause with a key).
set-key <KEY>          Store the Gemini key (--model, --vt-key optional).
scan [paths...]        Report only. Exit 1 if anything critical.
clean [paths...]       Scan, then remove payloads. --dry-run to preview.
repos [paths...]       Fetch and audit every branch, local and remote-tracking,
                       plus each repo's git config and hooks. --fix repairs a
                       poisoned remote branch (see below).
procs                  List hidden stage-2 processes. --kill stops them.
protect / unprotect    Just the pre-commit hook.
quarantine             List the originals kept aside.
```

Flags: `--json`, `--dry-run`, `--quick`, `--no-fetch`, `--kill`, `--drives`,
`--interval <secs>`, `--no-autostart`, `--no-color`.

### Getting it off the machine entirely

```
polinrider-hunter hunt --drives
```

`hunt` is the command for "remove this from my computer". It does three things,
in an order that matters:

1. **Stops any running loader first.** A live stage 2 can drop a fresh payload
   into a directory the scan has already walked past, so stopping it before
   scanning is what makes the sweep hold.
2. **Finds every project on the machine**, not just configured ones - the whole
   home directory by default, every drive with `--drives`. Operating-system,
   vendor and package-cache directories are skipped, because PolinRider lives in
   project trees and walking a Rust registry or the Windows directory would take
   hours for nothing.
3. **Cleans each hit**, quarantining the original first, and reports anything it
   will not touch automatically instead of guessing.

`--dry-run` shows what it would do and writes nothing.

**How long it takes.** A first full hunt is minutes, not seconds - it is reading
every candidate file under your home directory. It prints each directory as it
enters it, so you can see where it is. Two things keep it bounded:

- Operating-system, vendor and package-cache directories are skipped
  (`.cargo`, `.npm`, `node_modules`, the Windows directory, and so on).
- Files over 1 MB are skipped **unless** the filename is one PolinRider targets.
  The attack appends to a hand-maintained build config, and those are kilobytes;
  past a megabyte you are looking at a bundle or a lockfile. Reading a few
  hundred megabytes of editor-extension bundles and running every indicator over
  each was the difference between seconds and many minutes.

  That is a real trade-off, stated rather than hidden: a payload appended to a
  multi-megabyte bundle would be missed. Target filenames are exempt and always
  read in full.

Once the guard is installed you do not pay this cost again - its quick pass reads
only the ~30 filenames PolinRider targets, and only when one of them changes.

Exit codes: `0` clean, `1` something found, `2` bad usage.

### Auditing branches without pulling

```
polinrider-hunter repos ~/work/some-repo
```

`git grep` searches any ref straight out of the object database, so this fetches
and then reads `refs/remotes/*` - no pull, no merge, nothing written to your
working tree. When what you are looking for is malware, you want to know what is
on a branch *before* it lands on disk in a form something might execute.

Candidates from `git grep` are then re-checked with the real matcher, so CI gates
and scanners on those branches do not show up as infections.

---

## The background guard

Three cadences, because the cheap check is the one worth running often:

- **quick** (30s) - reads only the ~30 filenames PolinRider targets, and only
  when their mtime moved. Catches a fresh infection within half a minute at
  essentially no cost.
- **full** (15m) - walks the watched trees properly, in case a variant picks a
  filename we have not seen.
- **git** (1h) - fetches and audits every ref, reporting anything upstream.

It also checks for hidden stage-2 processes on every quick pass.

**What it will not do.** The guard heals working trees. It never rewrites git
history and it never pushes. An automated process that force-pushes to shared
branches is a worse problem than the one it is solving, so the *guard* only
reports what it finds on a branch.

### Repairing a poisoned remote: `repos --fix`

The campaign's propagation step re-pushes the victim's own latest commit with
the payload appended — same message, same author date — so the remote branch
sits one rewritten commit "ahead" of the clean local one, and `git pull` would
bring the infection down. `repos --fix` is the deliberate, human-invoked repair:

```
polinrider-hunter repos --fix --dry-run ~/work/repo   # print the exact push
polinrider-hunter repos --fix ~/work/repo             # do it, then re-fetch and re-audit
```

It pushes the clean local branch with `git push --force-with-lease=<branch>:<audited sha>`
so a concurrent push fails instead of being erased, and it refuses (**BLOCKED**,
with the reason) unless a local branch tracks the remote one, that local branch
is clean, and *every* commit the remote has beyond it touches an infected file.
Real work on the remote is never discarded; you are told which commit to merge
first. The end-to-end suite stands up a bare "origin", poisons it the way the
campaign does, and proves the branch comes back byte-identical.

## Beyond PolinRider: what else is covered

| Campaign | Hides as | Detected by | Removed? |
|---|---|---|---|
| npm-loader (`runtimedev-link`) | Startup `.vbs` → `npx -y runtimedev-link --token <C2>`; `agent.env`; task XML | markers + drop-dir scan + npx-cache check | shim/Run key/task removed, files deleted, cached package dir deleted |
| Shai-Hulud v1/v2 | `postinstall: node bundle.js`, `preinstall: setup_bun.js`, TruffleHog, `shai-hulud-workflow.yml` | lifecycle-script check, names | reported (JSON is never spliced) |
| GlassWorm | thousands of invisible variation selectors on a "blank" line, `codePointAt - 0xE0100` decoder, Solana memo C2 | invisible-run structural check (any variant), decoder + RPC corroboration | the invisible line is cut; code around it kept |
| Contagious Interview | `node-global-key-listener` + `screenshot-desktop`, folderOpen tasks | dependency pair | reported |
| Git config injection / GitSpawn | `core.fsmonitor`, `core.pager`, `credential.helper !cmd`, filter drivers, hooks, nested `.git`/bare repos in the tree | `.git/config` + hooks + nested audit (in `scan`, `clean`, `hunt`, `repos`) | `core.fsmonitor` and fetch-and-run values unset; hooks and nested repos reported |
| Install-script droppers | `curl \| sh`, `node -e`, base64 in `preinstall`/`postinstall` | fetch-and-execute shape | reported |
| Pwn-request workflows | `pull_request_target` + checkout of the PR head | workflow check | reported |
| ClickFix | `mshta`/`powershell -enc … \| iex` pasted into Win+R | Run-dialog history | reported as evidence |

The Startup-folder sweep is content-based: a script is removed only when it
names the fake NGEN path, `NativeImageGen`, the `Caches\cversions` drop dir, the
npm loader or a C2 address. Your own launchers are never touched.

Autostart is a plain text file you can read and delete:

| OS | Mechanism |
|---|---|
| Windows | `PolinRiderHunter.vbs` in the Startup folder (a one-line launcher, because a Startup shortcut to a console binary flashes a window) |
| macOS | `~/Library/LaunchAgents/com.polinrider.hunter.plist` |
| Linux | `~/.config/systemd/user/polinrider-hunter.service` |

`status` prints the exact path. A security tool that installs itself somewhere
you cannot find is behaving like the thing it removes.

Liveness is judged by heartbeat freshness rather than a PID, which needs no
platform process API and cannot be fooled by PID reuse.

---

## State

| Path | |
|---|---|
| `%LOCALAPPDATA%\polinrider-hunter` (Windows) | config, log, quarantine |
| `$XDG_DATA_HOME/polinrider-hunter` or `~/.local/share/...` | same, elsewhere |

Override with `POLINRIDER_HOME`. `config.txt` is `key = value`, hand-editable,
with `path` repeating once per directory.

---

## The page

<https://gloirembonyi.github.io/polinrider-hunter>

[`docs/`](docs/) is a static page - `index.html`, `styles.css`, `app.js`, no
build step - that explains all of this to someone who has just been told their
machine might be infected. It carries the installers and the Windows binary, so
publishing it is what makes the one-liner work.

Served by GitHub Pages from `main` / `/docs`. See [`docs/README.md`](docs/README.md)
for how it is wired and how to add macOS and Linux binaries.

---

## Build

```
cargo build --release      # target/release/polinrider-hunter
cargo test                 # unit tests + tests/end_to_end.rs + tests/campaigns.rs
```

The end-to-end suite in `tests/` is the one worth reading. It plants each real
attack shape on disk - spaced and tab-padded config payloads in both CRLF and
LF, the NestJS `eval` dropper, the dropped `.env`, JavaScript wearing a `.woff2`
extension - then asserts the payload is gone, the legitimate code around it is
byte-for-byte unchanged, a second pass finds nothing (removal is complete, not
partial), and the quarantined original still matches what was on disk. It also
covers the cases where the tool must *not* act: a real `.env` holding genuine
secrets, a genuine webfont, a markdown table, a CI gate.

Payloads in the suite are inert - the recognisable shape of PolinRider with a
harmless body - so running the tests never puts working malware on disk.

Requires only a Rust toolchain. No network access needed at build time - there is
nothing to download, which is a deliberate property for a tool whose entire
purpose is supply-chain compromise.

Cross-compiling, e.g. for a Linux CI image:

```
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```

---

## Use in CI

```yaml
- run: polinrider-hunter scan . --json
```

Exits 1 on anything critical, so the job fails. `clean` in a pre-commit hook
heals and re-stages automatically; if it cannot produce a clean file it blocks
the commit rather than guessing.

---

## A note on antivirus

Windows Defender detects the older obfuscated variant as
`Trojan:NPM/PolinRider.DB!MTB` / `.SB`. Two consequences:

- Writing a sample to disk for testing will have it removed under you.
- A file Defender has locked cannot be read, and a scanner that treats an
  unreadable file as a clean one hides the strongest available signal behind a
  silent skip. This tool reports it as `read-blocked` instead.

Defender did **not** flag the newer spaced-`global.i` variant. Signature coverage
is not the same as coverage.
