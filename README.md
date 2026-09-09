# polinrider-hunter

<!-- POLINRIDER-HUNTER-DETECTOR: this file documents malware signatures. Not malware. -->

Finds and removes the **PolinRider** supply-chain malware from developer machines
and git repositories, then keeps watching so it cannot come back quietly.

One binary. No runtime to install, no dependencies to audit — the whole thing is
Rust standard library, on purpose.

## Install

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/OWNER/polinrider-hunter/main/install.ps1 | iex
```

**Linux / macOS**:

```sh
curl -fsSL https://raw.githubusercontent.com/OWNER/polinrider-hunter/main/install.sh | sh
```

Either installs the binary to a user directory (no administrator or root),
sweeps the whole machine and cleans what it finds, then registers the background
guard. Run it once. Replace `OWNER` with wherever the repository lives, or set
`POLINRIDER_REPO`.

Both prefer a published release binary and fall back to building from source
with `cargo`; if neither is possible they say exactly what is missing rather
than failing quietly.

Already have the binary?

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
untouched. It runs on any `dev`, `build` or `lint` that loads the config — and
also inside your editor, since extensions like ESLint and Tailwind IntelliSense
execute the project config in their own Node process.

**2. It resolves its C2 from the Ethereum blockchain.** Rather than a domain that
can be taken down, stage 1 reads the most recent transaction from a hardcoded
sender address using public RPC endpoints, and decodes two IPv4 addresses out of
the transaction's `to` field — bytes 0-3 and 4-7. The operator moves the C2 by
sending a cheap transaction. Nothing to seize, nothing to blocklist. This
technique is generally called *EtherHiding*.

**3. It fetches stage 2 over plain HTTP on port 443.** Port 443 carrying
cleartext looks like TLS to anything counting ports. The request wears a spoofed
Chrome `User-Agent` and carries the campaign id in a `Sec-V` header; the response
can deliver the payload in an `X-Payload-B64` header so a `HEAD` request leaves
no body to inspect. It is XOR-encrypted with a key baked into stage 1.

**4. It runs stage 2 twice — once visibly, once not.** In-process via `eval`, and
again as:

```js
spawn("node", ["-e", env + code], { detached: true, stdio: "ignore", windowsHide: true }).unref()
```

A hidden, detached interpreter with no console and no parent, which outlives the
build that started it. `require` and `module` are handed across through globals,
so stage 2 has the full run of Node.

**Other shapes seen:** a NestJS `src/main.ts` with an injected
`import 'dotenv/config'` plus an IIFE that `atob`-decodes `AUTH_API_KEY` into a
URL, fetches code and `eval`s it — fed by a dropped `.env` containing only that
key; and a `.vscode/tasks.json` that auto-runs a payload disguised as a webfont
on `folderOpen`, armed by `task.allowAutomaticTasks`.

---

## Why it kept coming back

The scanners already guarding these repos matched `global\.i=`. The live variant
writes `global.i = '...'` **with spaces**, and pads with tabs instead of spaces.
That one character of whitespace walked it past every gate — local pre-commit
hook, CI job, and Docker build check — for months, while each of them reported
"clean".

So this tool does not rely on a string list alone.

---

## How detection works

Three layers, deliberately independent:

| Layer | Catches | Weakness it covers |
|---|---|---|
| **Signatures** | Known strings: the sender address, `/0x/cls`, `X-Payload-B64`, `global['!']`, `_$_1e42`, `AUTH_API_KEY`, campaign tags | Fast and precise, but only for variants we have seen |
| **Structure** | A run of ≥200 spaces/tabs followed by code | Variant-agnostic. A new build can change every string it contains, but not this — the padding *is* the camouflage, and dropping it means showing up in the editor |
| **Process** | Running `node -e` whose command line carries the stage-2 globals (`global['_V']`, `global['_t_s']`, …) | Finds an infection whose file you already cleaned, or that arrived by another route entirely |

The process layer is not theoretical: it is what found a live stage 2 on the
machine this tool was written on — parented by the editor, C2 already resolved,
long after the repositories themselves were clean.

**Severity matters.** `Critical` means unambiguous, and is safe to remove
automatically. `Suspicious` means consistent with PolinRider but plausible in
honest code — Ethereum RPC hostnames, `windowsHide` — and is only ever reported.
Padding alone is treated as critical *but only inside a file PolinRider is known
to target*; elsewhere it asks a human to look.

### Not flagging the detectors

Every malware scanner contains the strings it hunts for, so any file containing

```
POLINRIDER-HUNTER-DETECTOR
```

is skipped wherever it lives. That is better than us maintaining a list of
everyone's filenames — a project opts its own gate out explicitly, and the
exemption travels with the file. A short list of well-known gate filenames
(`check-malware.mjs`, `security-malware-scan.yml`, …) is skipped too.

---

## How removal works

Two rules:

**Quarantine before writing.** Every original is copied to
`<home>/quarantine/` and indexed in `index.jsonl` before anything is modified. A
wrong cut is always recoverable. `polinrider-hunter quarantine` lists them.

**Never rewrite bytes we did not mean to change.** The obvious implementation —
read to lines, edit, write lines back — silently rewrites every line ending in
the file. On a CRLF repository that turns a one-line security fix into a
whole-file diff, and buries the actual change in noise. So the healer splices the
byte buffer and leaves every other byte untouched. This is verified against real
samples: healing the live payload out of an infected `postcss.config.mjs`
produces a file **byte-identical** to the hand-reviewed fix.

The cut point is the *start of the whitespace pad*, so the camouflage goes with
the payload. For the `src/main.ts` shape it excises the `(async () => { … })();`
block and the injected `dotenv/config` import. A `.env` is deleted outright —
and untracked from git — but only when `AUTH_API_KEY` is essentially all it
contains; a real `.env` that merely picked up the key is never destroyed.

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

scan [paths...]        Report only. Exit 1 if anything critical.
clean [paths...]       Scan, then remove payloads. --dry-run to preview.
repos [paths...]       Fetch and audit every branch, local and remote-tracking.
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

**How long it takes.** A first full hunt is minutes, not seconds — it is reading
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

Once the guard is installed you do not pay this cost again — its quick pass reads
only the ~30 filenames PolinRider targets, and only when one of them changes.

Exit codes: `0` clean, `1` something found, `2` bad usage.

### Auditing branches without pulling

```
polinrider-hunter repos ~/work/some-repo
```

`git grep` searches any ref straight out of the object database, so this fetches
and then reads `refs/remotes/*` — no pull, no merge, nothing written to your
working tree. When what you are looking for is malware, you want to know what is
on a branch *before* it lands on disk in a form something might execute.

Candidates from `git grep` are then re-checked with the real matcher, so CI gates
and scanners on those branches do not show up as infections.

---

## The background guard

Three cadences, because the cheap check is the one worth running often:

- **quick** (30s) — reads only the ~30 filenames PolinRider targets, and only
  when their mtime moved. Catches a fresh infection within half a minute at
  essentially no cost.
- **full** (15m) — walks the watched trees properly, in case a variant picks a
  filename we have not seen.
- **git** (1h) — fetches and audits every ref, reporting anything upstream.

It also checks for hidden stage-2 processes on every quick pass.

**What it will not do.** The guard heals working trees. It never rewrites git
history and it never pushes. An automated process that force-pushes to shared
branches is a worse problem than the one it is solving, so `repos` reports what
it finds on a branch and leaves the decision to you.

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

## Build

```
cargo build --release      # target/release/polinrider-hunter
cargo test                 # 44 unit + 14 end-to-end tests
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

Requires only a Rust toolchain. No network access needed at build time — there is
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
