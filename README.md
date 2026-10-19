# polinrider-hunter

<!-- POLINRIDER-HUNTER-DETECTOR: this file documents malware signatures. Not malware. -->

Finds and removes the **PolinRider** supply-chain malware from developer machines
and git repositories, then keeps watching so it cannot come back quietly.

Since 1.1 it also covers the other developer-targeted campaigns of 2025–26 -
the **Shai-Hulud** npm worm, **GlassWorm**'s invisible-Unicode payloads in editor
extensions, the **npm-loader** (`runtimedev-link`) variant of the AppData
campaign, **Contagious Interview** keylogger kits, injected **git config**
(`core.fsmonitor`, hooks, nested bare repositories - "GitSpawn"), install-script
droppers, pwn-request workflows and **ClickFix** run history - and it can repair
a **poisoned remote branch**. Since 1.2 there is an **AI incident-response
agent** (`agent`): a model from the provider of your choice (Claude, OpenAI,
Gemini, a local Ollama…) with all of the above as tools, plus file reading, git
history, process/persistence listing, web search and hash lookups - every change
to your machine shown to you for a `y` first.

Since 1.3 the default branch repair is **`repos --repair`**: one ordinary commit
on top of each infected remote branch, built inside git's object database
without checking anything out and pushed as a fast-forward - never a force push,
so it is safe on branches a team shares. The `api.js` dropper shape is detected
by its form alone, under any name. And the binary is an **MCP server**
(`polinrider-hunter mcp`), so Claude Code, Cursor, Codex or Windsurf can drive
it with no API key of ours. The step-by-step is in
[`docs/GUIDE.md`](docs/GUIDE.md); agents should read [`AGENTS.md`](AGENTS.md)
and [`SKILL.md`](SKILL.md).

**Already infected?** Cleaning the files is half the job - whatever ran as you also took
your git credentials and your tokens. [`docs/AFTER_AN_INFECTION.md`](docs/AFTER_AN_INFECTION.md)
is the 30-minute runbook for taking that access back.

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

One shape needs no such caution. The `api.js` dropper is a file that is
*nothing but* a line of 200 or more tabs or spaces followed by a kilobyte or
more of code. No honest source file begins with 200 blank columns, so that
shape is critical whatever the file is called (`api.js`, a font name, a
`.dat`) and whether or not any known string matches - before 1.3 it passed
branch audits as clean unless its obfuscator happened to emit a signature. A
`package.json` script that runs such a file (`"dev": "node api.js && next
dev"`) is flagged with it, as `script-runs-dropper`, because that hook is what
makes every `npm run dev` execute the payload. Fake fonts now include the
`.lfk` spelling alongside `.llf` and `.lkf`.

Every git command the tool runs - audits, fetches, the agent's own `git
status` - has `core.fsmonitor`, hooks and the pager switched off, so auditing
a hostile repository cannot execute that repository's config.

### Not flagging the detectors

Every malware scanner contains the strings it hunts for, so any file containing

```
POLINRIDER-HUNTER-DETECTOR
```

is skipped wherever it lives. That is better than us maintaining a list of
everyone's filenames - a project opts its own gate out explicitly, and the
exemption travels with the file. A short list of well-known gate filenames
(`check-malware.mjs`, `security-malware-scan.yml`, …) is skipped too.

The marker is public - it is in this README - so it cannot excuse a padded
dropper or a script that runs one. A scanner quotes indicator *strings*; it
does not begin with a 200-column pad and kilobytes of code.

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
| The `api.js` dropper: one line of 200+ tabs/spaces, then ≥1 KB of code, nothing else - under any name | file shape alone (`padded-dropper`); the detector marker cannot exempt it | file deleted; on a branch, removed by `--repair` |
| `package.json` script running that file (`node api.js && …`) | `script-runs-dropper` - the script's target is read and checked | reported locally (JSON is never spliced); the hook is dropped by `--repair` on a branch |
| Fake font under a third spelling, `.lfk` | font magic bytes vs. extension | file deleted |
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

agent [paths...]       Chat with an AI agent that does real work in your terminal:
                       malware response, branch repair, file edits, builds,
                       tests, any command - every change shown first by default.
                       --task "…" for one job, --mode read-only|ask|
                       workspace-write|full-access, --investigate.
ai [setup|key|use|mode|test|remove]
                       AI providers: anthropic (Claude), openai, gemini (free),
                       openrouter, groq, deepseek, ollama (local), any
                       OpenAI-compatible endpoint. `ai setup` is guided;
                       `ai key <provider>` asks for the key - never put one
                       on the command line.
mcp                    Serve the hunter's tools to another AI agent over MCP
                       on stdio (Claude Code, Cursor, Codex, Windsurf). No key
                       of ours. Destructive tools dry-run first and need a
                       second call with confirm:true. See below.
report [paths...]      Written incident report (AI root-cause with a provider).
set-key                Store a Gemini key (older shortcut for `ai key gemini`);
                       asks for the key rather than taking it as an argument.
scan [paths...]        Report only. Exit 1 if anything critical.
clean [paths...]       Scan, then remove payloads. --dry-run to preview.
repos [paths|urls...]  Fetch and audit every branch, local and remote-tracking,
                       plus each repo's git config and hooks. A URL is audited
                       through a bare clone in a temp dir, nothing checked out.
                       --repair cleans each infected remote branch with ONE
                       forward commit, no force push (the default repair; see
                       below); --fix force-with-lease-pushes a clean local
                       branch; --excise removes the poisoned commit itself;
                       --history audits old commits too, not just the tips.
procs                  List hidden stage-2 processes. --kill stops them.
protect / unprotect    Just the pre-commit hook.
quarantine             List the originals kept aside.
```

Flags: `--json`, `--dry-run`, `--quick`, `--no-fetch`, `--history`, `--repair`, `--fix`, `--excise`, `--kill`, `--drives`,
`--interval <secs>`, `--no-autostart`, `--no-color`. Env: `POLINRIDER_SKIP_REMOTES=name,name`
keeps `--repair` off remotes that belong to someone else.

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
reports what it finds on a branch. Repairs are yours to run: `repos --repair`
adds a commit, `--fix` and `--excise` rewrite.

### Repairing a shared branch: `repos --repair`

`--fix` and `--excise` (below) both replace history, so both need a force push,
and both refuse - rightly - once teammates have pushed real work on top of the
infection. On a shared repository that is nearly always. `--repair` leaves
history alone:

```
polinrider-hunter repos --repair --dry-run ~/work/repo   # the plan: which branches, which files
polinrider-hunter repos --repair ~/work/repo             # do it, then re-fetch and re-audit
polinrider-hunter repos --repair https://github.com/you/repo   # not cloned: a bare clone in a temp dir
```

For each infected remote branch it builds **one new commit on top of the
current tip** that removes the infection, and pushes it as an ordinary
fast-forward. If anyone pushed in the meantime the push is rejected
(`someone pushed to origin/main since the audit - nothing was overwritten; run
again`), never overwritten. Nobody's clone breaks; the branch still
fast-forwards for everyone.

Everything happens inside git's object database through a private index. The
infected tree is **never checked out**, so nothing that could execute the
payload - an editor extension loading a config, a live stage 2 re-infecting
whatever folder it sees, `npm run dev` - ever gets a copy on disk. That last
one is not hypothetical: on 2026-10-11 a worktree-based cleanup was re-infected
*while it ran* and committed a fresh `api.js` under the message "remove
injected PolinRider malware".

What the commit removes: the padded payload lines in config files; padded
droppers (`api.js` and its font-named twins); `node api.js &&` hooks in
`package.json` scripts; appended config payloads; folder-open `.vscode` tasks
and the `task.allowAutomaticTasks` arming; fake fonts; the dropped artefacts
`branch_structure.json`, `config.bat`, `temp_*push.bat`; and the `.gitignore`
lines that hid them. The result is re-audited before it is pushed - a commit
that would still carry an indicator is never pushed - and the branch is
re-fetched and re-audited after.

It refuses, with the reason, when the matcher flagged a file this repair does
not know how to clean (look at it by hand), and `POLINRIDER_SKIP_REMOTES=upstream,fork`
keeps it off remotes that are somebody else's repository. `--json` prints one
`{"type":"repair",…}` object per branch with `ok`, `dry`, `message` and
`actions`.

What it does not do: the poisoned commit stays in history, reachable by hash,
until the owner purges it (`--history` prints the command). A forward commit
makes the branch safe to pull; it does not make the history clean. When you
want the commit itself gone and nobody else works on the branch, that is
`--excise`.

#### Repos you cannot fix

Half the infected branches on a real account belong to someone else - an
organisation, a client, a fork you contributed to. The audit still reads them,
and for each infected branch it reports the repository **owner**, **who pushed**
the infected commits (in this campaign that is the victim whose credential was
stolen, usually not the attacker's own account) and `can_write` - whether the
credentials on this machine can push there. `can_write: false` means ask; the
tool does not try another route.

What to tell that person: run `polinrider-hunter repos --repair` on their
clone - one normal commit, no force push, nothing infected checked out - or
accept a pull request carrying the same change (the repair is an ordinary
commit, so it reviews like one). And that GitHub keeps the poisoned commit in
the repository's history, in every clone, until **they** purge it with the
`git filter-repo` command `--history` prints and ask GitHub to collect the
unreachable objects.

### Repairing a poisoned remote: `repos --fix`

The campaign's propagation step re-pushes the victim's own latest commit with
the payload appended - same message, same author date - so the remote branch
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

A merge commit used to defeat the planner. It asked `git diff-tree` what each
divergent commit changed, and `diff-tree` prints nothing for a merge unless it
is given `-m`/`--cc` - so a branch whose extra history contained a merge looked
like it touched no files, failed the "does this touch the infection?" test, and
was refused with the self-contradicting reason *"changes 0 file(s) that are not
part of the infection"*. That is the common case, not a corner: a campaign that
re-pushes through a pull request produces exactly that shape. The planner now
asks what the remote's extra history changes as a whole (`local...remote`) and
requires every file in it to be an infected one - merge-correct, and stricter
than the old per-commit test, which passed a commit that touched one infected
file and fifty real ones.

### A clean tip is not a clean repository: `repos --history`

`repos` audits ref **tips**, which answers *"what would run if I checked this
out"*. It does not answer *"is the payload still in here"*. Healing a config and
committing the fix leaves the poisoned blob in the object database, reachable by
`git show`, by checking out the old commit, and - once pushed - by anyone who
can read the repository.

```
polinrider-hunter repos --history ~/work/repo
```

This walks every blob reachable from any ref, not just the tips, reading them
through a single `git cat-file --batch` (one child process, not one per object)
and running the real matcher on the bytes - so the detector exemption applies
and a repository's own `check-malware.mjs` is not mistaken for the thing it
hunts. Lockfiles and `node_modules` are skipped.

Each finding is reported with its object id, the path it was stored at, its
indicators and the commits that still hold it. The blob ids are written to a
file in the state directory and the `git filter-repo` command that purges them
is printed. Purging rewrites every commit id, so everyone has to re-clone, and
GitHub keeps unreachable objects until its own GC - it is a deliberate
operation, which is why the tool prints the command instead of running it.

On the three repositories this was built for, every tip audited clean while
**thirteen** payload blobs were still in history: three `src/main.ts` droppers
and a committed `.env`, four `eslint.config.mjs` in the backend, four
`tailwind.config.js` in the mobile app and one `eslint.config.mjs` in the
dashboard. Nothing had reported them, because nothing looked.

## The AI agent: `agent`

`polinrider-hunter agent` is a chat in your terminal with a model that has this
whole tool as its hands. How it works, in one paragraph: you type; the binary
sends the model a fixed system prompt (its method for incidents - triage,
scope, contain, eradicate, root cause, recover, report), the list of its
thirty-odd tools and the conversation; the model answers with *one proposed
tool call*; the binary classifies that call against your permission mode -
readers run at once, changes are shown to you first, a short list is refused
in every mode - runs it itself, and sends the result back, capped at 16 KB and
marked as untrusted data; and round it goes until the model calls `finish`
with a summary, asks you something with `ask_user`, or hits 60 steps in one
turn and pauses. Ctrl-C stops the current step; twice quits.

Permission modes (`--mode`, `/mode`, `ai mode` for the default): `read-only`
(every change refused), `ask` (the default - every change shown as the exact
command, file or diff: `y` / `n` with a reason / `e` edit / `a` always, for that
exact command line / `q`), `workspace-write` (file writes and edits inside the
project directories run freely; everything else asks) and `full-access`
(`--yes`; nothing asks except secret stores, which ask in every mode). A real
push - `repos_repair` with `dry_run: false`, `repos_fix`, `repos_excise` -
asks unless you are in `full-access`, with no "always".

Since 1.3 the agent is harder to turn against you: keys never appear on
`curl`'s command line (headers go through a private temp file); the command
classifier cannot be slipped past with a single `&`, `$()`, backticks, a
redirect, a quoted `powershell -Command`/`cmd /c` body or `git -c`/
`--upload-pack`; secret stores (`.env`, `.ssh`, `.git-credentials`, `gh`
hosts, `.npmrc`, the hunter's own config) are refused unless you approve each
one; `web_fetch` goes without asking only to a built-in list of research
sites, with private, loopback and link-local addresses blocked, redirects
included; every file, command and web result is marked UNTRUSTED and capped at
16 KB; long sessions are compacted to a per-provider context budget; a
`finish` mid-turn is handled; and two tools are new - `repos_repair` (dry run
by default; a real push always asks) and `credential_exposure` (which
credential stores exist and what to rotate - paths and yes/no, never values).
`ai setup` and `ai key <provider>` now prompt for the key instead of taking it
as an argument, because an argument lands in your shell history.

Every turn, tool call and result is appended to `agent\<timestamp>.jsonl` in
the state directory; reports go to `reports\`. Providers: `anthropic`,
`openai`, `gemini`, `openrouter`, `groq`, `deepseek`, `ollama`, `custom`. The
full walk-through, with the tool list and example prompts, is in
[`docs/GUIDE.md`](docs/GUIDE.md) and on the site.

## From other AI agents: `mcp`

You may already have an agent you trust - Claude Code, Cursor, Codex, Windsurf.
`polinrider-hunter mcp` starts an MCP (Model Context Protocol) server over
stdio, so that agent gets the hunter's scanners, audits and repairs as tools
and you never hand this tool an API key of any kind. The server opens no port
and talks only to the host that started it.

Tools: `scan`, `clean`, `hunt`, `repos_audit`, `repos_repair`, `repos_history`,
`processes`, `persistence`, `quarantine_list`, `status`, `access_check`.

Three properties worth knowing before you let an agent loose with it:

- **Destructive tools default to a dry run.** `clean`, `hunt` and
  `repos_repair` - and the `kill` / `remove` options of `processes` and
  `persistence` - plan on the first call and write nothing; only a second call
  with `confirm: true` performs it. The host agent has to show you the plan in
  between - the protocol leaves it no other way to get the work done.
- **`repos_audit` and `repos_repair` take local paths or repository URLs.** A
  URL is audited through a bare clone in a temporary directory: nothing is
  checked out, no payload lands on disk.
- **The output names whom to ask.** Every infected branch comes back with
  whether the current user can push to it (`can_write`), the repository owner
  and who pushed the infected commits, so a user without write access knows
  exactly whom to contact.

Registering it (the binary must be on the agent's `PATH`; open a new terminal
after installing):

```sh
# Claude Code - this project (writes .mcp.json; the repo ships one) or every project
claude mcp add --transport stdio --scope project polinrider-hunter -- polinrider-hunter mcp
claude mcp add --transport stdio --scope user    polinrider-hunter -- polinrider-hunter mcp

# OpenAI Codex CLI
codex mcp add polinrider-hunter -- polinrider-hunter mcp
```

```json
// Claude Code .mcp.json  ·  Cursor .cursor/mcp.json or ~/.cursor/mcp.json
{
  "mcpServers": {
    "polinrider-hunter": { "type": "stdio", "command": "polinrider-hunter", "args": ["mcp"] }
  }
}
```

```toml
# Codex ~/.codex/config.toml
[mcp_servers.polinrider-hunter]
command = "polinrider-hunter"
args = ["mcp"]
```

```json
// Windsurf ~/.codeium/windsurf/mcp_config.json  (Windows: %USERPROFILE%\.codeium\windsurf\mcp_config.json)
{
  "mcpServers": {
    "polinrider-hunter": { "command": "polinrider-hunter", "args": ["mcp"] }
  }
}
```

If the host cannot find the bare command, use the full path the installer
uses: Windows `C:\Users\<you>\AppData\Local\Programs\polinrider-hunter\polinrider-hunter.exe`
(doubled backslashes inside JSON), Unix `~/.local/bin/polinrider-hunter` with
`~` spelled out - not every host expands it.

Then ask the agent in plain words. For *"please remove any malware from my
remote repos, check incoming changes and check my pc, make sure all are
clean"* a well-behaved agent will: `hunt` (dry run) and `repos_audit` each
repository → show you the infected branches, including remote commits you have
not pulled → `hunt` with `confirm: true` to clean the machine first →
`repos_repair` dry run per repository → ask → `repos_repair` with
`confirm: true` → `repos_audit` again → list the branches it could not push to,
with owner and who pushed → remind you to rotate credentials and install the
guard. That is the workflow written into [`AGENTS.md`](AGENTS.md).

**Without MCP.** [`SKILL.md`](SKILL.md) is the same playbook in the Agent
Skills format (YAML `name`/`description` frontmatter, then instructions). Copy
it to `.claude/skills/polinrider-hunter/SKILL.md` (this project) or
`~/.claude/skills/polinrider-hunter/SKILL.md` (every project) and Claude Code
runs the CLI itself when the conversation turns to malware or poisoned
branches.

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
cargo test                 # unit tests + tests/end_to_end.rs + tests/campaigns.rs + tests/agent.rs
```

<!-- TEST-COUNT: 213 at 1.3.0 (151 unit, 62 integration) - keep docs/index.html in step -->
The suite is 213 tests at 1.3.0. `tests/agent.rs` drives the agent with a
scripted model: it proves `repos_repair` plans dry by default and pushes only
with approval, that `credential_exposure` reports paths and never values, and
that the command classifier and secret-path checks hold.

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
