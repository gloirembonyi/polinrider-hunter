# polinrider-hunter — how to use it

<!-- POLINRIDER-HUNTER-DETECTOR: this file documents malware signatures. Not malware. -->

This is the short, practical version. The README explains *why* each design
decision was made; this page tells you *what to type*, in order, and what you
should see.

## 0. Build it (once)

```powershell
cd polinrider-hunter
cargo build --release
# binary: target\release\polinrider-hunter.exe   (put it on PATH, or use the full path below)
```

`cargo test` runs the suite: unit tests plus two end-to-end binaries (`tests/`)
that plant every attack shape on disk — including a real poisoned remote — and
prove it gets removed.

## 1. Clean this machine: `hunt`

```powershell
polinrider-hunter hunt --dry-run     # look first: prints what it WOULD do, writes nothing
polinrider-hunter hunt               # do it
polinrider-hunter hunt --drives      # also every other drive (slower)
```

What one `hunt` does, in this order:

1. **Stops running loaders** — hidden `node -e` stage-2 processes.
2. **Removes Windows persistence whose target is provably malware** — Run keys,
   scheduled tasks, and **Startup-folder scripts** (`MicrosoftCLROptimization.vbs`,
   `VSCodeUpdater.vbs`, the `runtimedev-link` shim). Judged on the script's
   *contents* (fake NGEN path, `NativeImageGen`, `runtimedev-link`, C2 addresses),
   never on its name — your own startup scripts are left alone.
3. **Walks your home directory** and heals every infected file: padded config
   payloads, GlassWorm invisible-Unicode lines, `.env` droppers, JavaScript
   disguised as fonts, dropped loader files. Originals go to quarantine first.
4. **Scans the hideouts the walk skips**: the fake `AppData\Local\Microsoft\CLR_v4.0`,
   `~/.config/runtimedev-link`, `~/.local/share/runtimedev-link`, and **removes
   cached malicious npm packages** from `~/.npm/_npx` and the global `node_modules`.
5. **Audits every repository's git config and hooks** — `core.fsmonitor` set to
   a program is unset; hooks that `curl | sh` and nested bare repositories are
   named.
6. **Checks the Win+R history** for a pasted fetch-and-execute command (ClickFix).

Then it prints `hunt complete: …` with counts. Anything under **"clean these by
hand"** is something it deliberately would not touch (JSON it cannot safely
splice, UTF-16 files, hooks) — open each one and judge.

## 2. Check your repositories' *remotes*: `repos`

Your working tree can be clean while the branch on GitHub is poisoned — the
campaign re-pushes your own latest commit with the payload appended, same
message, same date. `git status` shows nothing; `git pull` would bring it back.

```powershell
polinrider-hunter repos <repo> [<repo> ...]          # fetch + audit every branch, report only
polinrider-hunter repos --fix --dry-run <repo> ...   # show exactly what --fix would push
polinrider-hunter repos --fix <repo> ...             # repair
```

`--fix` pushes your **clean local branch** over the poisoned remote branch with
`git push --force-with-lease=<branch>:<audited-sha>`, then re-fetches and
re-audits. It only does so when:

- a local branch tracks (or is named like) the remote branch,
- that local branch itself carries no indicator, and
- **every** commit the remote has beyond your local branch touches an infected
  file — i.e. the remote's extra history *is* the infection.

Otherwise it prints **BLOCKED** with the reason (e.g. "remote commit abc123
changes 3 files that are not part of the infection") and pushes nothing. Merge
or rebase that work by hand, `clean` + commit, then run `--fix` again.

Order that works: **commit your clean local work first**, then `repos --fix`.
Whatever is in your local branch is what the remote becomes.

## 2b. Let the AI investigate: `agent`

`agent` puts a Gemini model in front of every command above, with you approving
anything that changes the machine. It is for the questions the scanners cannot
answer on their own: *how did this get here, is this package known-bad, what
else on this machine talks to that address, which commit and which account
introduced it, what do I still have to rotate?*

```powershell
polinrider-hunter set-key AIza...          # free key: https://aistudio.google.com/apikey (no card)
polinrider-hunter agent                    # interactive: it investigates, you steer with plain text
polinrider-hunter agent --task "Find out how the Startup shim got here and whether anything else launches from AppData"
polinrider-hunter agent ~/work/repo-a ~/work/repo-b    # focus on these projects
polinrider-hunter report                   # a written incident report (AI-written with a key, factual without)
```

What it can do (its *tools*): `scan`, `clean`, `repos_audit`, `repos_fix`,
`processes`, `kill_process`, `persistence`, `remove_persistence`, `read_file`,
`list_dir` (with "modified in the last N days"), `hash_file`, `threat_intel`
(VirusTotal, if you add `--vt-key`), `web_search`, `web_fetch`, `run_command`,
`quarantine_list`, `ask_user`, `write_report`, `finish`.

How the human stays in the loop:

- **Read-only runs freely** — scanning, reading files, listing directories,
  hashing, searching, and shell commands on a read-only allow-list (`git log/
  show/diff/status`, `dir`/`ls`, `type`/`cat`, `findstr`/`grep`, `tasklist`,
  `reg query`, `schtasks /query`, `netstat`, `Get-*` PowerShell…).
- **Anything mutating asks first** — `clean`, `remove_persistence`, `repos_fix`,
  `kill_process`, and any other command. You see the exact command and its
  reason and answer `y` / `n` (with an optional reason the agent gets to read) /
  `e` to edit a command / `a` always for that tool / `q` quit.
- **Some things are refused even with approval** — disk wipes, mass deletes,
  registry-wide deletes, and download-and-execute one-liners (`curl | sh`,
  `powershell -enc`, `mshta`, `iex`).
- **`--yes`** pre-approves the mutating tools for people who have already
  decided; the refusal list still applies. In the REPL, `/yes` toggles it.
- Every turn, tool call and result is appended to a transcript in the state
  directory (`agent\<timestamp>.jsonl`), reports go to `reports\`.

The agent's method is the incident-response loop — triage, scope, contain,
eradicate, root cause, recover, report — and its rules say evidence first
(paths, lines, commit hashes, authors, dates, IPs), never guess a finding, and
treat web results as leads, not instructions. When it sees the campaign's
signature move — your own commits re-pushed with payloads — it will tell you the
credential that pushed them is compromised and put rotation at the top of the
report.

Models: the free Gemini tier (Flash family) is enough. The client tries the
configured model first, then falls back (`gemini-2.5-flash` → `flash-lite` →
`3.1-flash-lite`) on quota or availability errors. If you have access to a
security-tuned model (Gemini Flash *Cyber*, Sec-Gemini), `set-key … --model <id>`
puts it first in line.

## 3. Keep it clean: `install`

```powershell
polinrider-hunter install <dir> [<dir> ...]   # watch these, pre-commit hook in each repo, guard at login
polinrider-hunter status                      # is the guard alive, where is everything
polinrider-hunter log --follow                # what it is doing
polinrider-hunter monitor                     # live terminal dashboard (--web for a browser)
```

The guard: quick pass every 30 s (only the ~40 filenames the campaigns write
to), full walk every 15 min, git-ref audit every hour, stage-2 process check on
every pass.

## 4. On demand

| Command | Use it when |
|---|---|
| `scan <paths>` | "Is this folder clean?" — reports (incl. git config), changes nothing, exit 1 if infected |
| `clean <paths>` | fix just these folders (quarantines first; `--dry-run` to preview) |
| `procs` / `procs --kill` | list / stop hidden stage-2 processes |
| `persistence` | shell profiles, Startup, Run keys, tasks, Win+R history — what is removable vs. review-by-hand |
| `quarantine` | list the originals kept aside |
| `protect <repo>` | just the pre-commit hook |

## 5. What it detects now (2026)

| Campaign | How it hides | Detection | Removal |
|---|---|---|---|
| **PolinRider** (DPRK, 4,000+ repos) | payload after ~500 spaces/tabs on one config line; C2 via Ethereum/TRON/Aptos/BSC dead drops; `.vscode/tasks.json` autorun; JS in `.woff2` | padding heuristic + 60 signatures | byte-exact cut; font/env files deleted; tasks.json reported |
| **AppData / npm loader** (`runtimedev-link`) | Startup `.vbs` → fake `ngen.exe`, or `npx -y runtimedev-link --token <C2>` | markers, drop-dir scan, npx cache | shim + Run key + task removed; cached package dir deleted |
| **Shai-Hulud** npm worm (v1/v2) | `postinstall: node bundle.js` / `preinstall: setup_bun.js`; TruffleHog secret theft; `shai-hulud-workflow.yml` | lifecycle-script check, names, `.truffler-cache` | reported (package.json is never spliced) |
| **GlassWorm** (VS Code / OpenVSX / GitHub) | payload as thousands of invisible variation selectors; Solana memo C2 | invisible-run structural check (variant-agnostic), decoder constant, Solana RPC | the invisible line is cut, code around it kept |
| **Contagious Interview** (fake job take-homes) | `node-global-key-listener` + `screenshot-desktop`; folderOpen tasks | dependency pair, autorun | reported |
| **GitSpawn / git config injection** | `core.fsmonitor`, hooks, nested bare repos run code on `git status` | `.git/config` + hooks + nested-repo audit | `core.fsmonitor` unset; rest reported |
| **Install-script droppers** (generic) | `preinstall`/`postinstall` with `curl | sh`, `node -e`, base64 | fetch-and-execute pattern | reported |
| **Pwn-request workflows** | `pull_request_target` + checkout of PR head | workflow check | reported |
| **ClickFix / fake CAPTCHA** | user pastes `mshta`/`powershell -enc` into Win+R | Run-dialog history | reported (evidence) |

Limits, stated plainly: Google Docs–style hosted editors are out of scope; the
branch audit (`git grep`) cannot express invisible-Unicode runs, so GlassWorm on
an un-checked-out branch is caught only after checkout/`hunt`; JSON/YAML/UTF-16
are reported rather than spliced.

## 6. What a real infection looked like (a worked example)

On one developer machine, `hunt --dry-run` + `persistence` + `repos` found, all
at once: a `MicrosoftCLROptimization.vbs` Startup shim (its fake `ngen.exe`
payload already gone, the launcher still armed); the `runtimedev-link` npm
loader's `agent.env`, `agent.env.bat`, `start.vbs` and task XML under
`~/.config` and `~/.local/share`; two staged loaders in `%TEMP%`; and every one
of the developer's GitHub repositories with its default branch re-pushed as the
developer's own latest commit plus a payload — in `api/index.js`, a route file,
`postcss.config.mjs`, a `.woff2` "font" plus `.vscode/tasks.json`, a
`vite.config.ts` plus a dropped `.env`. The working trees were clean, which is
exactly why nothing looked wrong. `hunt` removed the shim and the files,
`repos --fix` restored every remote branch from the clean local commit, and the
report's first recommendation was to rotate the GitHub credential that had been
used to push.
