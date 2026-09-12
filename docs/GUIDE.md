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

## 6. This incident (September 2026), for the record

On the machine this was written on, `hunt --dry-run` + `persistence` + `repos`
found: the `MicrosoftCLROptimization.vbs` Startup shim (payload already gone,
launcher still armed); the `runtimedev-link` loader's `agent.env`,
`agent.env.bat`, `start.vbs`, `runtimedev-link.task.xml`; and **five** GitHub
repositories whose `main`/`master` had been re-pushed with PolinRider payloads
(`api/index.js` + `agent.routes.js`, `postcss.config.mjs`, `public/fonts/fa-solid-500.woff2`
+ `.vscode/tasks.json`, `frontend/vite.config.ts` + a dropped `.env`). Working
trees were clean. `hunt` removed the local files and shim; `repos --fix`
restored every remote branch from the clean local commit.
