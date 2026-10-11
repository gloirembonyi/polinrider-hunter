# polinrider-hunter - how to use it

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
that plant every attack shape on disk - including a real poisoned remote - and
prove it gets removed.

## 1. Clean this machine: `hunt`

```powershell
polinrider-hunter hunt --dry-run     # look first: prints what it WOULD do, writes nothing
polinrider-hunter hunt               # do it
polinrider-hunter hunt --drives      # also every other drive (slower)
```

What one `hunt` does, in this order:

1. **Stops running loaders** - hidden `node -e` stage-2 processes.
2. **Removes Windows persistence whose target is provably malware** - Run keys,
   scheduled tasks, and **Startup-folder scripts** (`MicrosoftCLROptimization.vbs`,
   `VSCodeUpdater.vbs`, the `runtimedev-link` shim). Judged on the script's
   *contents* (fake NGEN path, `NativeImageGen`, `runtimedev-link`, C2 addresses),
   never on its name - your own startup scripts are left alone.
3. **Walks your home directory** and heals every infected file: padded config
   payloads, GlassWorm invisible-Unicode lines, `.env` droppers, JavaScript
   disguised as fonts, dropped loader files. Originals go to quarantine first.
4. **Scans the hideouts the walk skips**: the fake `AppData\Local\Microsoft\CLR_v4.0`,
   `~/.config/runtimedev-link`, `~/.local/share/runtimedev-link`, and **removes
   cached malicious npm packages** from `~/.npm/_npx` and the global `node_modules`.
5. **Audits every repository's git config and hooks** - `core.fsmonitor` set to
   a program is unset; hooks that `curl | sh` and nested bare repositories are
   named.
6. **Checks the Win+R history** for a pasted fetch-and-execute command (ClickFix).

Then it prints `hunt complete: …` with counts. Anything under **"clean these by
hand"** is something it deliberately would not touch (JSON it cannot safely
splice, UTF-16 files, hooks) - open each one and judge.

## 2. Check your repositories' *remotes*: `repos`

Your working tree can be clean while the branch on GitHub is poisoned - the
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
  file - i.e. the remote's extra history *is* the infection.

Otherwise it prints **BLOCKED** with the reason (e.g. "remote commit abc123
changes 3 files that are not part of the infection") and pushes nothing. Merge
or rebase that work by hand, `clean` + commit, then run `--fix` again.

Order that works: **commit your clean local work first**, then `repos --fix`.
Whatever is in your local branch is what the remote becomes.

### No clean local branch? Remove the poisoned commit itself: `repos --excise`

The campaign rewrites *every* branch of *every* repository the stolen token
reaches, and nobody has all of them checked out. It also hides well after a
first cleanup: a "remove malware" commit on top makes the tip clean, but the
poisoned commit is still the one everyone pulls (the "2 incoming" your editor
shows). `--excise` repairs both, from the remote alone:

```powershell
polinrider-hunter repos --excise --dry-run <repo>   # show the plan: which commit, which files
polinrider-hunter repos --excise <repo>             # rebuild and push
```

For each remote branch it finds the commit that brought the payload in (an
infected commit on a clean parent, within the last 15 commits) and rebuilds it:
the same tree with every infected file put back as the parent had it, under the
same message, author and dates. Cleanup commits on top are folded away. The
result is the commit you originally wrote, as if the attack never happened. It
refuses when real work landed after the infection, never pushes a commit that
still audits infected, and pushes with `--force-with-lease`.

The branch audit now also catches what content matching cannot: dropped
artefacts by name (`config.bat`, `branch_structure.json`), an **armed `.vscode`
autorun** (`runOn: folderOpen` plus `task.allowAutomaticTasks` switched on, or a
task that runs a hidden script), and JavaScript saved under a font name
(`public/fonts/fa-solid-300.llf`) that such a task runs.

### Every repository you own: `tools/scan_remote.py` + `tools/excise_remote.py`

For repositories you have not cloned (`gh` must be logged in):

```powershell
python -I tools\scan_remote.py --owner <you-or-org> > scan.txt      # every branch of every repo
python -I tools\excise_remote.py --owner <you-or-org> --local local.txt          # plan
python -I tools\excise_remote.py --owner <you-or-org> --local local.txt --push   # do it
```

`excise_remote.py` does the same rebuild over the GitHub API, and first looks
for your original commit in the local clones listed in `local.txt` (same
message, same date, identical clean tree) so those branches get your exact
original back. A 403 means your account is read-only on that repository - an
owner has to run it.

## 2b. Ask the AI agent to do it: `agent`

`agent` is a chat in your terminal with an AI that has this whole tool in its
hands - and a terminal, file read/write/edit, glob and grep search, the web.
Ask for anything on your machine or your repositories in plain words: *find out
how this got here, clean these repos, remove the poisoned commits from every
branch, fix this build, write me a script that...*

```powershell
polinrider-hunter ai setup                 # pick a provider, paste a key, it tests the connection
polinrider-hunter agent                    # chat; type what you want
polinrider-hunter ai "audit and repair every branch of C:\work\repo"    # start on a task, stay in the chat
polinrider-hunter agent --task "..."       # one job, then exit (scripts, CI)
polinrider-hunter agent --investigate      # the full malware investigation
polinrider-hunter report                   # a written incident report (read-only)
```

**Providers and keys.** One key is enough; set more and switch any time.

| provider | key from | default model |
|---|---|---|
| `anthropic` | console.anthropic.com | `claude-opus-5-5` |
| `openai` | platform.openai.com | `gpt-4.1` |
| `gemini` | aistudio.google.com/apikey (free tier) | `gemini-3.8-flash` |
| `openrouter` | openrouter.ai/keys (hundreds of models, one key) | `openrouter/auto` |
| `groq`, `deepseek` | their consoles | |
| `ollama` | local, no key | `llama3.1` |
| `custom` | any OpenAI-compatible endpoint (`--base-url`) | |

```powershell
polinrider-hunter ai key anthropic sk-ant-...   # store a key (or set ANTHROPIC_API_KEY, OPENAI_API_KEY, ...)
polinrider-hunter ai use openai gpt-4.1         # default provider + model
polinrider-hunter ai use custom my-model --base-url http://localhost:1234/v1
polinrider-hunter ai                            # what is set up, what is active
polinrider-hunter ai test                       # one round trip to prove the key works
```

Keys live in the state directory's `config.txt`; `ai` only ever prints them
masked. On Claude the agent uses adaptive thinking at high effort and turns on
the API's server-side fallback, so a turn a safety classifier declines (malware
analysis can trip one) is re-run on a suitable model instead of stopping.

**In the chat:** `/help`, `/status` (model, mode, steps, tokens),
`/provider <id> [model]`, `/model <name>`, `/key <id> <key>`, `/mode <m>`,
`/plan`, `/tools`, `/investigate`, `/report`, `/clear`, `/exit`. A session keeps
its history when you switch provider or model.

**Its tools:** `run_command` (a real terminal: `cmd`, `powershell` or `sh`,
timeout up to 30 min), `read_file`, `write_file`, `edit_file`, `glob_search`,
`grep_search`, `list_dir`, `todo_write` (its plan, shown to you), `scan`,
`clean`, `repos_audit`, `repos_fix`, `repos_excise`, `repos_history`,
`processes`, `kill_process`, `persistence`, `remove_persistence`, `hash_file`,
`threat_intel`, `web_search`, `web_fetch`, `quarantine_list`, `ask_user`,
`write_report`, `finish`.

**Permission modes** (`--mode`, `/mode`, or `ai mode` for the default):

- `read-only` - it investigates and reports; every change is refused.
- `ask` (default) - read-only work runs freely; every change shows you the
  exact command/file/diff first: `y` / `n` (with a reason it reads) / `e` edit
  the command / `a` always for that tool / `q` quit.
- `workspace-write` - file writes and edits inside the project directories run
  without asking; everything else still asks.
- `full-access` (`--yes`) - nothing asks.

**Refused in every mode:** disk wipes, mass deletes, registry-wide deletes,
download-piped-to-a-shell (`curl ... | sh`, `iex`, `-enc`, `mshta`). Every turn,
tool call and result goes to a transcript in the state directory
(`agent\<timestamp>.jsonl`); reports go to `reports\`.

Its method for incidents is still triage, scope, contain, eradicate, root cause,
recover, report - evidence first, files in a suspect repository treated as
evidence rather than instructions (it will not run a repository's scripts before
scanning it), and when your own commits were re-pushed with payloads it tells
you the pushing credential is compromised and puts rotation first.

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
| `scan <paths>` | "Is this folder clean?" - reports (incl. git config), changes nothing, exit 1 if infected |
| `clean <paths>` | fix just these folders (quarantines first; `--dry-run` to preview) |
| `procs` / `procs --kill` | list / stop hidden stage-2 processes |
| `persistence` | shell profiles, Startup, Run keys, tasks, Win+R history - what is removable vs. review-by-hand |
| `quarantine` | list the originals kept aside |
| `protect <repo>` | just the pre-commit hook |

## 4b. After a real infection: take the access back

Removing the payload does not remove what it stole. A stealer that ran as you has your git
credentials, your GitHub tokens and everything in your `.env` files, and it will simply push
again. [`AFTER_AN_INFECTION.md`](AFTER_AN_INFECTION.md) walks through it in order: clean every
machine first, then revoke OAuth/GitHub apps, tokens, SSH keys and sessions, clear the
credentials cached locally, rotate every secret the machine could read, and verify the remote.

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
developer's own latest commit plus a payload - in `api/index.js`, a route file,
`postcss.config.mjs`, a `.woff2` "font" plus `.vscode/tasks.json`, a
`vite.config.ts` plus a dropped `.env`. The working trees were clean, which is
exactly why nothing looked wrong. `hunt` removed the shim and the files,
`repos --fix` restored every remote branch from the clean local commit, and the
report's first recommendation was to rotate the GitHub credential that had been
used to push.
