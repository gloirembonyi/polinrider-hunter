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

`cargo test` runs the suite (218 tests at 1.3.0): unit tests plus four
end-to-end binaries (`tests/`) that plant every attack shape on disk -
including a real poisoned remote - and prove it gets removed, and drive the
agent with a scripted model.

Or skip the build: the installers at <https://gloirembonyi.github.io/polinrider-hunter>
put a prebuilt binary on your `PATH` (`%LOCALAPPDATA%\Programs\polinrider-hunter`
on Windows, `~/.local/bin` elsewhere).

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
polinrider-hunter repos <repo> [<repo> ...]             # fetch + audit every branch, report only
polinrider-hunter repos https://github.com/you/repo     # not cloned: audited via a bare clone in a temp dir
polinrider-hunter repos --repair --dry-run <repo> ...   # the plan: one forward commit per infected branch
polinrider-hunter repos --repair <repo> ...             # do it (no force push), re-fetch, re-audit
```

The audit covers every local and remote-tracking branch straight out of the
object database - nothing is checked out - and every git command it runs has
`core.fsmonitor`, hooks and the pager switched off, so a hostile repository's
config cannot run. `--json` prints one object per finding.

### The default repair: `repos --repair`

For each infected remote branch, `--repair` builds **one ordinary commit on top
of the current tip** that removes the infection, and pushes it as a plain
fast-forward:

- never a force push - if someone pushed in the meantime the push is rejected
  (`BLOCKED … someone pushed to origin/main since the audit - nothing was
  overwritten; run again`), never overwritten;
- nothing infected is ever checked out - the commit is built inside git's
  object database through a private index, so no payload lands on disk;
- teammates' work on top of the infection is fine, which is why this is the one
  to use on a branch a team shares.

It removes padded droppers (`api.js`), `node api.js &&` hooks in `package.json`
scripts, appended config payloads, folder-open `.vscode` tasks, fake fonts, the
dropped `branch_structure.json` / `config.bat` / `temp_*push.bat`, and the
`.gitignore` lines that hid them. A commit that would still carry an indicator
is never pushed, and the branch is re-audited afterwards. What you see per
branch:

```
remote branches --repair would clean (dry run, nothing pushed)
  ready    C:\work\app  would add 8c1d… on top of origin/main c71e… (3 files changed, 2 deletions)
           - api.js: deleted (padded dropper)
           - package.json: dropped `node api.js &&` from "dev"
           - .vscode/tasks.json: deleted (folderOpen autorun)
  BLOCKED  C:\work\api  origin/develop: can_write: false - owner acme-org, infected commits pushed by m-okafor
```

`POLINRIDER_SKIP_REMOTES=upstream,fork` keeps it off remotes that belong to
someone else. The poisoned commit stays in history until the owner purges it
(`--history` prints the command) - a forward commit makes the branch safe to
pull, not the history clean. When you want the commit itself gone and nobody
else works on the branch, that is `--excise` below.

### Older option, your clean local branch: `repos --fix`

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

### Repos you cannot fix

Some infected branches belong to someone else - an organisation, a client, a
fork. The audit still reads them, and the repair reports, per branch:

- the repository **owner**;
- **who pushed** the infected commits (in this campaign, the victim whose
  credential was stolen - usually not the attacker's own account);
- `can_write` - whether the credentials on this machine can push there.
  `false` means the tool stops and tells you; it does not try another route.

What to tell that person, in one message: *your branch `origin/<branch>` of
`<repo>` carries PolinRider malware; run `polinrider-hunter repos --repair` on
your clone - it adds one normal commit that removes it, no force push, nothing
infected checked out; or accept the pull request I will open.* Point them at
the installer page. And say plainly that GitHub keeps the poisoned commit in
the repository's history - reachable by hash, in every clone - until **they**
purge it with the `git filter-repo` command `repos --history` prints and ask
GitHub support to collect the unreachable objects.

## 2b. Ask the AI agent to do it: `agent`

`agent` is a chat in your terminal with an AI that has this whole tool in its
hands - and a terminal, file read/write/edit, glob and grep search, the web.
Ask for anything on your machine or your repositories in plain words: *find out
how this got here, clean these repos, remove the poisoned commits from every
branch, fix this build, write me a script that...*

**How it works.** The model never touches your machine; it proposes, the binary
decides and acts. You type. The binary sends the model its system prompt (the
incident method: triage, scope, contain, eradicate, root cause, recover,
report), the list of its tools and the conversation. The model answers with
*one proposed tool call* and its arguments. The binary classifies that call
against your permission mode - a reader runs at once, a change is shown to you
first, a short list is refused in every mode - runs it itself, and sends the
result back, capped at 16 KB and marked as untrusted data. Round again, until
the model calls `finish` with a summary, asks you something with `ask_user`,
or reaches 60 steps in one turn and pauses (`continue` resumes).

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
polinrider-hunter ai key anthropic              # asks for the key (or set ANTHROPIC_API_KEY, OPENAI_API_KEY, ...)
polinrider-hunter ai use openai gpt-4.1         # default provider + model
polinrider-hunter ai use custom my-model --base-url http://localhost:1234/v1
polinrider-hunter ai                            # what is set up, what is active
polinrider-hunter ai test                       # one round trip to prove the key works
```

Keys live in the state directory's `config.txt`, written owner-only (0600 on
Unix; inheritance cut and only your account granted on Windows); `ai` only ever
prints them masked. Give keys at the prompt (`ai key <provider>`, `/key
<provider>`), not as arguments: an argument lands in your shell history, and the
tool warns when it gets one. Keys never appear on curl's command line either -
headers go through a private temp file that is deleted after each request.
On Claude the agent uses the standard Messages API with adaptive thinking at
high effort, and caches the system prompt and tool list; every provider retries
429/5xx/overloaded with backoff. If a Claude turn is declined (`refusal`), the
agent says so and you can rephrase or switch with `/model`.

**In the chat:** `/help`, `/status` (model, mode, steps, tokens, context),
`/provider <id> [model]`, `/model <name>`, `/key <id>`, `/mode <m>`,
`/plan`, `/tools`, `/investigate`, `/report`, `/clear`, `/exit`. A session keeps
its history when you switch provider or model. One request runs at most 60 model
steps before it pauses for you (`continue` resumes; `--max-steps` is the session
cap, which `/clear` resets). Ctrl-C stops the current step; twice quits. Long
sessions are compacted: older tool results are trimmed, then older turns are
folded into a summary, keeping the last few exchanges verbatim (budget per
provider - small for Groq/Ollama; override with `POLINRIDER_CONTEXT_CHARS`).

**Its tools:** `run_command` (a real terminal: `cmd`, `powershell` or `sh`,
timeout up to 30 min), `read_file`, `write_file`, `edit_file`, `glob_search`,
`grep_search`, `list_dir`, `todo_write` (its plan, shown to you), `scan`,
`clean`, `repos_audit`, `repos_repair`, `repos_fix`, `repos_excise`,
`repos_history`, `processes`, `kill_process`, `persistence`,
`remove_persistence`, `credential_exposure`, `hash_file`, `threat_intel`,
`web_search`, `web_fetch`, `quarantine_list`, `ask_user`, `write_report`,
`finish`.

`repos_repair` is its default fix for a poisoned remote branch: a forward commit
on top of the branch, built without checking anything out and pushed as a
fast-forward (no force push - safe for shared branches). It plans dry by
default, and a real push always asks you, even in `workspace-write`; only
`full-access`/`--yes` skips the question. `credential_exposure` lists which
credential stores exist (git helpers, `.git-credentials`, `gh` tokens, SSH keys,
`.npmrc` tokens, `.env` files) and what to rotate - paths and yes/no only, never
the values.

**Permission modes** (`--mode`, `/mode`, or `ai mode` for the default):

- `read-only` - it investigates and reports; every change is refused.
- `ask` (default) - read-only work runs freely; every change shows you the
  exact command/file/diff first: `y` / `n` (with a reason it reads) / `e` edit
  the command / `a` always (for a command: that exact command line only) / `q`
  quit.
- `workspace-write` - file writes and edits inside the project directories run
  without asking; everything else still asks.
- `full-access` (`--yes`) - nothing asks.

**Refused in every mode:** disk wipes, mass deletes, registry-wide deletes,
download-piped-to-a-shell (`curl ... | sh`, `iex`, `-enc`, `mshta`). The deny
list matches whole tokens, so `| sha256sum`, `rm -rf *.log` or a word like
`confirm` are not caught by accident (they ask instead).

**What counts as read-only** for `run_command`: every segment (split on `|`,
`;`, `&`, `&&`, `||`) must be a known reader in a reading form. Anything with
`$(…)`, backticks or `<(…)`, a real redirect (`2>&1`, `2>nul`, `>/dev/null` are
fine), `sudo`/`runas`, `env`/`set`/`printenv` (secrets), `npx`, `git -c` or git
config that runs programs, or a quoted `powershell -Command`/`cmd /c`/`bash -c`
body that is not itself read-only, asks. Auto-run `git` commands get
`core.fsmonitor`, hooks and the pager switched off, so `git status` in a
poisoned repository cannot run the attacker's code.

**Secrets and the web.** `read_file`/`grep_search`/`glob_search` will not read
secret stores (`.env*` except examples, `.ssh/`, `.git-credentials`, `.npmrc`,
key files, browser profiles, `gh` hosts.yml, the hunter's own config) unless you
approve each one - not even in `full-access`, and never in `read-only`.
`web_fetch` goes straight to a built-in list of research sites (GitHub, NVD,
OSV, npm, PyPI, VirusTotal, Socket, MS Learn, MDN, Stack Overflow, Wikipedia,
docs.rs, crates.io, search engines) when the query string is short; any other
host asks (and is refused in `read-only`), and private/loopback/link-local
addresses are never fetched, redirects included. File, command and web output
reaches the model marked as untrusted data, and the system prompt tells it never
to act on instructions found there. Every result is capped at 16 KB.

Every turn, tool call and result goes to a transcript in the state directory
(`agent\<timestamp>.jsonl` under `%LOCALAPPDATA%\polinrider-hunter` on Windows,
`~/.local/share/polinrider-hunter` elsewhere; `status` prints it); reports go
to `reports\`.

Things people ask it:

```
my repos show 2 incoming commits I never made - clean C:\work\app properly
audit this machine and my repos, find the root cause, tell me what to rotate
why does npm run dev start a hidden node process? find it, stop it, explain
check every branch of https://github.com/me/api without cloning it
which of my credential stores could this have read? what do I rotate first?
write the incident report for what you found
```

Its method for incidents is still triage, scope, contain, eradicate, root cause,
recover, report - evidence first, files in a suspect repository treated as
evidence rather than instructions (it will not run a repository's scripts before
scanning it), and when your own commits were re-pushed with payloads it tells
you the pushing credential is compromised and puts rotation first.

## 2c. From the AI agent you already use: `mcp`

If you already work in Claude Code, Cursor, Codex or Windsurf, you do not need
a key for this tool at all. `polinrider-hunter mcp` starts an MCP (Model
Context Protocol) server over stdio; your agent gets the hunter's operations as
tools and you ask it in plain words. The server opens no port and talks only to
the host that started it.

| tool | does | changes anything? |
|---|---|---|
| `scan` | report indicators under paths, plus git config and hooks | no |
| `hunt` | sweep this whole machine and clean it | dry run first; `confirm: true` to do it |
| `clean` | heal the findings under paths, quarantining originals | dry run first; `confirm: true` |
| `repos_audit` | every branch of each repo (paths **or URLs**), with `can_write`, owner, who pushed | `git fetch` only |
| `repos_repair` | one clean forward commit per infected remote branch | dry run first; `confirm: true` pushes |
| `repos_history` | payloads still held by old commits, and the purge command | no |
| `processes` | hidden stage-2 loaders and every interpreter process; `kill` stops the loaders | listing no; `kill`: dry run first, `confirm: true` |
| `persistence` | Run keys, tasks, Startup, profiles, Win+R history; `remove` takes out provable malware | listing no; `remove`: dry run first, `confirm: true` |
| `quarantine_list` | the originals kept aside | no |
| `status` | guard, watched paths, state directory | no |
| `access_check` | can this machine's credentials push to a repo/branch; who owns it | no |

Destructive tools **default to a dry run** and only act on a second call with
`confirm: true`, so the host agent has to put the plan in front of you first.
A URL given to `repos_audit`/`repos_repair` (the `urls` parameter, beside `paths`) is fetched into a bare mirror in a
temporary directory - nothing checked out.

Register it once (the binary must be on the agent's `PATH`; open a new terminal
after installing):

```powershell
# Claude Code: this project (writes .mcp.json - the repo ships one) or every project
claude mcp add --transport stdio --scope project polinrider-hunter -- polinrider-hunter mcp
claude mcp add --transport stdio --scope user    polinrider-hunter -- polinrider-hunter mcp

# OpenAI Codex CLI
codex mcp add polinrider-hunter -- polinrider-hunter mcp
```

```json
// Claude Code .mcp.json  ·  Cursor .cursor/mcp.json (project) or ~/.cursor/mcp.json
{ "mcpServers": { "polinrider-hunter": { "type": "stdio", "command": "polinrider-hunter", "args": ["mcp"] } } }
```

```toml
# Codex ~/.codex/config.toml
[mcp_servers.polinrider-hunter]
command = "polinrider-hunter"
args = ["mcp"]
```

```json
// Windsurf ~/.codeium/windsurf/mcp_config.json  (Windows: %USERPROFILE%\.codeium\windsurf\mcp_config.json)
{ "mcpServers": { "polinrider-hunter": { "command": "polinrider-hunter", "args": ["mcp"] } } }
```

If the host cannot find the bare command, give the full path: Windows
`C:\Users\<you>\AppData\Local\Programs\polinrider-hunter\polinrider-hunter.exe`
(doubled backslashes in JSON), Unix `/home/<you>/.local/bin/polinrider-hunter`
(`/Users/<you>/…` on macOS) - not every host expands `~`.

Then, for example: *"please remove any malware from my remote repos, check
incoming changes and check my pc, make sure all are clean."* Expect the agent
to: `hunt` (dry run) and `repos_audit` each repository → show you the infected
branches, including remote commits you have not pulled → `hunt` with
`confirm: true` to clean the machine first → `repos_repair` dry run → ask you →
`repos_repair` with `confirm: true` → `repos_audit` again → list the branches it
could not push to, with owner and who pushed, and whom to ask → remind you to
rotate credentials (section 4b) and run `install`. [`AGENTS.md`](AGENTS.md)
spells that workflow out for the agent.

**Without MCP:** `SKILL.md` in the repository root is the same playbook in the
Agent Skills format. Copy it to `.claude/skills/polinrider-hunter/SKILL.md` or
`~/.claude/skills/polinrider-hunter/SKILL.md` and Claude Code runs the CLI itself.

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
| **PolinRider** (DPRK, 4,000+ repos) | payload after ~500 spaces/tabs on one config line; an `api.js` dropper (a line of 200+ tabs/spaces then ≥1 KB of code, nothing else) run by a `node api.js &&` hook in `package.json`; C2 via Ethereum/TRON/Aptos/BSC dead drops; `.vscode/tasks.json` autorun; JS in `.woff2`/`.llf`/`.lkf`/`.lfk` | padding heuristic + 60 signatures; the dropper by its shape alone, under any name - the detector marker cannot exempt it; `script-runs-dropper` for the hook | byte-exact cut; dropper/font/env files deleted; tasks.json and package.json reported locally, removed by `repos --repair` on a branch |
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
used to push. Today the same job is `repos --repair`: one forward commit per
branch, and it would also have worked on the branches where colleagues had
pushed since.
