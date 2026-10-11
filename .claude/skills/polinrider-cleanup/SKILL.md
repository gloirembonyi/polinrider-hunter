---
name: polinrider-cleanup
description: Find and remove PolinRider-style supply-chain malware from a developer machine, its local repositories and every branch of every GitHub repository the account owns - including poisoned "twin" commits hidden under cleanup commits. Use when the user reports malware, "incoming changes" they did not make, commits re-pushed with the same message, a postcss/eslint/babel/jest/tailwind config with a huge whitespace run, config.bat / branch_structure.json, or asks to clean their repos.
---

<!-- POLINRIDER-HUNTER-DETECTOR: this file documents malware handling. Not malware. -->

# PolinRider cleanup playbook

Tool: `polinrider-hunter` (this repository; `cargo build --release` -> `target/release/polinrider-hunter`).
Read-only first, every time. Never `git pull`, `npm install`, build, or open in an editor a repository
you have not scanned - two of the payload shapes run on open or on build.

## 0. Recognise the campaign

- **Poisoned twin:** the remote carries a copy of the victim's latest commit - same subject, same author
  date, different hash - with the payload added. The editor shows "1 outgoing, 1-2 incoming" on every repo.
  A later "security: remove ... malware" commit on top makes the tip clean but leaves the twin in history.
- **Payload shapes:** code appended after 200+ spaces/tabs to `postcss|eslint|babel|jest|tailwind|next`
  config files; an obfuscated `api.js` dropper plus a `package.json` script that runs it; `config.bat`,
  `branch_structure.json`, `temp_*_push.bat`; `.gitignore` entries that hide those files; an armed
  `.vscode/settings.json` or `tasks.json` (`runOn: folderOpen` with `task.allowAutomaticTasks` on, or a
  task running `node ./public/fonts/*.llf|*.woff2`); JavaScript saved as a font.
- **Meaning:** the pushes were made with the victim's GitHub credential. Rotation comes first in the report.

## 1. The machine

```
polinrider-hunter hunt            # sweep + clean (quarantines originals), persistence, processes
polinrider-hunter persistence     # Run keys, tasks, Startup, profiles, ClickFix history
polinrider-hunter procs           # hidden stage-2 loaders
```
Then: Cursor/VS Code `task.allowAutomaticTasks: off` and Workspace Trust on.

## 2. Local repositories (every branch, nothing checked out)

```
git -C <repo> fetch --all --prune          # fetch only
polinrider-hunter repos <repo>...          # audits every local + remote-tracking ref
```
Compare the twin with the local commit before pushing anything:
```
twin=$(git rev-list --reverse <branch>..@{u} | head -1)
git diff --stat --ignore-cr-at-eol <branch> $twin   # must list ONLY payload files
```
Repair, preferring the exact original:
```
polinrider-hunter repos --fix --dry-run <repo>     # local branch clean -> push it over the remote
polinrider-hunter repos --excise --dry-run <repo>  # no clean local branch, or twin under a cleanup
```
`--excise` rebuilds the original commit (twin's tree, infected files restored from its parent, same
message/author/dates), folds cleanup commits away, refuses if real work landed after the infection,
and pushes with `--force-with-lease`. Drop `--dry-run` once the plan is right.

## 3. Every repository on the account (not cloned)

```
python -I tools/scan_remote.py --owner <user-or-org> > scan.txt          # every branch, blob:none clones
# local.txt: "<clone url>|<path under $HOME>" for each local clone (originals may live there)
python -I tools/excise_remote.py --owner <user> --local local.txt         # plan
python -I tools/excise_remote.py --owner <user> --local local.txt --push  # do it (gh, push rights)
python -I tools/scan_remote.py --owner <user>                             # verify: all CLEAN
python -I tools/excise_remote.py --owner <user> --local local.txt         # verify: prints nothing
```
- A 403 means the account is read-only there: list those repos for an org owner; do not route around it.
- `prod`/`production` branches: ask the user before touching them (some teams forbid it).
- A local "original" only counts if subject AND author date AND the clean tree all match.

## 4. Verify and hand over

- Re-run `repos` / `scan_remote.py`; `ahead/behind` should be `0 0` on every repo the user has open.
- Tell the user, in this order: rotate GitHub tokens/SSH keys, revoke sessions and OAuth apps, rotate
  every secret that was in a `.env` on disk; enable `polinrider-hunter install` (the guard); keep editor
  autorun off.
- Report what was removed, where, and what is still blocked (with the reason).

## Gotchas learned the hard way

- Git Bash mangles `ref:path` (`origin/main:file` -> `origin\main;file`): set `MSYS_NO_PATHCONV=1`.
- `.gitignore` entries that *name* the malware files are defensive, not infections, unless the files exist.
- A repository's own scanner (signature strings in `scan_remote.py`, `check-malware.mjs`) is not a payload.
- Never `ls-tree` with `%(objectsize)` on a blob:none clone - it fetches every blob.
- Python on Windows: `-I` ignores `PYTHONIOENCODING`; reconfigure stdout to UTF-8 in the script.
- Keep file line endings (`newline=""`); a CRLF rewrite turns a one-line fix into a whole-file diff.

## Using the AI agent instead

`polinrider-hunter agent` (after `polinrider-hunter ai setup`) has all of the above as tools
(`repos_audit`, `repos_fix`, `repos_excise`, `repos_history`, `scan`, `clean`, `persistence`, ...)
plus a terminal and file editing. Ask in plain words; it shows every change first in the default
`ask` mode.
