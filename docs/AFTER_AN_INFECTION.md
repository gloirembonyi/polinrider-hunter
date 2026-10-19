# After an infection - lock the attacker out

`polinrider-hunter` removes the malware. It cannot remove the *access* the malware
already gave away: a stealer that ran as you for a day has your git credentials, your
tokens and whatever was in your `.env` files. Cleaning the files and stopping there is
the single most common reason an infection comes back a week later.

Work through this in order. It takes about 30 minutes.

---

## 0. Know what you are looking for

Malicious commits do not look malicious. The PolinRider family appends its payload to the
*end of a line that is already there*, behind 200–400 spaces or tabs, so every diff view
and every code review shows the file as unchanged. If you have ever thought "I don't
remember making that commit, but it looks empty", that was it.

```
polinrider-hunter hunt --dry-run      # what is infected, changes nothing
polinrider-hunter repos               # which of your repos have infected commits on the remote
```

---

## 1. Clean the machine first

Rotating credentials while a stealer is still running just hands the attacker the new
ones. Clean, *then* rotate.

```
polinrider-hunter hunt                # quarantines payloads, strips the padded lines,
                                      # removes loaders, scheduled tasks and Run keys
polinrider-hunter hunt --dry-run      # must come back clean
```

If the second run still reports something, stop and investigate it (`polinrider-hunter
agent --task "explain what is left and where it came from"`) before going on.

**Every machine that pushed to the affected repos** needs this - laptop, desktop, the CI
runner, the VM you forgot about. One dirty machine re-infects everything.

---

## 2. Take push access away

Do these in this order. Each step is on github.com → your avatar → **Settings**.

| # | Page | Do |
|---|---|---|
| 1 | **Password and authentication** | Change your password. Turn on 2FA if it is off (an authenticator app or a passkey - not SMS). Changing the password invalidates existing web sessions. |
| 2 | **Sessions** | "Sign out" every session that is not the one you are using. Look at the locations: a country you have never been in is your answer about whether this was targeted. |
| 3 | **Applications ▸ Authorized OAuth Apps** | Revoke everything you do not actively use. Anything you keep, you are trusting with your repos. |
| 4 | **Applications ▸ Authorized GitHub Apps** | Same. **"Revoke all" is safe** - nothing is deleted, the apps simply have to ask again next time you use them. Expect to re-authorize: your deploy provider (Vercel/Netlify/Railway) - *auto-deploys stop until you reconnect*, your editor (Cursor, Copilot), any CI. |
| 5 | **Developer settings ▸ Personal access tokens** | Delete **all** of them, both *Tokens (classic)* and *Fine-grained tokens*. Recreate only the ones you actually need, fine-grained, scoped to single repos, with an expiry. A classic token with `repo` scope is a skeleton key to every repository you can see. |
| 6 | **SSH and GPG keys** | Delete any key you cannot point at on one of your machines right now. Check "Last used" on each. |
| 7 | **Security log** (`github.com/settings/security-log`) | Read it. It lists every token creation, OAuth grant, SSH key added and repo access. This is where you find out what they actually did, and whether anything else was touched. |

Then, **per repository** (Settings inside the repo):

- **Deploy keys** - delete anything with write access you did not add.
- **Webhooks** - a webhook pointed at an address you do not recognise is exfiltration.
- **Collaborators and teams** - remove anyone who should not be there.
- **Secrets and variables ▸ Actions** - assume every one of these leaked; rotate them.
- **Actions ▸ General** - if "Allow all actions" is set and you did not set it, and there
  are workflow files you did not write, treat the repo as fully compromised.

Check them quickly from a terminal with the `gh` CLI:

```sh
for r in you/repo-one you/repo-two; do
  echo "== $r"
  gh api repos/$r/keys  --jq '.[] | "deploy key: \(.title) rw=\(.read_only|not)"'
  gh api repos/$r/hooks --jq '.[] | "webhook: \(.config.url)"'
  gh api repos/$r/collaborators --jq '.[].login'
  gh api repos/$r/actions/secrets --jq '"secrets: \(.total_count)"'
done
```

---

## 3. Clear the credentials cached on the machine

The attacker's copy is gone once you revoke server-side, but your own machine is still
holding the old ones, and some tools will happily keep using them.

**Windows**

```powershell
cmdkey /list | Select-String github        # see what is stored
# then: Control Panel ▸ Credential Manager ▸ Windows Credentials ▸ remove git:https://github.com
gh auth logout ; gh auth login             # fresh token for the CLI
```

**macOS** - Keychain Access, search `github.com`, delete the internet-password entries.
**Linux** - `git credential-cache exit`, and delete `~/.git-credentials` if it exists.

Everywhere: check for plaintext leftovers.

```sh
cat ~/.git-credentials 2>/dev/null        # should not exist
cat ~/.netrc 2>/dev/null                  # should not mention github
git config --global --get credential.helper
```

---

## 4. Rotate every secret the machine could read

A stealer reads `.env*` files, shell history and config directories. Anything in them is
public knowledge now. Rotate at the provider - do not just edit the file - and update
your deploy environment afterwards.

- Database connection strings
- Cloud and AI API keys (rotate the key, do not only restrict it)
- Payment provider keys (Stripe etc.) - roll the secret key, check the event log for
  anything you did not do
- Cache/queue tokens
- OAuth client secrets
- Anything in your deploy provider's environment variables

If a secret was ever committed, rotating it is the *only* fix - it is in the git history
and in every clone, forever.

---

## 5. Verify the remote is actually clean

```
polinrider-hunter repos --repair --dry-run   # the plan: one forward commit per infected branch
polinrider-hunter repos --repair             # push it (fast-forward, never forced), re-audit
polinrider-hunter repos                      # must report nothing
```

`--repair` adds one ordinary commit on top of each infected remote branch - built without
checking anything out, so no payload touches your disk - and pushes it as a fast-forward.
If the push is rejected, *something pushed after you cleaned* - re-run step 1 before
trying again. It never overwrites. (`repos --excise` removes the poisoned commit from
history instead; it is a force push, so only for branches nobody else works on.)

Then, for each repo, check the commit list on the web for authors and dates you do not
recognise, and check that your default branch is where you expect it to be.

**Branches you cannot push to.** The repair reports, per infected branch, the repository
owner, who pushed the infected commits and `can_write: false` when your account cannot
push there. Send that person one message: *run `polinrider-hunter repos --repair` on your
clone (one normal commit, no force push), or accept the pull request I will open* - and
tell them GitHub keeps the poisoned commit in history until **they** purge it
(`repos --history` prints the `git filter-repo` command). Do not try to route around a
missing permission; the tool does not either.

---

## 6. Stop it happening again

```
polinrider-hunter install     # background guard: re-scans on a schedule, blocks the known payloads
```

- Turn on 2FA everywhere, not just GitHub - npm, your cloud provider, your email.
  Email first: whoever owns your email owns every password reset.
- Prefer fine-grained tokens with an expiry over classic tokens.
- `npm ci --ignore-scripts` in CI, and think twice before installing a package that was
  published in the last 48 hours.
- Enable branch protection or a required review on your default branch if your plan
  allows it, so a stolen token cannot rewrite history unnoticed.
- Keep a second factor that is not on the infected machine (a phone, a hardware key).

---

## If you are not sure whether you are clean

```
polinrider-hunter agent --task "audit this machine and my repos, find the root cause, tell me what to rotate"
```

The agent scans, reads what it finds, runs read-only commands, and asks before anything
that changes the system. It needs a key for a provider of your choice
(`polinrider-hunter ai setup` - Gemini's free tier is enough, Ollama needs none), and it
asks for the key at a prompt rather than taking it on the command line.

Already using Claude Code, Cursor or Codex? Register `polinrider-hunter mcp` as an MCP
server (snippets in [`GUIDE.md`](GUIDE.md), section 2c) and ask *that* agent to check the
machine and the repositories - no key of ours needed. Anything destructive dry-runs first
and needs a second call with `confirm: true`, so you see the plan before it acts.
