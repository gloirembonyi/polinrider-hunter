# tools/ — the Python side

<!-- POLINRIDER-HUNTER-DETECTOR: this file names malware indicators. Not malware. -->

The Rust binary is the engine: it detects, removes, and guards, with no runtime
to install. Every protective function works without ever running anything here.

**Start with `polinrider-hunter monitor`.** The dashboard is now part of the
binary — terminal view, `--web` for a browser view on localhost, `--once`,
`--json` — so it works on any machine that ran the install command, from any
directory, with nothing cloned and no Python. That is what almost everybody
wants, and this directory is not it.

What is left here is the same dashboard in Python, for anyone who has the repo
checked out and would rather read or extend a script than a Rust module. It
must be run from this directory, which is exactly why the built-in one exists.

Standard library only. Python 3.8+. No `pip install`, on purpose: a tool about
supply-chain compromise should not ask you to trust a dependency tree in order
to look at its own logs.

---

## `monitor.py` — see what is going on

```sh
python monitor.py            # live terminal dashboard, refreshes every 3s
python monitor.py --once     # one snapshot, then exit
python monitor.py --json     # the same snapshot as JSON, for scripting
python monitor.py --web      # local dashboard at http://127.0.0.1:8787
```

It shows, in one place:

- whether the guard is alive, its pid, how long since its last heartbeat, and
  its memory and priority
- the cadences and settings actually in effect
- every watched path
- counts: cleaned, needing review, processes stopped, quarantined
- a timeline of recent detections with the indicators that fired
- the quarantine, so you can see exactly what was taken out of your files

**It is strictly read-only.** It never edits config, never heals anything, never
stops the guard. That is worth stating plainly: a monitor you are not certain is
read-only is a monitor you hesitate to run on a machine you are worried about.

The web mode binds to `127.0.0.1` and nothing else. It displays where infections
were found on your disk, which has no business being reachable from the network.

### Where it reads from

The same state directory the guard writes to, resolved identically:

| | |
|---|---|
| Windows | `%LOCALAPPDATA%\polinrider-hunter` |
| macOS / Linux | `$XDG_DATA_HOME/polinrider-hunter`, else `~/.local/share/polinrider-hunter` |

`POLINRIDER_HOME` overrides both, which is how you point the monitor at a
sandbox rather than your real state.

If nothing is installed yet it says so and exits `2`, rather than drawing an
empty dashboard that looks like everything is fine.

---

## Notifications live in the Rust side

They are not here, and that is the point: a notification is part of protection,
so it must not depend on Python being present. The guard raises one when it
cleans something, and a louder one when it finds something it will not touch
automatically.

```sh
polinrider-hunter test-notify   # check they actually reach you on this machine
```

Under the hood it is a tray balloon on Windows, `osascript` on macOS,
`notify-send` on Linux — all already present on those systems. Failure is silent
by design: on a headless box or a locked session there is nowhere to show a
notification, and a scanner that refused to run because it could not raise a
toast would be worse than one that stays quiet. The log records every detection
either way.

Turn them off with `notify = false` in `config.txt`.

---

## Removing everything

```sh
polinrider-hunter uninstall           # stop the guard, remove the hooks
polinrider-hunter uninstall --purge   # ...and the state, PATH entry and binary
```

Plain `uninstall` is reversible — it stops the guard and removes the pre-commit
hooks, and leaves the binary and your state directory alone. It prints what it
removed and what was already absent, so you are never guessing.

`--purge` additionally deletes the state directory (config, log, **and the
quarantine**), takes the install directory off your `PATH`, and removes the
binary. It warns first if the quarantine is not empty, because those are the
only copies of whatever was cut out of your files.

A running executable cannot delete itself on Windows, so a detached helper waits
for the process to exit and then removes it; elsewhere the file is simply
unlinked. On Unix the `PATH` line lives in whichever shell profile you
hand-edited, so it tells you which line to delete rather than rewriting your
`.zshrc` unasked.
