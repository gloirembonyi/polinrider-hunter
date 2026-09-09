# site/ — the polinrider-hunter page

<!-- POLINRIDER-HUNTER-DETECTOR: this file documents malware signatures. Not malware. -->

A static page: `index.html`, `styles.css`, `app.js`. No framework, no build step,
no `node_modules`.

That is a deliberate choice rather than a shortcut. This page exists to convince
someone it is safe to pipe a script into their shell, so the whole thing should
be readable in one sitting — and a page about supply-chain malware that pulls
four hundred megabytes of transitive dependencies to render some text would be
making the wrong argument. It also loads instantly and deploys anywhere.

The design language (deep indigo gradient, glassy panels, serif display type,
the token names in `styles.css`) is taken from the `kinyarwanda-voice` project so
the two read as siblings.

---

## Deploying to Vercel

**Dashboard:** New Project → import the repository → set:

| Setting | Value |
|---|---|
| Framework Preset | **Other** |
| Root Directory | **`site`** |
| Build Command | *(leave empty)* |
| Output Directory | *(leave empty)* |

**CLI:**

```sh
npm i -g vercel
cd site
vercel --prod
```

`vercel.json` sets `cleanUrls`, a few security headers, forces the install
scripts to `text/plain` so a browser shows them instead of downloading, and
stops them being served from a stale cache.

### After the first deploy — one line to change

Vercel gives you a domain. Point the installers at it:

- `site/install.ps1` → the `$Site = '…'` line
- `site/install.sh` → the `SITE="${POLINRIDER_SITE:-…}"` line

The **page** needs no such edit: `app.js` rewrites the displayed command to
`location.origin`, so whatever domain it is served from, the command a visitor
copies is correct. Only the scripts hardcode it, because a script piped into a
shell cannot know the URL it came from.

Both also honour an override, which is handy for testing a preview deployment:

```sh
POLINRIDER_SITE=https://my-preview.vercel.app sh install.sh
```

Both scripts also take:

| | |
|---|---|
| `POLINRIDER_SITE` | where to fetch the binary from — handy for a preview deploy |
| `POLINRIDER_REPO` | `owner/repo`, to enable the release and source-build fallbacks |
| `POLINRIDER_NO_HUNT=1` | install the binary, skip the initial machine sweep |
| `POLINRIDER_NO_INSTALL=1` | install the binary, do not start the guard |

The last two make the installer usable in CI, and testable without waiting for a
full sweep.

---

## Serving the binary

`bin/polinrider-hunter-windows-x86_64.exe` (362 KB) is committed, so
`irm https://your-domain/install.ps1 | iex` works the moment the site is live —
**no GitHub repository or release is required**. The installer downloads that
file and checks it really is an executable before trusting it, because a static
host answers `200` with an HTML error page for a missing path, and piping that
into a shell would be worse than failing.

### Adding macOS and Linux binaries

Only the Windows binary is published, because only the Windows target is
installed on the machine this was built on. To add the others, build on (or
cross-compile for) each platform and drop the result in `bin/` using the names
the installer looks for:

```
bin/polinrider-hunter-darwin-x86_64
bin/polinrider-hunter-darwin-aarch64
bin/polinrider-hunter-linux-x86_64
bin/polinrider-hunter-linux-aarch64
```

```sh
# on the target platform
cargo build --release
cp target/release/polinrider-hunter site/bin/polinrider-hunter-linux-x86_64
```

Until then `install.sh` builds from source, which takes about a minute and needs
`cargo` — it says so plainly rather than failing. Set `POLINRIDER_REPO` to
`owner/repo` if you want the source-build and GitHub-release paths to work.

### Keeping the binary in step with the code

The page quotes a version and a size. After changing the Rust source:

```sh
cargo build --release
cp target/release/polinrider-hunter.exe site/bin/polinrider-hunter-windows-x86_64.exe
```

---

## Previewing locally

```sh
cd site
python -m http.server 8080
# or: npx serve .
```

Then open <http://localhost:8080>. On localhost `app.js` deliberately leaves the
illustrative domain in place, since copying `http://localhost:8080/install.ps1`
would be useless.

---

## What is on the page

Hero and install (OS-detected tabs) · what PolinRider does, in four stages · the
whitespace evasion that defeated three existing scanners · the three detection
layers · a table of every known technique and whether it is removed, deleted,
stopped or reported · how removal stays reversible and byte-exact · the guard's
cadences and measured resource use · a command reference · how it was tested ·
and an FAQ that answers "will it slow my machine down", "could it damage my
code" and "does it phone home" without hedging.
