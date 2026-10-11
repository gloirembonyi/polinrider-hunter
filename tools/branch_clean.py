#!/usr/bin/env python3
# POLINRIDER-HUNTER-DETECTOR: this tool names malware signatures to find them. Not malware.
"""Clean every infected remote branch of a repository with a NORMAL push (no history rewrite).

  python tools/branch_clean.py <repo> [<repo> ...] [--push] [--remote origin] [--only main,prod]

Why this exists: `polinrider-hunter repos --fix` restores a branch by force-pushing your clean local
copy, and correctly refuses (BLOCKED) whenever the remote holds real work your local branch lacks -
which on shared/team repos is almost always. This tool instead fixes each infected branch IN PLACE:

  for every remote branch whose tip is infected (per `polinrider-hunter repos --no-fetch`):
    1. detached worktree at the remote tip (nothing in your own checkout changes)
    2. `polinrider-hunter clean` on it   -> strips appended payloads (configs, api.js, ...)
    3. removes whole-payload files       -> api.js left empty, fake fonts (public/fonts/fa-solid-*)
    4. removes the folder-open task      -> .vscode/tasks.json tasks that run node on a payload
    5. un-hooks package.json scripts      -> "node api.js && next build" -> "next build"
    6. drops .gitignore lines that hide the campaign's push scripts
    7. re-scans; only if the tree is clean: commit "security: remove injected PolinRider malware"
    8. with --push: `git push <remote> HEAD:refs/heads/<branch>` (fast-forward; never --force)

Without --push it only prepares and reports (dry run) - always run that first.
The payload stays in history (the push only fixes the tip); purge with `repos --history` +
git filter-repo once credentials are rotated, if the repo must be scrubbed completely.
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HUNTER = os.environ.get("POLINRIDER_BIN") or os.path.join(os.path.dirname(HERE), "target", "release",
                                                         "polinrider-hunter.exe" if os.name == "nt" else "polinrider-hunter")
ARTIFACTS = {"branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat", "config.bat"}
FONT_MAGIC = (b"wOF2", b"wOFF", b"OTTO", b"\x00\x01\x00\x00", b"true", b"ttcf")
COMMIT_MSG = "security: remove injected PolinRider malware\n\nRemoves payloads appended to config files, the dropper (api.js / fake font),\nthe folder-open VS Code task, package.json script hooks and .gitignore entries\nthat hid the campaign's push scripts. Rotate any secret this branch's builds could read."


def git(repo, *a, check=True, capture=True):
    r = subprocess.run(["git", "-C", repo, *a], capture_output=capture, text=True, encoding="utf8", errors="replace",
                       env={**os.environ, "MSYS_NO_PATHCONV": "1", "GIT_TERMINAL_PROMPT": "0"})
    if check and r.returncode:
        raise RuntimeError(f"git {' '.join(a)}: {r.stderr.strip()[:400]}")
    return r.stdout


def hunter(*a):
    # flags go AFTER the subcommand (the CLI rejects a leading --no-color)
    return subprocess.run([HUNTER, a[0], "--no-color", *a[1:]], capture_output=True, text=True, encoding="utf8", errors="replace").stdout


def infected_branches(repo, remote):
    out = hunter("repos", "--no-fetch", repo)
    found = {}
    for line in out.splitlines():
        m = re.match(rf"INFECTED .* remotes/{re.escape(remote)}/(\S+) :: (.+)$", line.strip())
        if m:
            found.setdefault(m.group(1), set()).add(m.group(2).strip())
    found.pop("HEAD", None)
    return found


def fix_tasks_json(path):
    """Drop tasks that silently run node on folder open; delete the file if nothing legit remains."""
    raw = open(path, encoding="utf8", errors="replace").read()
    try:
        data = json.loads(re.sub(r"[\t ]{40,}.*$", "", raw, flags=re.S))  # tolerate appended padding
    except Exception:
        return "delete"
    tasks = data.get("tasks") or []
    bad = lambda t: ("folderOpen" in json.dumps(t.get("runOptions", {}))) and re.search(r"\bnode\b", json.dumps(t))
    keep = [t for t in tasks if not bad(t)]
    if not keep and not data.get("inputs"):
        return "delete"
    data["tasks"] = keep
    data.pop("configurations", None) if not keep else None
    open(path, "w", encoding="utf8").write(json.dumps(data, indent=2) + "\n")
    return "edited"


def unhook_package_json(path, payload_files):
    s = open(path, encoding="utf8", newline="").read()
    orig = s
    for f in payload_files:
        b = re.escape(os.path.basename(f))
        p = re.escape(f)
        # "node api.js && next build" / "node ./api.js; x" / "x && node api.js"
        s = re.sub(rf'node\s+(?:\./)?(?:{p}|{b})\s*(?:&&|;)\s*', "", s)
        s = re.sub(rf'\s*(?:&&|;)\s*node\s+(?:\./)?(?:{p}|{b})(?=")', "", s)
        s = re.sub(rf'"(?:pre|post)?\w*"\s*:\s*"node\s+(?:\./)?(?:{p}|{b})"\s*,?\s*\n', "", s)
    if s != orig:
        open(path, "w", encoding="utf8", newline="").write(s)
        return True
    return False


def clean_tree(wt, flagged):
    """Apply every fix to a checked-out tree. Returns a list of human-readable actions."""
    acts = []
    hunter("clean", wt)  # heals appended payloads in place (originals go to the hunter's quarantine)
    payload_files = set()
    for rel in sorted(flagged):
        p = os.path.join(wt, rel)
        if not os.path.exists(p):
            continue
        name = os.path.basename(rel)
        try:
            head = open(p, "rb").read(8)
            size = os.path.getsize(p)
        except OSError:  # file locked/odd after the hunter's own clean - treat as whole-payload
            head, size = b"", 0
        if rel.startswith("public/fonts/") and not head.startswith(FONT_MAGIC):
            git(wt, "rm", "-q", "-f", "--", rel); payload_files.add(rel); acts.append(f"deleted fake font {rel}")
        elif name in ("api.js",) and size < 64:
            git(wt, "rm", "-q", "-f", "--", rel); payload_files.add(rel); acts.append(f"deleted dropper {rel}")
        elif rel.endswith(".vscode/tasks.json"):
            how = fix_tasks_json(p)
            if how == "delete":
                git(wt, "rm", "-q", "-f", "--", rel)
            acts.append(f"{how} folder-open task {rel}")
        else:
            acts.append(f"healed {rel}")
    # committed campaign artefacts (push scripts / branch map) - whole files, anywhere in the tree
    for root, dirs, files in os.walk(wt):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for f in files:
            if f in ARTIFACTS:
                rel = os.path.relpath(os.path.join(root, f), wt).replace(os.sep, "/")
                git(wt, "rm", "-q", "-f", "--", rel); acts.append(f"deleted committed artefact {rel}")
    # package.json files anywhere that call a removed payload
    for root, dirs, files in os.walk(wt):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        if "package.json" in files:
            pj = os.path.join(root, "package.json")
            if unhook_package_json(pj, payload_files or {"api.js"}):
                acts.append(f"unhooked scripts in {os.path.relpath(pj, wt)}")
        if ".gitignore" in files:
            gi = os.path.join(root, ".gitignore")
            lines = open(gi, encoding="utf8", errors="replace").read().splitlines(True)
            kept = [l for l in lines if l.strip() not in ARTIFACTS]
            if len(kept) != len(lines):
                open(gi, "w", encoding="utf8").writelines(kept); acts.append(f"removed artefact lines from {os.path.relpath(gi, wt)}")
    return acts


def verify(wt):
    out = hunter("scan", wt)
    bad = [l for l in out.splitlines() if l.startswith("INFECTED")]
    for root, dirs, files in os.walk(wt):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        if "package.json" in files:
            s = open(os.path.join(root, "package.json"), encoding="utf8", errors="replace").read()
            if re.search(r"node\s+(?:\./)?(api\.js|public/fonts/)", s):
                bad.append(f"package.json still calls a payload in {root}")
    return bad


# long padding run AFTER code on the same line, hiding >=200 chars of appended code off-screen.
# (?<=\S) matters: a bare deeply-indented line is legitimate code, not a payload (dnsconfig.js false hit)
PAD_TAIL = re.compile(r"(?<=\S)[ \t]{20,}\S.{199,}$")


INJECTED_HEADER = re.compile(r"\Aimport \{ createRequire \} from 'module';\r?\n(?:\r?\n)?const require = createRequire\(import\.meta\.url\);\r?\n(?:\r?\n)?")


def heal_text(text):
    """Strip appended payloads: everything after a long space/tab run on a line (the campaign's hiding trick).
    When a payload was found, also drop the createRequire header it injects at the top of ESM configs."""
    healed = "\n".join(PAD_TAIL.sub("", l) for l in text.split("\n"))
    return INJECTED_HEADER.sub("", healed) if healed != text else healed


def index_clean(repo, remote, br, flagged, push, tip_ref=None):
    """Clean a branch WITHOUT writing the payload to disk (antivirus blocks/quarantines it there).
    Works on a private index: read-tree -> rewrite blobs in memory -> write-tree -> commit-tree -> push."""
    env = {**os.environ, "GIT_INDEX_FILE": os.path.join(tempfile.mkdtemp(prefix="pr-idx-"), "index"),
           "MSYS_NO_PATHCONV": "1", "GIT_TERMINAL_PROMPT": "0"}
    run = lambda *a, inp=None: subprocess.run(["git", "-C", repo, *a], input=inp, capture_output=True, env=env, check=True).stdout
    tip = run("rev-parse", tip_ref or f"{remote}/{br}").decode().strip()
    run("read-tree", tip)
    files = [f for f in run("ls-files", "-z").decode("utf8", "replace").split(chr(0)) if f]
    acts, payload_files = [], set()
    def put(path, data: bytes):
        sha = run("hash-object", "-w", "--stdin", inp=data).decode().strip()
        mode = "100644"
        run("update-index", "--cacheinfo", f"{mode},{sha},{path}")
    for rel in sorted(flagged):
        if rel not in files:
            continue
        blob = run("cat-file", "blob", f"{tip}:{rel}")
        name = os.path.basename(rel)
        is_font = rel.startswith("public/fonts/") or re.search(r"\.(woff2?|ttf|otf|eot|lkf|llf)$", rel, re.I)
        if is_font and not blob[:4].startswith(FONT_MAGIC):
            run("rm", "--cached", "-q", "--", rel); payload_files.add(rel); acts.append(f"deleted fake font {rel}")
        # the dropper is usually ONE line: padding from column 0 then the payload - nothing real before it
        elif name == "api.js" and len(re.sub(r"(?m)[ \t]{20,}\S.*$", "", blob.decode("utf8", "replace")).strip()) < 64:
            run("rm", "--cached", "-q", "--", rel); payload_files.add(rel); acts.append(f"deleted dropper {rel}")
        elif rel.endswith(".vscode/tasks.json"):
            run("rm", "--cached", "-q", "--", rel); acts.append(f"deleted folder-open task {rel}")
        else:
            put(rel, heal_text(blob.decode("utf8", "replace")).encode("utf8")); acts.append(f"healed {rel}")
    for rel in files:
        base = os.path.basename(rel)
        if base in ARTIFACTS:
            run("rm", "--cached", "-q", "--", rel); acts.append(f"deleted committed artefact {rel}")
        elif base == "package.json" and "node_modules/" not in rel:
            t = run("cat-file", "blob", f"{tip}:{rel}").decode("utf8", "replace")
            tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf8", newline=""); tmp.write(t); tmp.close()
            if unhook_package_json(tmp.name, payload_files or {"api.js"}):
                put(rel, open(tmp.name, encoding="utf8", newline="").read().encode("utf8")); acts.append(f"unhooked scripts in {rel}")
            os.unlink(tmp.name)
        elif base == ".gitignore":
            t = run("cat-file", "blob", f"{tip}:{rel}").decode("utf8", "replace")
            kept = [l for l in t.splitlines(True) if l.strip() not in ARTIFACTS]
            if "".join(kept) != t:
                put(rel, "".join(kept).encode("utf8")); acts.append(f"removed artefact lines from {rel}")
    tree = run("write-tree").decode().strip()
    if tree == run("rev-parse", f"{tip}^{{tree}}").decode().strip():
        return "nothing to change", acts
    # verify the cleaned files (now payload-free, so safe to write) with the real matcher
    chk = tempfile.mkdtemp(prefix="pr-chk-")
    for rel in flagged | {f for f in files if os.path.basename(f) in ("package.json", ".gitignore")}:
        r = subprocess.run(["git", "-C", repo, "cat-file", "blob", f"{tree}:{rel}"], capture_output=True, env=env)
        if r.returncode == 0:
            dst = os.path.join(chk, rel); os.makedirs(os.path.dirname(dst), exist_ok=True); open(dst, "wb").write(r.stdout)
    left = verify(chk); shutil.rmtree(chk, ignore_errors=True)
    if left:
        return "STILL-INFECTED (not committed): " + "; ".join(left[:3]), acts
    commit = run("commit-tree", tree, "-p", tip, "-m", COMMIT_MSG).decode().strip()
    stat = run("diff", "--shortstat", tip, commit).decode().strip()
    if not push:
        return "READY (dry run, index mode) " + stat, acts
    r = subprocess.run(["git", "-C", repo, "push", remote, f"{commit}:refs/heads/{br}"], capture_output=True, text=True, env=env)
    return ("PUSHED " if r.returncode == 0 else "PUSH-FAILED ") + stat + ("" if r.returncode == 0 else " :: " + r.stderr.strip().splitlines()[-1][:200]), acts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repos", nargs="+")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--remote", default="origin")
    ap.add_argument("--only", help="comma-separated branch names")
    ap.add_argument("--fetch", action="store_true", help="git fetch --prune first")
    ap.add_argument("--index", action="store_true", help="always use index mode (never write payloads to disk)")
    a = ap.parse_args()
    if not os.path.exists(HUNTER):
        sys.exit(f"hunter binary not found: {HUNTER} (cargo build --release, or set POLINRIDER_BIN)")
    summary = []
    for repo in a.repos:
        repo = os.path.abspath(repo)
        if a.fetch:
            git(repo, "fetch", "--prune", a.remote, check=False)
        branches = infected_branches(repo, a.remote)
        if a.only:
            branches = {b: f for b, f in branches.items() if b in a.only.split(",")}
        if not branches:
            print(f"[clean] {repo}: no infected {a.remote}/* branch tips"); continue
        for br, flagged in sorted(branches.items()):
            wt = tempfile.mkdtemp(prefix="pr-clean-")
            shutil.rmtree(wt)
            status = "?"
            try:
                if a.index:
                    raise OSError("index mode requested")
                git(repo, "worktree", "add", "--detach", "-q", wt, f"{a.remote}/{br}")
                acts = clean_tree(wt, flagged)
                left = verify(wt)
                git(wt, "add", "-A")
                if left:
                    status = "STILL-INFECTED (not committed): " + "; ".join(left[:3])
                elif not git(wt, "status", "--porcelain").strip():
                    status = "nothing to change"
                else:
                    git(wt, "commit", "-q", "-m", COMMIT_MSG)
                    stat = git(wt, "diff", "--shortstat", "HEAD~1", "HEAD").strip()
                    if a.push:
                        r = subprocess.run(["git", "-C", wt, "push", a.remote, f"HEAD:refs/heads/{br}"], capture_output=True, text=True,
                                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
                        status = ("PUSHED " if r.returncode == 0 else "PUSH-FAILED ") + stat + ("" if r.returncode == 0 else " :: " + r.stderr.strip().splitlines()[-1][:200])
                    else:
                        status = "READY (dry run) " + stat
                print(f"[clean] {os.path.basename(repo)} {a.remote}/{br}: {status}")
                for x in acts:
                    print(f"           - {x}")
            except Exception as e:
                # Antivirus blocking the checked-out payload ("Function not implemented"/access denied) or
                # --index: redo this branch entirely in git's object database, nothing written to disk.
                git(repo, "worktree", "remove", "--force", wt, check=False)
                try:
                    status, acts = index_clean(repo, a.remote, br, flagged, a.push)
                except Exception as e2:
                    status, acts = f"ERROR {e} / index mode: {e2}", []
                print(f"[clean] {os.path.basename(repo)} {a.remote}/{br}: {status}")
                for x in acts:
                    print(f"           - {x}")
            finally:
                git(repo, "worktree", "remove", "--force", wt, check=False)
                shutil.rmtree(wt, ignore_errors=True)
            summary.append((os.path.basename(repo), br, status.split(" ")[0]))
    print("\nsummary:")
    for r, b, s in summary:
        print(f"  {s:16} {r} {b}")


if __name__ == "__main__":
    main()
