#!/usr/bin/env python3
"""Scan EVERY branch of every GitHub repo of an owner/org for PolinRider, without full clones.

  python -u tools/scan_remote.py --owner gloirembonyi --owner Global-Kwik-Koders [--cache DIR] [--jobs 4]

Per repo: `git clone --bare --filter=blob:none` (commits + trees only, a few MB), then for each branch
tip it lists the tree and downloads ONLY the blobs PolinRider touches (configs, package.json, api.js,
.vscode/tasks.json, fake fonts, .gitignore, dropped .bat/.json artefacts). Nothing is checked out, so
no payload ever lands on disk as a file. Read-only: never pushes. Needs `gh` logged in.

Output lines:  INFECTED <owner/repo> <branch> :: <reason>   |   SUSPECT ...   |   CLEAN <owner/repo> (<n> branches)
"""
import argparse, json, os, re, subprocess, sys, concurrent.futures as cf

ARTIFACTS = {"config.bat", "temp_auto_push.bat", "temp_interactive_push.bat", "branch_structure.json"}
CONFIG_RE = re.compile(r"(^|/)[^/]*(config|rc)\.(js|mjs|cjs|ts|mts|cts)$|(^|/)\.?(eslintrc|babelrc)(\.js|\.cjs)?$", re.I)
FONT_RE = re.compile(r"(^|/)(public|assets|static)/.*fonts?/.*|\.(woff2?|ttf|otf|eot|lkf|llf)$", re.I)
FONT_MAGIC = (b"wOF2", b"wOFF", b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf")
PAD_TAIL = re.compile(rb"[ \t]{20,}\S")
# the real shape (92/92 infected configs): code, then 20+ blanks, then >=200 chars ON THE SAME LINE
APPENDED = re.compile(rb"(?m)\S[ \t]{20,}\S[^\n]{199,}$")
# padding FOLLOWED by a long run of code (swagger docs in api.js are deeply indented comment lines)
PAD_CODE = re.compile(rb"[ \t]{20,}[^ \t*/#\n][^\n]{80,}")
OSM_SIGS = (b'("rmcej%otb%",2857687)', b"global['!']='8-270-2';var _$_1e42=")
JS_HINT = re.compile(rb"_0x[0-9a-f]{3,}|eval\(|Function\(|require\(|atob\(|fromCharCode|global\[")


def git(d, *a, inp=None, check=True):
    r = subprocess.run(["git", "-C", d, *a], input=inp, capture_output=True,
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if check and r.returncode:
        raise RuntimeError(f"git {' '.join(a[:3])}: {r.stderr.decode('utf8','replace').strip()[-300:]}")
    return r.stdout


def blobs(d, oids):
    """Fetch many missing blobs in one request, then read them."""
    oids = sorted(set(oids))
    if not oids:
        return {}
    # one batched fetch of exactly these objects (promisor remote supports want-by-oid)
    git(d, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "--no-tags", "--no-write-fetch-head",
        "--filter=blob:none", "origin", *oids, check=False)
    out = git(d, "cat-file", "--batch", inp=("\n".join(oids) + "\n").encode())
    res, i = {}, 0
    while i < len(out):
        nl = out.index(b"\n", i)
        hdr = out[i:nl].split()
        if len(hdr) < 3 or hdr[1] == b"missing":
            i = nl + 1; continue
        n = int(hdr[2]); res[hdr[0].decode()] = out[nl + 1:nl + 1 + n]; i = nl + 1 + n + 1
    return res


def check_branch(d, ref):
    found = []
    # never ask for %(objectsize): in a blob:none clone that downloads every blob one request at a time
    tree = git(d, "ls-tree", "-r", "-z", "--format=%(objecttype) %(objectname) %(path)", ref).split(b"\0")
    want = {}
    for ent in tree:
        if not ent:
            continue
        typ, oid, path = ent.decode("utf8", "replace").split(" ", 2)
        if typ != "blob":
            continue
        base = path.rsplit("/", 1)[-1]
        if base in ARTIFACTS:
            found.append(("INFECTED", f"{path} (dropped artefact)"))
        if base == "api.js" or base == "package.json" or path.endswith(".vscode/tasks.json") or base == ".gitignore" \
                or CONFIG_RE.search(path) or (FONT_RE.search(path) and re.search(r"\.(woff2?|ttf|otf|eot|lkf|llf)$", path, re.I)):
            want[oid] = want.get(oid, []) + [path]
    data = blobs(d, want)
    for oid, paths in want.items():
        b = data.get(oid)
        if b is None:
            continue
        for path in paths:
            base = path.rsplit("/", 1)[-1]
            if any(sig in b for sig in OSM_SIGS):
                found.append(("INFECTED", f"{path} PolinRider signature (OSM)")); continue
            if base == "package.json":
                if re.search(rb"node\s+(\./)?api\.js", b):
                    found.append(("INFECTED", f"{path} runs `node api.js`"))
            elif base == "api.js":
                code_lines = [l for l in b.splitlines() if not l.lstrip().startswith((b"*", b"//", b"/*"))]
                if any(PAD_CODE.search(l) for l in code_lines) or JS_HINT.search(b) and max(map(len, b.splitlines() or [b""])) > 300:
                    found.append(("INFECTED", f"{path} obfuscated dropper"))
            elif path.endswith(".vscode/tasks.json"):
                if b"folderOpen" in b and re.search(rb"node|\.woff|\.lkf|\.llf|curl|powershell", b):
                    found.append(("INFECTED", f"{path} auto-runs on folder open"))
            elif base == ".gitignore":
                hits = [a for a in ARTIFACTS if a.encode() in b]
                if hits:
                    found.append(("SUSPECT", f"{path} ignores {','.join(sorted(hits))}"))
            elif FONT_RE.search(path) and re.search(r"\.(woff2?|ttf|otf|eot|lkf|llf)$", path, re.I):
                if not b.startswith(FONT_MAGIC) and JS_HINT.search(b[:200000]):
                    found.append(("INFECTED", f"{path} is JavaScript disguised as a font"))
            elif CONFIG_RE.search(path):
                longest = max((len(l) for l in b.splitlines()), default=0)
                if APPENDED.search(b):
                    found.append(("INFECTED", f"{path} payload after padding ({longest} chars)"))
                elif longest > 3000 and JS_HINT.search(b):
                    found.append(("INFECTED", f"{path} obfuscated line ({longest} chars)"))
    return found


def scan(full, cache):
    d = os.path.join(cache, full.replace("/", "__") + ".git")
    try:
        if os.path.isdir(d):
            git(d, "fetch", "-q", "--prune", "--filter=blob:none", "origin", "+refs/heads/*:refs/heads/*")
        else:
            subprocess.run(["git", "clone", "-q", "--bare", "--filter=blob:none", f"https://github.com/{full}.git", d],
                           check=True, capture_output=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
            git(d, "config", "remote.origin.fetch", "+refs/heads/*:refs/heads/*")
        heads = [l.split(" ", 1) for l in git(d, "for-each-ref", "--format=%(objectname) %(refname:short)", "refs/heads").decode().split("\n") if l]
    except Exception as e:
        return [f"ERROR {full} :: {str(e)[-200:]}"]
    if not heads:
        return [f"EMPTY {full}"]
    lines, seen = [], {}
    for oid, br in heads:
        try:
            tree = git(d, "rev-parse", f"{oid}^{{tree}}").decode().strip()
            if tree not in seen:
                seen[tree] = check_branch(d, oid)
            for sev, why in seen[tree]:
                tz = git(d, "log", "-1", "--format=%ci", oid).decode().strip()
                lines.append(f"{sev} {full} {br} :: {why}  [tip {oid[:8]} {tz}]")
        except Exception as e:
            lines.append(f"ERROR {full} {br} :: {str(e)[-200:]}")
    if not any(l.startswith(("INFECTED", "SUSPECT")) for l in lines):
        lines.append(f"CLEAN {full} ({len(heads)} branches)")
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", action="append", required=True)
    ap.add_argument("--repo", action="append", default=[], help="extra owner/repo")
    ap.add_argument("--cache", default=os.path.join(os.environ.get("TEMP", "/tmp"), "pr-remote-scan"))
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()
    os.makedirs(a.cache, exist_ok=True)
    repos = list(a.repo)
    for o in a.owner:
        r = subprocess.run(["gh", "repo", "list", o, "--limit", "1000", "--json", "nameWithOwner,isEmpty",
                            "--jq", ".[] | select(.isEmpty|not) | .nameWithOwner"], capture_output=True, text=True)
        repos += r.stdout.split()
    print(f"scanning {len(repos)} repos", flush=True)
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        for lines in ex.map(lambda f: scan(f, a.cache), repos):
            for l in lines:
                print(l, flush=True)


if __name__ == "__main__":
    main()
