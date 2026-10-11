"""excise_remote.py - replace (poisoned twin + cleanup) on every branch of an owner's repos with the clean commit.

For each branch whose tip T is the 2026-10-11 "security: remove injected PolinRider malware"
cleanup commit, and whose parent P is the poisoned twin:
  - if a local clone holds a commit with P's subject + author date and the SAME tree as T,
    force-push that original commit;
  - otherwise create, via the GitHub API, a commit with T's (clean) tree, P's parents and
    P's message/author/committer, and force-update the branch to it (lease: only if tip is still T).
Usage: python -I excise_remote.py --owner <user-or-org> --local local.txt [--push]
       [--cleanup-subject "security: remove injected PolinRider malware"] [--cleanup-date 2026-10-11]

local.txt: one "<clone url>|<path relative to your home dir>" per line, for clones whose original
commits may still exist (they are fetched, never modified). It may be empty.
Run tools/scan_remote.py --owner <same> first: it fills the bare-clone cache this reads.
Needs `gh` logged in with push rights. Run it without --push first: it prints the plan only.
"""
import argparse, json, os, re, subprocess, sys

CLEAN_MSG = "security: remove injected PolinRider malware"
PAYLOAD = re.compile(r"(^|/)(api\.js|package\.json|\.gitignore|config\.bat|branch_structure\.json|temp_\w+\.bat"
                     r"|[\w.-]*\.config\.(c|m)?(js|ts)|eslint\.config\.\w+|\.vscode/.*|public/fonts/.*|.*\.(llf|lkf))$")


def git(d, *a):
    return subprocess.run(["git", "-C", d, *a], capture_output=True, text=True, encoding="utf-8", errors="replace")


def gh(*a, inp=None):
    return subprocess.run(["gh", *a], capture_output=True, text=True, input=inp, encoding="utf-8", errors="replace")


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap =argparse.ArgumentParser()
    ap.add_argument("--owner", required=True)
    ap.add_argument("--local", required=True)
    ap.add_argument("--cache", default=os.path.join(os.environ["TEMP"], "pr-remote-scan"))
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--cleanup-subject", default=CLEAN_MSG)
    ap.add_argument("--cleanup-date", default="2026-10-11", help="author date (YYYY-MM-DD) of the cleanup commits")
    a = ap.parse_args()

    locals_by_repo = {}
    for line in open(a.local, encoding="utf-8"):
        url, _, path = line.strip().partition("|")
        name = url.rstrip("/").removesuffix(".git").split("/")[-1].lower()
        locals_by_repo.setdefault(name, []).append(os.path.join(os.environ["USERPROFILE"], path))

    repos = gh("repo", "list", a.owner, "--limit", "1000", "--json", "name,isEmpty",
               "--jq", ".[] | select(.isEmpty|not) | .name").stdout.split()
    for name in repos:
        d = os.path.join(a.cache, f"{a.owner}__{name}.git")
        if not os.path.isdir(d):
            print(f"NOCACHE {name}"); continue
        git(d, "fetch", "-q", "--prune", "origin", "+refs/heads/*:refs/heads/*")
        for br in git(d, "for-each-ref", "--format=%(refname:short)", "refs/heads").stdout.split():
            t = git(d, "rev-parse", br).stdout.strip()
            subj, adate = git(d, "log", "-1", "--format=%s%x00%ad", "--date=short", t).stdout.strip().split("\x00")
            if subj != a.cleanup_subject or adate != a.cleanup_date:
                continue
            p = git(d, "rev-parse", t + "^").stdout.strip()
            changed = git(d, "diff", "--name-only", p, t).stdout.split()
            bad = [f for f in changed if not PAYLOAD.search(f)]
            if bad:
                print(f"SKIP    {name} {br}: cleanup touched non-payload files {bad[:5]}"); continue
            tree = git(d, "rev-parse", t + "^{tree}").stdout.strip()
            meta = git(d, "log", "-1", "--format=%P%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI", p).stdout.strip("\n").split("\x00")
            parents = meta[0].split()
            msg = git(d, "log", "-1", "--format=%B", p).stdout.rstrip("\n") + "\n"
            psubj = msg.splitlines()[0] if msg.strip() else ""
            # 1) a local original with the identical clean tree
            orig = None
            for ld in locals_by_repo.get(name.lower(), []):
                git(ld, "fetch", "-q", "origin")
                for c in git(ld, "log", "--all", "--format=%H%x00%T%x00%aI%x00%s", "-n", "2000").stdout.splitlines():
                    h, tr, ad, s = c.split("\x00", 3)
                    if tr == tree and h not in (t, p) and s == psubj and ad == meta[3]:
                        orig = (ld, h); break
                if orig: break
            if orig:
                print(f"RESTORE {name} {br}: local original {orig[1][:7]} from {orig[0]}")
                if a.push:
                    r = git(orig[0], "push", f"--force-with-lease=refs/heads/{br}:{t}", "origin", f"{orig[1]}:refs/heads/{br}")
                    print("   ", (r.stderr.strip().splitlines() or ["ok"])[-1])
                continue
            print(f"REBUILD {name} {br}: '{psubj[:60]}' on {len(parents)} parent(s)")
            if a.push:
                body = {"message": msg, "tree": tree, "parents": parents,
                        "author": {"name": meta[1], "email": meta[2], "date": meta[3]},
                        "committer": {"name": meta[4], "email": meta[5], "date": meta[6]}}
                r = gh("api", f"repos/{a.owner}/{name}/git/commits", "--input", "-", inp=json.dumps(body))
                if r.returncode:
                    print("    commit FAILED", r.stdout[-200:], r.stderr[-200:]); continue
                new = json.loads(r.stdout)["sha"]
                # lease: re-read tip right before the forced update
                cur = gh("api", f"repos/{a.owner}/{name}/git/ref/heads/{br}", "--jq", ".object.sha").stdout.strip()
                if cur != t:
                    print(f"    tip moved ({cur[:7]}), skipped"); continue
                r = gh("api", "-X", "PATCH", f"repos/{a.owner}/{name}/git/refs/heads/{br}",
                       "-f", f"sha={new}", "-F", "force=true")
                print("    ->", new[:7] if r.returncode == 0 else f"FAILED {r.stdout[-200:]} {r.stderr[-200:]}")


if __name__ == "__main__":
    main()
