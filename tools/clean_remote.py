#!/usr/bin/env python3
# POLINRIDER-HUNTER-DETECTOR: this tool names malware signatures to find them. Not malware.
"""Clean every infected branch found by scan_remote.py - for repos that are NOT cloned on this machine.

  python -u tools/clean_remote.py <scan-output.txt> [--push] [--skip prod,production] [--only-repo owner/repo,...] [--jobs 4]

Works inside scan_remote.py's blob:none bare clones (same --cache dir) using branch_clean.index_clean:
the tip tree is rewritten in a private index (payload never touches the disk), committed on top of the
tip and pushed as a normal fast-forward `git push origin <commit>:refs/heads/<branch>` - never --force.
Without --push it is a dry run. Branches named in --skip are reported and left alone.
"""
import argparse, os, re, sys, concurrent.futures as cf

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from branch_clean import index_clean, ARTIFACTS  # noqa: E402

LINE = re.compile(r"^INFECTED (\S+) (\S+) :: (\S+) ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scan")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--skip", default="prod,production")
    ap.add_argument("--only-repo", default="")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--cache", default=os.path.join(os.environ.get("TEMP", "/tmp"), "pr-remote-scan"))
    a = ap.parse_args()
    skip = {b for b in a.skip.split(",") if b}
    only = {r for r in a.only_repo.split(",") if r}
    work = {}
    for l in open(a.scan, encoding="utf8", errors="replace"):
        m = LINE.match(l)
        if not m:
            continue
        repo, br, path = m.groups()
        if only and repo not in only:
            continue
        files = work.setdefault(repo, {}).setdefault(br, set())
        if os.path.basename(path) not in ARTIFACTS and os.path.basename(path) not in ("package.json", ".gitignore"):
            files.add(path)

    def do_repo(repo):
        d = os.path.join(a.cache, repo.replace("/", "__") + ".git")
        out = []
        for br, flagged in sorted(work[repo].items()):
            if br in skip:
                out.append(f"  SKIPPED          {repo} {br} (protected by --skip)"); continue
            try:
                status, acts = index_clean(d, "origin", br, flagged, a.push, tip_ref=f"refs/heads/{br}")
            except Exception as e:
                status, acts = f"ERROR {str(e)[-200:]}", []
            out.append(f"  {status.split(' ')[0]:16} {repo} {br} :: {status} | {'; '.join(acts)}")
        return out

    with cf.ThreadPoolExecutor(a.jobs) as ex:
        for lines in ex.map(do_repo, sorted(work)):
            for l in lines:
                print(l, flush=True)


if __name__ == "__main__":
    main()
