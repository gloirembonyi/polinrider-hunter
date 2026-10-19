#!/usr/bin/env bash
# POLINRIDER-HUNTER-DETECTOR: names campaign artefacts to recognise them. Not malware.
#
# After `repos --repair`, a local branch usually shows "1 ahead, 2 behind": the local commit is
# your original, the remote holds the campaign's re-pushed twin of it plus the cleanup. If the
# local-only commits carry nothing the remote tip lacks, the branch is moved to the remote tip.
#
#   bash tools/sync_after_repair.sh <repo> <branch> [<branch>...]
#
# Safety: the old tip is kept at refs/backup/<date>/<branch> (restore with
# `git branch -f <branch> refs/backup/<date>/<branch>`); a checked-out branch moves with
# `reset --keep`, which keeps uncommitted work and refuses instead of overwriting it; a branch
# whose local-only commits contain real changes is skipped.
G="git -c core.fsmonitor=false -c core.hooksPath=NUL"
day=$(date +%Y-%m-%d)
r=$1; shift
cur=$($G -C "$r" rev-parse --abbrev-ref HEAD)
for b in "$@"; do
  u=$($G -C "$r" rev-parse --abbrev-ref "$b@{u}" 2>/dev/null) || { echo "  SKIP $b: no upstream"; continue; }
  old=$($G -C "$r" rev-parse "$b")
  mb=$($G -C "$r" merge-base "$b" "$u")
  for f in $($G -C "$r" diff --name-only "$mb" "$b"); do
    $G -C "$r" diff --quiet "$b" "$u" -- "$f" && continue
    if [ "$f" = .gitignore ]; then
      # only the campaign's hiding lines may differ
      $G -C "$r" diff "$b" "$u" -- "$f" | grep -E '^[-+][^-+]' \
        | grep -qvE 'config\.bat|branch_structure\.json|temp_.*push\.bat|spellright\.dict' \
        && { echo "  SKIP $b: local $f has real changes"; continue 2; }
    else
      echo "  SKIP $b: local $f differs from $u - merge by hand"; continue 2
    fi
  done
  $G -C "$r" update-ref "refs/backup/$day/$b" "$old"
  if [ "$b" = "$cur" ]; then
    # a modified file whose content already equals the target's needs no keeping
    for f in $($G -C "$r" diff --name-only); do
      [ "$($G -C "$r" hash-object -- "$r/$f")" = "$($G -C "$r" rev-parse "$u:$f" 2>/dev/null)" ] \
        && $G -C "$r" checkout -q HEAD -- "$f"
    done
    if $G -C "$r" reset -q --keep "$u"; then
      echo "  OK   $b -> $u (checked out; uncommitted work kept)"
    else
      echo "  FAIL $b: reset --keep refused (uncommitted changes overlap) - left as it was"
    fi
  else
    $G -C "$r" branch -q -f "$b" "$u" && echo "  OK   $b -> $u"
  fi
done
