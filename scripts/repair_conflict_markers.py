#!/usr/bin/env python3
"""Self-heal generated JSON/text files that were committed with git conflict markers.

Root cause this guards against: `git pull --rebase --autostash` run AFTER the
pipeline regenerated bridge/ + data/ stashes the fresh output, rebases onto the
previous hourly commit and re-applies the stash. Both sides touched the same
generated files, so git wrote `<<<<<<< Updated upstream` / `=======` /
`>>>>>>> Stashed changes` into them and the old step then `git add`-ed that.

Resolution policy (generated files only): keep the SECOND side (the freshly
generated "Stashed changes"/incoming content). If the result is not valid JSON,
fall back to the newest earlier git revision that parses. Exit 1 only when a
file cannot be repaired. Use --check to only report (exit 2 if markers found).
"""
import json, re, subprocess, sys
from pathlib import Path

START = re.compile(r'^<<<<<<< .*$')
MID = re.compile(r'^=======\s*$')
END = re.compile(r'^>>>>>>> .*$')
ROOTS = ("bridge", "data", "export", "docs")


def has_markers(text: str) -> bool:
    return any(START.match(l) or END.match(l) for l in text.splitlines())


def resolve_second_side(text: str) -> str:
    out, state = [], 0  # 0 normal, 1 in first side, 2 in second side
    for line in text.splitlines(keepends=True):
        s = line.rstrip("\r\n")
        if state == 0 and START.match(s):
            state = 1
        elif state == 1 and MID.match(s):
            state = 2
        elif state == 2 and END.match(s):
            state = 0
        elif state in (0, 2):
            out.append(line)
    return "".join(out)


def valid(path: Path, text: str) -> bool:
    if path.suffix == ".json":
        try:
            json.loads(text)
        except ValueError:
            return False
    return not has_markers(text)


def git_history_good(path: Path):
    revs = subprocess.run(["git", "log", "--format=%H", "-n", "40", "--", str(path)],
                          capture_output=True, text=True).stdout.split()
    for rev in revs:
        r = subprocess.run(["git", "show", f"{rev}:{path.as_posix()}"], capture_output=True)
        if r.returncode == 0:
            t = r.stdout.decode("utf-8", "replace")
            if valid(path, t):
                return t
    return None


def main() -> int:
    check_only = "--check" in sys.argv
    bad, fixed, failed = [], [], []
    for root in ROOTS:
        for p in sorted(Path(root).rglob("*")) if Path(root).exists() else []:
            if not p.is_file() or p.suffix not in (".json", ".txt", ".md") or p.stat().st_size > 64_000_000:
                continue
            text = p.read_text("utf-8", "replace")
            if not has_markers(text):
                continue
            bad.append(str(p))
            if check_only:
                continue
            cand = resolve_second_side(text)
            if not valid(p, cand):
                cand = git_history_good(p)
            if cand is None:
                failed.append(str(p))
                continue
            p.write_text(cand, "utf-8")
            fixed.append(str(p))
    print(f"conflict-marker files: {len(bad)}  repaired: {len(fixed)}  unrepairable: {len(failed)}")
    for f in bad:
        print(("  FIXED " if f in fixed else "  BAD   ") + f)
    if check_only:
        return 2 if bad else 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
