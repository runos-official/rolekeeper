#!/usr/bin/env python3
"""treehash: check the files of this repository against SOURCE.

rolekeeper is generated from the RunOS source. SOURCE records the source
commit and the tree hash of every other file. The tree hash is the SHA-256
over the sorted lines "<sha256 of the file> <mode> <path>", one per file,
each line ended by a newline. The mode is 755 for an executable file and 644
for any other. SOURCE itself is not part of the hash.

  treehash.py            print the tree hash of the files
  treehash.py --check    exit 1 when it differs from SOURCE

The files are the tracked files when this is a git checkout, and every file
below the repository root (without .git) otherwise.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def files():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
        names = [p for p in out.decode("utf-8").split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        names = []
        for d, dirs, fs in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x != ".git"]
            for f in fs:
                names.append(os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/"))
    return sorted(n for n in names if n != "SOURCE")


def tree_hash():
    lines = []
    for rel in files():
        full = os.path.join(ROOT, rel)
        with open(full, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        mode = "755" if os.stat(full).st_mode & 0o111 else "644"
        lines.append("%s %s %s" % (digest, mode, rel))
    lines.sort()
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def recorded():
    with open(os.path.join(ROOT, "SOURCE"), encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("tree-sha256: "):
                return line.split(": ", 1)[1].strip()
    return None


def main(argv):
    got = tree_hash()
    if argv == ["--check"]:
        want = recorded()
        if want != got:
            sys.stderr.write(
                "treehash FAILED: the files hash to %s but SOURCE records %s.\n"
                "This repository is generated from the RunOS source; a hand edit does not belong here.\n"
                % (got, want)
            )
            return 1
        print("treehash: the files match SOURCE (%s)" % got)
        return 0
    if argv:
        sys.stderr.write(__doc__)
        return 2
    print(got)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
