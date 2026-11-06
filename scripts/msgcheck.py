#!/usr/bin/env python3
"""msgcheck: keep internal references out of commit messages and file names.

A commit message and a file name are public text in a public repository, and
the file scanners do not read them. msgcheck runs the same two rule sets over
them:

  scripts/leakcheck.py   credential shapes, machine names, account ids, IP
                         addresses
  scripts/denycheck.py   internal references, listed names, and (for file
                         names) the path rules in scripts/denycheck.rules

  msgcheck.py --range A..B       every commit message and the name of every
                                 file that the commits in the range add or
                                 change. The value may hold more rev-list words,
                                 for example "SHA --not --remotes=origin"
  msgcheck.py --message-file F   one message file (the commit-msg hook); lines
                                 that start with # are git comments and skipped
  msgcheck.py --repo DIR ...     run in another repository (the tests do)

Exit codes: 0 clean, 1 findings, 2 usage or environment error.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


leakcheck = load("leakcheck")
denycheck = load("denycheck")


class Checker:
    def __init__(self):
        cfg = leakcheck.load_config(os.path.join(HERE, "leakcheck.config"))
        self.patterns = leakcheck.build_identifier_patterns(cfg)
        self.res, self.paths, self.allows, self.hashes = denycheck.load_rules(denycheck.RULES)

    def text(self, label, text):
        """Return (label, line, rule, token) findings for a block of text."""
        out = []
        for f in leakcheck.scan_line(label, 1, text, self.patterns):
            out.append((label, 0, f.kind, f.token))
        out.extend(denycheck.scan(label, text.encode("utf-8"), self.res, self.allows, self.hashes))
        return out

    def path(self, label, rel):
        out = []
        for f in leakcheck.scan_line(label, 1, rel, self.patterns):
            out.append((label, 0, f.kind, f.token))
        out.extend(denycheck.scan_path(rel, self.paths))
        # A file name is not prose, so only the list of names applies to it.
        for tok in denycheck.TOKEN.findall(rel):
            if hashlib.sha256(tok.lower().encode()).hexdigest() in self.hashes:
                out.append((label, 0, "listed-name", "a name on the list"))
        return out


def git(repo, *args):
    try:
        return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"").decode("utf-8", "replace").strip()
        sys.stderr.write("msgcheck: git %s failed: %s %s\n" % (" ".join(args), exc, detail))
        sys.exit(2)


def check_range(checker, repo, rng):
    findings = []
    shas = git(repo, "rev-list", "--reverse", *rng.split()).decode().split()
    for sha in shas:
        short = sha[:12]
        msg = git(repo, "log", "-1", "--format=%B", sha).decode("utf-8", "replace")
        findings.extend(checker.text("commit %s message" % short, msg))
        names = git(repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "-z", "--no-renames", "--diff-filter=AMC", sha)
        for rel in filter(None, names.decode("utf-8", "replace").split("\0")):
            findings.extend(checker.path("commit %s file %s" % (short, rel), rel))
    return findings, len(shas)


def main(argv):
    ap = argparse.ArgumentParser(prog="msgcheck", description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--range", dest="rng", metavar="A..B")
    mode.add_argument("--message-file", metavar="FILE")
    ap.add_argument("--repo", default=".")
    args = ap.parse_args(argv)

    checker = Checker()
    if args.message_file:
        try:
            with open(args.message_file, encoding="utf-8", errors="replace") as fh:
                lines = [ln for ln in fh.read().split("\n") if not ln.startswith("#")]
        except OSError as exc:
            sys.stderr.write("msgcheck: cannot read %s: %s\n" % (args.message_file, exc))
            return 2
        findings, count = checker.text("commit message", "\n".join(lines)), 1
    else:
        findings, count = check_range(checker, args.repo, args.rng)

    if findings:
        sys.stderr.write("\nmsgcheck FAILED\n")
        for label, _, rule, token in findings:
            sys.stderr.write("  %s: %s: %s\n" % (label, rule, token))
        sys.stderr.write("\n  Reword the message or rename the file. Do not add an exception.\n\n")
        return 1
    print("msgcheck: clean (%d commit%s)" % (count, "" if count == 1 else "s"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
