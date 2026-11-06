#!/usr/bin/env python3
"""denycheck: keep internal references out of this public repository.

leakcheck.py looks for credentials, machine names, account ids and IP
addresses. denycheck.py looks for the rest: tracking and review ids, internal
hosts, e-mail addresses, dates of decisions, environment names and the custody
design of signing keys, and a list of names. It reads the path of every file
as well as its text, because a file name or a test name can carry an id.

The rules are in scripts/denycheck.rules. A pattern appears there as it is. A
name appears only as the SHA-256 of its lower-case form, so the list does not
publish what it forbids. The script splits every file into tokens
([A-Za-z0-9]+), lower-cases them, hashes each one and compares. That finds a
whole word, not a part of a longer word; the exporter that writes this
repository checks for parts as well.

A gzip file is read decompressed. A file that is not UTF-8 text is a failure,
because the script cannot read it.

  denycheck.py              scan every tracked file
  denycheck.py --paths F..  scan the named files

Exit codes: 0 clean, 1 findings, 2 usage or environment error.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "scripts", "denycheck.rules")
# The rules file holds the patterns, so the patterns match themselves. The
# leakcheck files are the checker that every public RunOS repository carries,
# byte for byte; its tests hold the very shapes it must catch.
SKIP = {
    "scripts/denycheck.rules",
    "scripts/leakcheck.py",
    "scripts/leakcheck_test.py",
    "scripts/leakcheck.config",
    "scripts/leakcheck.baseline",
}

TOKEN = re.compile(r"[A-Za-z0-9]+")


def load_rules(path):
    res, paths, allows, hashes = [], [], [], set()
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, _, rest = line.partition(" ")
            rest = rest.strip()
            if kind == "re":
                name, _, expr = rest.partition(" ")
                res.append((name, re.compile(expr.strip(), re.IGNORECASE)))
            elif kind == "path":
                name, _, expr = rest.partition(" ")
                paths.append((name, re.compile(expr.strip(), re.IGNORECASE)))
            elif kind == "allow":
                allows.append(re.compile("^(?:" + rest + ")$", re.IGNORECASE))
            elif kind == "hash":
                hashes.add(rest.lower())
            else:
                sys.stderr.write("denycheck: %s:%d: unknown rule %r\n" % (path, n, kind))
                sys.exit(2)
    return res, paths, allows, hashes


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.stderr.write("denycheck: cannot list tracked files: %s\n" % exc)
        sys.exit(2)
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def scan_path(rel, paths):
    return [(rel, 0, pname, m.group(0)) for pname, rx in paths for m in rx.finditer(rel)]


def scan(name, data, res, allows, hashes):
    out = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [(name, 0, "unreadable", "not UTF-8 text")]
    if "\x00" in text:
        return [(name, 0, "unreadable", "contains a NUL byte")]
    for i, line in enumerate(text.split("\n"), 1):
        for rname, rx in res:
            for m in rx.finditer(line):
                if any(a.match(m.group(0)) for a in allows):
                    continue
                out.append((name, i, rname, m.group(0)))
        for tok in TOKEN.findall(line):
            if hashlib.sha256(tok.lower().encode()).hexdigest() in hashes:
                out.append((name, i, "listed-name", "a name on the list"))
    return out


def main(argv):
    res, paths, allows, hashes = load_rules(RULES)
    if argv[:1] == ["--paths"]:
        files = argv[1:]
    elif argv:
        sys.stderr.write(__doc__)
        return 2
    else:
        files = tracked_files()
    findings = []
    for rel in files:
        if rel in SKIP:
            continue
        full = rel if os.path.isabs(rel) else os.path.join(ROOT, rel)
        if not os.path.isfile(full):
            continue
        with open(full, "rb") as fh:
            data = fh.read()
        findings.extend(scan_path(os.path.relpath(full, ROOT).replace(os.sep, "/"), paths))
        name = rel
        if rel.endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except OSError as exc:
                findings.append((rel, 0, "unreadable", "bad gzip: %s" % exc))
                continue
            name = rel + "!gunzip"
        findings.extend(scan(name, data, res, allows, hashes))
    if findings:
        sys.stderr.write("\ndenycheck FAILED\n")
        for f, ln, rule, text in findings:
            sys.stderr.write("  %s:%d: %s: %s\n" % (f, ln, rule, text))
        sys.stderr.write("\n  Remove or reword the text. Do not add an exception.\n\n")
        return 1
    print("denycheck: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
