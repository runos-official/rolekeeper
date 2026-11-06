#!/usr/bin/env python3
"""Tests for scripts/msgcheck.py, in a throwaway git repository.

Run: python3 scripts/msgcheck_test.py
"""

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MSGCHECK = os.path.join(HERE, "msgcheck.py")


def git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
    subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, env=env)


def commit(repo, name, message):
    with open(os.path.join(repo, name), "w", encoding="utf-8") as fh:
        fh.write("content\n")
    git(repo, "add", name)
    git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", message)


def run(*args, repo="."):
    return subprocess.run([sys.executable, MSGCHECK, "--repo", repo, *args], capture_output=True, text=True)


class MsgcheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        git(self.repo, "init", "-q", "-b", "dev")
        commit(self.repo, "base.txt", "Start")
        git(self.repo, "tag", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_commits_pass(self):
        commit(self.repo, "reconcile.go", "Repair drift in the reconciler")
        out = run("--range", "base..HEAD", repo=self.repo)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("clean (1 commit)", out.stdout)

    def test_a_tracking_id_in_a_message_fails(self):
        commit(self.repo, "a.go", "Fix the thing from FP" + "L123")
        out = run("--range", "base..HEAD", repo=self.repo)
        self.assertEqual(out.returncode, 1)
        self.assertIn("fpl-number", out.stderr)

    def test_an_ip_address_in_a_message_fails(self):
        commit(self.repo, "a.go", "Probe 8.8." + "4.4 first")
        self.assertEqual(run("--range", "base..HEAD", repo=self.repo).returncode, 1)

    def test_a_documentation_address_passes(self):
        commit(self.repo, "a.go", "Probe 192.0.2.7 first")
        self.assertEqual(run("--range", "base..HEAD", repo=self.repo).returncode, 0)

    def test_a_file_name_with_an_id_fails(self):
        commit(self.repo, "f18" + "d_test.go", "Add a test")
        out = run("--range", "base..HEAD", repo=self.repo)
        self.assertEqual(out.returncode, 1)
        self.assertIn("file-name-id", out.stderr)

    def test_a_deleted_file_with_an_id_in_its_name_is_not_a_finding(self):
        commit(self.repo, "f18" + "d_test.go", "Add a test")
        git(self.repo, "tag", "mid")
        git(self.repo, "rm", "-q", "f18" + "d_test.go")
        git(self.repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Remove the test")
        self.assertEqual(run("--range", "mid..HEAD", repo=self.repo).returncode, 0)

    def test_the_message_file_skips_git_comments(self):
        path = os.path.join(self.repo, "MSG")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("Clean subject\n\n# FP" + "L123 in a comment line is not part of the message\n")
        self.assertEqual(run("--message-file", path, repo=self.repo).returncode, 0)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("Subject from FP" + "L123\n")
        self.assertEqual(run("--message-file", path, repo=self.repo).returncode, 1)


if __name__ == "__main__":
    unittest.main()
