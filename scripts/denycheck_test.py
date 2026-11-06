#!/usr/bin/env python3
"""Tests for scripts/denycheck.py and the rules file it reads.

Run: python3 scripts/denycheck_test.py
"""

import hashlib
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import denycheck  # noqa: E402


class DenycheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res, cls.paths, cls.allows, cls.hashes = denycheck.load_rules(denycheck.RULES)

    def scan(self, text):
        return denycheck.scan("sample.txt", text.encode(), self.res, self.allows, self.hashes)

    def rules_hit(self, text):
        return {rule for (_, _, rule, _) in self.scan(text)}

    def test_clean_text_has_no_finding(self):
        self.assertEqual(self.scan("The applier verifies the bundle and applies it.\n"), [])

    def test_a_tracking_id_is_a_finding(self):
        self.assertIn("fpl-number", self.rules_hit("see FP" + "L123 for the plan"))

    def test_a_decision_date_is_a_finding(self):
        self.assertIn("iso-date", self.rules_hit("decided on 2026" + "-01-02"))

    def test_an_internal_host_is_a_finding(self):
        self.assertIn("runos-host", self.rules_hit("curl https://api.internal.run" + "os.com/x"))

    def test_an_email_is_a_finding_unless_allowed(self):
        self.assertIn("email", self.rules_hit("write to someone@corp" + ".test"))
        self.assertEqual(self.scan("write to security@runos.com"), [])
        self.assertEqual(self.scan("write to a@example.com"), [])

    def test_a_test_name_with_an_id_is_a_finding(self):
        self.assertIn("test-name-id", self.rules_hit("func Test" + "F18dCutoff(t *testing.T) {"))

    def test_a_listed_name_is_found_by_its_hash_only(self):
        word = "zzquux"
        hashes = {hashlib.sha256(word.encode()).hexdigest()}
        found = denycheck.scan("sample.txt", b"call ZzQuux now", self.res, self.allows, hashes)
        self.assertEqual([r for (_, _, r, _) in found], ["listed-name"])
        self.assertEqual(denycheck.scan("sample.txt", b"call zzquuxes now", self.res, self.allows, hashes), [])

    def test_a_file_name_with_an_id_is_a_finding(self):
        self.assertTrue(denycheck.scan_path("signer/keys/f18" + "d_test.go", self.paths))
        self.assertTrue(denycheck.scan_path("applier/rev" + "iew9_anchors_test.go", self.paths))
        self.assertEqual(denycheck.scan_path("signer/keys/rotation_test.go", self.paths), [])

    def test_a_file_that_is_not_text_is_a_finding(self):
        self.assertEqual(self.scan("a\x00b")[0][2], "unreadable")
        found = denycheck.scan("sample.bin", b"\xff\xfe\x00", self.res, self.allows, self.hashes)
        self.assertEqual(found[0][2], "unreadable")

    def test_hash_line_never_holds_the_word(self):
        line = denycheck.hash_line("SomeName")
        self.assertEqual(line, "hash " + hashlib.sha256(b"somename").hexdigest())
        self.assertNotIn("somename", line.lower())

    def test_hash_option_prints_the_line(self):
        out = subprocess.run([sys.executable, os.path.join(HERE, "denycheck.py"), "--hash", "Word"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertEqual(out.stdout.strip(), denycheck.hash_line("word"))
        bad = subprocess.run([sys.executable, os.path.join(HERE, "denycheck.py"), "--hash", "two words"], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 2)

    def test_the_rules_file_holds_no_plain_name(self):
        with open(denycheck.RULES, encoding="utf-8") as fh:
            for n, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                kind, _, rest = line.partition(" ")
                self.assertIn(kind, ("re", "path", "allow", "hash"), "line %d" % n)
                if kind == "hash":
                    self.assertRegex(rest, r"^[0-9a-f]{64}$", "line %d is not a SHA-256" % n)
        self.assertGreater(len(self.hashes), 0)

    def test_the_whole_tree_is_clean(self):
        out = subprocess.run([sys.executable, os.path.join(HERE, "denycheck.py")], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)


if __name__ == "__main__":
    unittest.main()
