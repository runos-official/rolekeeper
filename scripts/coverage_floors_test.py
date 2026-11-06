#!/usr/bin/env python3
"""Tests for scripts/coverage-floors.

Run: python3 scripts/coverage_floors_test.py
"""

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "coverage-floors")

loader = importlib.machinery.SourceFileLoader("coverage_floors", SCRIPT)
spec = importlib.util.spec_from_loader("coverage_floors", loader)
cf = importlib.util.module_from_spec(spec)
loader.exec_module(cf)

PREFIX = "example.com/m/"

OUTPUT = """\
ok  \texample.com/m/compile\t1.2s\tcoverage: 97.7% of statements
ok  \texample.com/m/signer/keys\t9.9s\tcoverage: 60.0% of statements
ok  \texample.com/m/deploy\t0.5s\tcoverage: [no statements]
?   \texample.com/m/cmd/tool\t[no test files]
"""


class ParseTest(unittest.TestCase):
    def test_reads_percentages_no_statements_and_missing_tests(self):
        cover, failed = cf.parse(OUTPUT, PREFIX)
        self.assertFalse(failed)
        self.assertEqual(cover, {"compile": 97.7, "signer/keys": 60.0, "deploy": None, "cmd/tool": 0.0})

    def test_a_failing_package_is_noticed(self):
        _, failed = cf.parse(OUTPUT + "FAIL\texample.com/m/bundle\t0.1s\n", PREFIX)
        self.assertTrue(failed)


class CheckTest(unittest.TestCase):
    def test_every_floor_holding_is_no_problem(self):
        self.assertEqual(cf.check({"a": 80.0, "b": None}, {"a": 80.0}), [])

    def test_below_the_floor_fails(self):
        problems = cf.check({"a": 79.9}, {"a": 80.0})
        self.assertEqual(len(problems), 1)
        self.assertIn("below the floor", problems[0])

    def test_a_package_without_a_floor_fails(self):
        problems = cf.check({"a": 50.0, "new": 10.0}, {"a": 40.0})
        self.assertEqual(len(problems), 1)
        self.assertIn("new", problems[0])
        self.assertIn("no floor", problems[0])

    def test_a_package_with_no_tests_needs_a_floor_of_zero(self):
        self.assertEqual(cf.check({"x": 0.0}, {"x": 0.0}), [])
        self.assertEqual(len(cf.check({"x": 0.0}, {})), 1)

    def test_a_stale_floor_fails(self):
        problems = cf.check({"a": 90.0}, {"a": 80.0, "gone": 10.0})
        self.assertEqual(len(problems), 1)
        self.assertIn("gone", problems[0])


class FloorsFileTest(unittest.TestCase):
    def write(self, text):
        fd, path = tempfile.mkstemp(suffix=".txt")
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        return path

    def test_comments_and_blank_lines_are_skipped(self):
        path = self.write("# note\n\na 80 # trailing\nb/c 7.5\n")
        self.assertEqual(cf.load_floors(path), {"a": 80.0, "b/c": 7.5})

    def test_a_bad_line_stops_the_check(self):
        for text in ("a\n", "a b\n", "a 1 2\n", "a 1\na 2\n"):
            with self.assertRaises(SystemExit):
                cf.load_floors(self.write(text))

    def test_the_real_floors_file_loads_and_every_floor_is_a_percentage(self):
        floors = cf.load_floors(cf.DEFAULT_FLOORS)
        self.assertGreater(len(floors), 5)
        for pkg, floor in floors.items():
            self.assertTrue(0 <= floor <= 100, pkg)

    def test_the_floors_for_the_packages_with_hand_built_tests_stay_high(self):
        floors = cf.load_floors(cf.DEFAULT_FLOORS)
        for pkg, minimum in (("compile", 70), ("reconcile", 50), ("kobj", 70), ("signer", 80)):
            self.assertGreaterEqual(floors[pkg], minimum, pkg)


class CommandTest(unittest.TestCase):
    def run_script(self, output):
        fd, out = tempfile.mkstemp(suffix=".out")
        self.addCleanup(os.unlink, out)
        with os.fdopen(fd, "w") as fh:
            fh.write(output)
        return subprocess.run([sys.executable, SCRIPT, "--from", out], capture_output=True, text=True)

    def module_lines(self):
        prefix = cf.module_path() + "/"
        floors = cf.load_floors(cf.DEFAULT_FLOORS)
        return prefix, floors

    def test_output_at_the_floors_passes(self):
        prefix, floors = self.module_lines()
        text = "".join("ok  \t%s%s\t1s\tcoverage: %.1f%% of statements\n" % (prefix, p, f) for p, f in floors.items())
        res = self.run_script(text)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_one_package_under_its_floor_fails(self):
        prefix, floors = self.module_lines()
        text = "".join("ok  \t%s%s\t1s\tcoverage: %.1f%% of statements\n" % (prefix, p, f - (1 if p == "compile" else 0)) for p, f in floors.items())
        res = self.run_script(text)
        self.assertEqual(res.returncode, 1)
        self.assertIn("compile", res.stderr)

    def test_output_with_a_failed_test_fails(self):
        prefix, floors = self.module_lines()
        text = "".join("ok  \t%s%s\t1s\tcoverage: 100.0%% of statements\n" % (prefix, p) for p in floors) + "FAIL\t%sbundle\t1s\n" % prefix
        self.assertEqual(self.run_script(text).returncode, 1)

    def test_output_with_no_coverage_lines_is_an_error(self):
        self.assertEqual(self.run_script("nothing\n").returncode, 2)


if __name__ == "__main__":
    unittest.main()
