import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from sealedlog.cli import main


def run(argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    import sys

    real = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = real
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")

    def tearDown(self):
        self.dir.cleanup()

    def test_append_message_then_verify(self):
        code, out, _ = run(["append", self.path, "--message", "deployed v2"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip()), 64)  # a sha256 hex seal
        code, out, _ = run(["verify", self.path])
        self.assertEqual(code, 0)
        self.assertIn("OK", out)

    def test_append_stdin_and_entry(self):
        self.assertEqual(run(["append", self.path, "--stdin"], stdin='{"a":1}')[0], 0)
        self.assertEqual(run(["append", self.path, "--entry", '{"b":2}'])[0], 0)
        _, out, _ = run(["verify", self.path, "--json"])
        self.assertEqual(json.loads(out)["count"], 2)

    def test_verify_detects_tamper(self):
        run(["append", self.path, "--message", "one"])
        run(["append", self.path, "--message", "two"])
        with open(self.path, encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
        d = json.loads(lines[0])
        d["entry"] = {"message": "forged"}
        lines[0] = json.dumps(d)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        code, _, err = run(["verify", self.path])
        self.assertEqual(code, 1)
        self.assertIn("BROKEN", err)

    def test_head_and_cat(self):
        run(["append", self.path, "--message", "x"])
        code, out, _ = run(["head", self.path])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip()), 64)
        code, out, _ = run(["cat", self.path, "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.strip())["entry"], {"message": "x"})

    def test_bad_entry_json(self):
        code, _, err = run(["append", self.path, "--entry", "{not json"])
        self.assertEqual(code, 2)

    def test_two_sources(self):
        code, _, _ = run(["append", self.path, "--message", "a", "--entry", "{}"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
