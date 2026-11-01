import json
import os
import tempfile
import unittest

from sealedlog import Log, LogError


class LogTemp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "audit.jsonl")

    def tearDown(self):
        self.dir.cleanup()

    def _rewrite(self, lines):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    def _lines(self):
        with open(self.path, encoding="utf-8") as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]


class TestAppendVerify(LogTemp):
    def test_append_and_verify(self):
        log = Log(self.path)
        a = log.append({"n": 1})
        b = log.append({"n": 2})
        self.assertEqual(a.seq, 0)
        self.assertEqual(b.prev, a.seal)
        v = log.verify()
        self.assertTrue(v.ok)
        self.assertEqual(v.count, 2)
        self.assertEqual(v.head, b.seal)
        self.assertEqual(log.head(), b.seal)

    def test_reopen(self):
        Log(self.path).append({"n": 1})
        head = Log(self.path).append({"n": 2}).seal  # second instance continues the chain
        reopened = Log(self.path)
        self.assertTrue(reopened.verify().ok)
        self.assertEqual(reopened.head(), head)

    def test_not_serializable(self):
        with self.assertRaises(LogError):
            Log(self.path).append({"bad": object()})


class TestTamper(LogTemp):
    def setUp(self):
        super().setUp()
        self.log = Log(self.path)
        for i in range(4):
            self.log.append({"i": i})

    def test_edited_entry_detected(self):
        lines = self._lines()
        d = json.loads(lines[1])
        d["entry"] = {"i": 999}  # change content, leave the seal
        lines[1] = json.dumps(d)
        self._rewrite(lines)
        v = Log(self.path).verify()
        self.assertFalse(v.ok)
        self.assertEqual(v.broken_seq, 1)
        self.assertIn("tampered", v.reason)

    def test_deleted_record_detected(self):
        lines = self._lines()
        del lines[1]  # remove a record from the middle
        self._rewrite(lines)
        v = Log(self.path).verify()
        self.assertFalse(v.ok)
        self.assertIn("sequence", v.reason)

    def test_tail_truncation_is_a_shorter_valid_chain(self):
        original_head = Log(self.path).head()
        lines = self._lines()
        self._rewrite(lines[:-1])  # drop the last record
        reopened = Log(self.path)
        self.assertTrue(reopened.verify().ok)  # still internally consistent...
        self.assertNotEqual(reopened.head(), original_head)  # ...but the head moved — anchor it externally


class TestKeyed(LogTemp):
    def test_keyed_roundtrip(self):
        Log(self.path, key="secret").append({"n": 1})
        self.assertTrue(Log(self.path, key="secret").verify().ok)
        self.assertFalse(Log(self.path, key="wrong").verify().ok)
        self.assertFalse(Log(self.path).verify().ok)  # unkeyed verify of a keyed log fails


if __name__ == "__main__":
    unittest.main()
