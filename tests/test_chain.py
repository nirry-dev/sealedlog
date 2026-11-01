import dataclasses
import unittest

from sealedlog.chain import GENESIS, Record, canonical, seal_record, verify_records


def build(entries, *, key=None, genesis=GENESIS):
    recs, prev = [], genesis
    for i, e in enumerate(entries):
        ts = f"t{i}"
        s = seal_record(i, ts, prev, e, key=key)
        recs.append(Record(i, ts, prev, s, e))
        prev = s
    return recs


class TestCanonical(unittest.TestCase):
    def test_key_order_independent(self):
        self.assertEqual(canonical({"b": 1, "a": 2}), canonical({"a": 2, "b": 1}))
        self.assertEqual(canonical({"b": 1, "a": 2}), '{"a":2,"b":1}')


class TestSeal(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(seal_record(0, "t", "p", {"x": 1}), seal_record(0, "t", "p", {"x": 1}))

    def test_key_changes_seal(self):
        self.assertNotEqual(seal_record(0, "t", "p", {"x": 1}), seal_record(0, "t", "p", {"x": 1}, key="k"))


class TestVerify(unittest.TestCase):
    def test_valid_chain(self):
        recs = build([{"a": 1}, {"b": 2}, {"c": 3}])
        v = verify_records(recs)
        self.assertTrue(v.ok)
        self.assertEqual(v.count, 3)
        self.assertEqual(v.head, recs[-1].seal)

    def test_empty(self):
        v = verify_records([])
        self.assertTrue(v.ok)
        self.assertEqual(v.count, 0)
        self.assertIsNone(v.head)

    def test_tampered_entry(self):
        recs = build([{"a": 1}, {"b": 2}])
        recs[1] = dataclasses.replace(recs[1], entry={"b": 999})  # seal no longer matches
        v = verify_records(recs)
        self.assertFalse(v.ok)
        self.assertEqual(v.broken_seq, 1)
        self.assertIn("tampered", v.reason)

    def test_out_of_sequence(self):
        recs = build([{"a": 1}, {"b": 2}, {"c": 3}])
        v = verify_records([recs[0], recs[2]])  # record 1 dropped
        self.assertFalse(v.ok)
        self.assertEqual(v.broken_seq, 2)
        self.assertIn("sequence", v.reason)

    def test_broken_link(self):
        recs = build([{"a": 1}, {"b": 2}])
        bad = seal_record(2, "t2", recs[0].seal, {"c": 3})  # links to record 0, not 1
        recs.append(Record(2, "t2", recs[0].seal, bad, {"c": 3}))
        v = verify_records(recs)
        self.assertFalse(v.ok)
        self.assertEqual(v.broken_seq, 2)
        self.assertIn("link", v.reason)

    def test_keyed(self):
        recs = build([{"a": 1}], key="secret")
        self.assertTrue(verify_records(recs, key="secret").ok)
        self.assertFalse(verify_records(recs, key="wrong").ok)
        self.assertFalse(verify_records(recs).ok)


if __name__ == "__main__":
    unittest.main()
