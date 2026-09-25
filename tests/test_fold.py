"""Round-trip and behaviour tests for CYS-ENC26-FOLD.

Uses a fast PBKDF2 round count and a temporary state directory so nothing
touches the real home. Run with: python3 -m unittest discover -s tests
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cys_fold as fold


def _stamp(hours_ago):
    when = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class FoldTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="foldtest-")
        self.state = os.path.join(self.tmp, "state")
        os.makedirs(self.state)
        os.environ["CYS_FOLD_STATE"] = self.state
        # Fast hashing for tests.
        self._orig_rounds = fold.PBKDF2_ROUNDS
        fold.PBKDF2_ROUNDS = 1000

    def tearDown(self):
        fold.PBKDF2_ROUNDS = self._orig_rounds
        os.environ.pop("CYS_FOLD_STATE", None)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- Step 1: derivation and check ----
    def test_derive_vector(self):
        # Fixed vector: same password+salt+rounds must give the same key.
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        h1, k1 = fold.derive("hunter2", salt, 1000)
        h2, k2 = fold.derive("hunter2", salt, 1000)
        self.assertEqual(h1, h2)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 16)                       # 128-bit CYS key
        self.assertEqual(k1.hex().upper(), h1.hex().upper()[:32])
        # Different password -> different key.
        _, k3 = fold.derive("hunter3", salt, 1000)
        self.assertNotEqual(k1, k3)

    def test_check_verify(self):
        salt = os.urandom(16)
        h, _ = fold.derive("pw", salt, 1000)
        rec = {"salt": salt.hex(), "rounds": 1000, "check": fold._check(h, fold.CHECK_LABEL)}
        ok, _, _ = fold.verify(rec, "pw")
        self.assertTrue(ok)
        bad, _, _ = fold.verify(rec, "nope")
        self.assertFalse(bad)

    def test_record_roundtrip(self):
        rec = {"id": fold.new_id(), "path": "/x", "created": fold._now()}
        fold.write_record(rec)
        self.assertEqual(fold.read_record(rec["id"])["path"], "/x")
        self.assertTrue(any(r["id"] == rec["id"] for r in fold.list_records()))
        # Files are private.
        mode = os.stat(fold._record_path(rec["id"])).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    # ---- Step 2: lock / unlock ----
    def _make_folder(self):
        d = os.path.join(self.tmp, "notes")
        os.makedirs(os.path.join(d, "sub", "deep"))
        with open(os.path.join(d, "a file.txt"), "w") as fh:
            fh.write("hello world\n" * 100)
        with open(os.path.join(d, "sub", "b.bin"), "wb") as fh:
            fh.write(os.urandom(2048))
        os.makedirs(os.path.join(d, "empty"))
        os.symlink("a file.txt", os.path.join(d, "link"))
        return d

    def _snapshot(self, root):
        out = {}
        for r, _dirs, files in os.walk(root):
            for f in files:
                p = os.path.join(r, f)
                rel = os.path.relpath(p, root)
                if os.path.islink(p):
                    out[rel] = ("link", os.readlink(p))
                else:
                    with open(p, "rb") as fh:
                        out[rel] = ("file", fh.read())
        # Record empty dirs too.
        for r, dirs, files in os.walk(root):
            if not dirs and not files:
                out[os.path.relpath(r, root) + "/"] = ("dir", b"")
        return out

    def test_folder_roundtrip(self):
        d = self._make_folder()
        before = self._snapshot(d)
        rec = fold.lock_folder(d, "secret")
        self.assertFalse(os.path.exists(d))                 # original gone
        self.assertTrue(os.path.exists(rec["locked_path"]))
        self.assertTrue(rec["locked_path"].endswith(".f.cys26"))
        restored = fold.unlock_folder(rec, "secret")
        self.assertEqual(restored, d)
        self.assertEqual(self._snapshot(d), before)
        self.assertFalse(os.path.exists(rec["locked_path"]))  # locked file gone
        self.assertEqual(fold.list_records(), [])             # record gone

    def test_empty_folder_roundtrip(self):
        d = os.path.join(self.tmp, "hollow")
        os.makedirs(d)
        rec = fold.lock_folder(d, "pw")
        fold.unlock_folder(rec, "pw")
        self.assertTrue(os.path.isdir(d))

    def test_single_file_roundtrip(self):
        p = os.path.join(self.tmp, "one file.dat")
        data = os.urandom(5000)
        with open(p, "wb") as fh:
            fh.write(data)
        rec = fold.lock_folder(p, "pw")
        self.assertEqual(rec["kind"], "file")
        self.assertFalse(os.path.exists(p))
        fold.unlock_folder(rec, "pw")
        with open(p, "rb") as fh:
            self.assertEqual(fh.read(), data)

    def test_wrong_password_unlock_raises(self):
        d = self._make_folder()
        rec = fold.lock_folder(d, "right")
        with self.assertRaises(PermissionError):
            fold.unlock_folder(rec, "wrong")
        self.assertTrue(os.path.exists(rec["locked_path"]))  # still locked

    def test_restore_conflict(self):
        d = self._make_folder()
        rec = fold.lock_folder(d, "pw")
        os.makedirs(d)                                       # something back at the path
        with self.assertRaises(FileExistsError):
            fold.unlock_folder(rec, "pw")

    # ---- Step 3: counter + lockout ----
    def test_prune_window(self):
        fails = [_stamp(1), _stamp(13), _stamp(0.5)]
        self.assertEqual(len(fold._prune_fails(fails)), 2)

    def test_lockout_after_five(self):
        d = self._make_folder()
        rec = fold.lock_folder(d, "right")
        for i in range(4):
            locked_out, tries = fold.register_wrong_try(rec)
            self.assertFalse(locked_out)
            self.assertEqual(tries, i + 1)
        locked_out, tries = fold.register_wrong_try(rec)
        self.assertTrue(locked_out)
        # The right password no longer opens it.
        with self.assertRaises(PermissionError):
            fold.unlock_folder(rec, "right")
        self.assertEqual(rec["state"], "locked")            # still a lock, just dead
        self.assertTrue(os.path.exists(rec["locked_path"]))

    def test_lockout_password_classes(self):
        pw = fold.make_lockout_password()
        self.assertEqual(len(pw), 128)
        self.assertGreaterEqual(sum(c.isupper() for c in pw), 14)
        self.assertGreaterEqual(sum(c.islower() for c in pw), 10)
        self.assertGreaterEqual(sum(c.isdigit() for c in pw), 8)
        self.assertGreaterEqual(sum(c in fold.LOCKOUT_SYMBOLS for c in pw), 4)

    def test_old_fails_dont_trigger(self):
        d = self._make_folder()
        rec = fold.lock_folder(d, "right")
        rec["fails"] = [_stamp(13)] * 4                      # all outside the window
        locked_out, tries = fold.register_wrong_try(rec)
        self.assertFalse(locked_out)
        self.assertEqual(tries, 1)

    # ---- Step 4: self-destruct ----
    def test_self_destruct(self):
        d = self._make_folder()
        other = os.path.join(self.tmp, "keepme.txt")
        with open(other, "w") as fh:
            fh.write("untouched")
        rec = fold.lock_folder(d, "pw", selfdestruct="boom")
        self.assertTrue(fold.is_selfdestruct(rec, "boom"))
        self.assertFalse(fold.is_selfdestruct(rec, "pw"))
        fold.self_destruct(rec)
        self.assertFalse(os.path.exists(rec["locked_path"]))  # only the .f.cys26 gone
        self.assertTrue(os.path.exists(other))                # nothing else touched
        self.assertEqual(fold.read_record(rec["id"])["state"], "destroyed")

    def test_recovery_key(self):
        d = self._make_folder()
        rec = fold.lock_folder(d, "pw")
        key = fold.recovery_key(rec, "pw")
        self.assertEqual(len(key), 32)
        # It matches the key the engine would derive.
        _, real = fold.derive("pw", bytes.fromhex(rec["salt"]), rec["rounds"])
        self.assertEqual(key, real.hex().upper())

    def test_selfdestruct_differs_from_password(self):
        d = self._make_folder()
        rec = fold.lock_folder(d, "pw", selfdestruct="boom")
        # Right password still unlocks even with a self-destruct code set.
        fold.unlock_folder(rec, "pw")
        self.assertTrue(os.path.exists(d))

    # ---- record ordering / recovery ----
    def test_record_written_before_original_deleted(self):
        # If the record write fails, the original must NOT have been deleted,
        # so a .f.cys26 whose salt was never saved can never be stranded.
        d = self._make_folder()
        orig = fold.write_record

        def boom(rec):
            raise RuntimeError("disk full")
        fold.write_record = boom
        try:
            with self.assertRaises(RuntimeError):
                fold.lock_folder(d, "pw")
        finally:
            fold.write_record = orig
        self.assertTrue(os.path.exists(d))          # original still intact

    def test_scan_promotes_leftover_tmp(self):
        # Simulate a lock stranded by the pre-fix version: the .f.cys26 exists
        # but the record only survived as a .rec-*.tmp.
        d = self._make_folder()
        rec = fold.lock_folder(d, "pw")
        # Move the real record aside into a temp, as an interrupted write would.
        rec_json = fold._record_path(rec["id"])
        with open(rec_json) as fh:
            content = fh.read()
        os.remove(rec_json)
        with open(os.path.join(self.state, ".rec-abc.tmp"), "w") as fh:
            fh.write(content)
        self.assertEqual(fold.list_records(), [])   # nothing visible yet
        healed = fold.scan_recovery()
        self.assertIn(rec["id"], healed["promoted"])
        # Now it is a normal record again and unlocks.
        rec2 = fold.read_record(rec["id"])
        fold.unlock_folder(rec2, "pw")
        self.assertTrue(os.path.exists(d))

    def test_scan_removes_useless_tmp(self):
        with open(os.path.join(self.state, ".rec-junk.tmp"), "w") as fh:
            fh.write("not json")
        healed = fold.scan_recovery()
        self.assertEqual(healed["removed_tmp"], 1)
        self.assertFalse(os.path.exists(os.path.join(self.state, ".rec-junk.tmp")))

    def test_scan_flags_half_finished(self):
        d = self._make_folder()
        rec = fold.lock_folder(d, "pw")
        os.makedirs(rec["path"])                     # original reappears next to .f.cys26
        healed = fold.scan_recovery()
        ids = [r["id"] for r in healed["half_finished"]]
        self.assertIn(rec["id"], ids)


if __name__ == "__main__":
    unittest.main()
