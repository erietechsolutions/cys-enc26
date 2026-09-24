"""Round-trip tests for the CYS-ENC26 engine. Run with:

    python3 -m unittest discover -s tests
"""

import base64
import json
import os
import random
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import cys_enc26 as c  # noqa: E402

ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcxyz0123456789 -|+=_!@#$%^&*()?.,:"
            "/'\n\t~é")
OPTION_SETS = [
    c.Options(use_phase9=p9, block_bits=bits, use_phase10=p10, compact=compact)
    for p9 in (True, False)
    for bits in ((c.DEFAULT_BLOCK_BITS,) if not p9 else c.BLOCK_BITS_OPTIONS)
    for p10 in (False, True)
    for compact in ((False, True) if p10 else (False,))
]


def expected_text(msg):
    return msg.upper()


class SmallChunks:
    """Use tiny file parts so multi-part files stay fast to test."""

    def __init__(self, size):
        self.size = size

    def __enter__(self):
        self.old, c.CHUNK_BYTES = c.CHUNK_BYTES, self.size

    def __exit__(self, *exc):
        c.CHUNK_BYTES = self.old


class MessageTests(unittest.TestCase):
    def test_round_trip_every_option(self):
        rng = random.Random(1)
        for opts in OPTION_SETS:
            for _ in range(15):
                key = c.generate_key()
                msg = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 120)))
                ph = c.encrypt(key, msg, opts)
                if not opts.compact:
                    _, res = c.decrypt(ph["final"].output, key)
                    self.assertEqual(res, {"kind": "text", "text": expected_text(msg)})
                _, res = c.decrypt_bytes(key, c.message_locked_bytes(ph, opts))
                self.assertEqual(res["text"], expected_text(msg))

    def test_phases_match_in_both_directions(self):
        key = c.generate_key()
        for opts in OPTION_SETS:
            enc = c.encrypt(key, "Phase check: A-B|C+D=E_F?", opts)
            dec, _ = c.decrypt_bytes(key, c.message_locked_bytes(enc, opts))
            for k in c.PHASE_KEYS[1:9]:
                self.assertEqual(enc[k].output, dec[k].output, f"phase {k}")

    def test_phase10_looks_like_binary(self):
        key = c.generate_key()
        out = c.encrypt(key, "HI", c.Options(use_phase10=True))["final"].output
        for line in out.splitlines():
            groups = line.split(" ")
            self.assertLessEqual(len(groups), 8)
            for g in groups:
                self.assertRegex(g, r"^[01]{8}$")
        self.assertEqual(c.phase10_encode(b"CYS"), "01000011 01011001 01010011")

    def test_block_size_sets_padding(self):
        key = c.generate_key()
        for bits in c.BLOCK_BITS_OPTIONS:
            blob = c.encrypt(key, "HELLO", c.Options(block_bits=bits))["final"].data
            body = len(blob) - 16
            self.assertEqual(body % (bits // 8), 0)
            self.assertGreaterEqual(body, bits // 8)

    def test_wrong_key(self):
        key = c.generate_key()
        for opts in OPTION_SETS:
            locked = c.message_locked_bytes(c.encrypt(key, "SECRET", opts), opts)
            with self.assertRaises(c.CipherError) as cm:
                c.decrypt_bytes(c.generate_key(), locked)
            self.assertEqual(str(cm.exception), c._WRONG_KEY)

    def test_garbage_is_rejected(self):
        key = c.generate_key()
        for text in ("", "hello there", "0101", "QUJD", "01000001"):
            with self.assertRaises(c.CipherError):
                c.decrypt(text, key)

    def test_reserved_characters_rejected(self):
        with self.assertRaises(c.CipherError):
            c.encrypt(c.generate_key(), "bad  char")

    def test_bad_block_size(self):
        with self.assertRaises(ValueError):
            c.Options(block_bits=512)


class FileTests(unittest.TestCase):
    def test_round_trip_multi_part(self):
        rng = random.Random(2)
        with SmallChunks(3000):
            for opts in OPTION_SETS:
                key = c.generate_key()
                size = rng.choice([0, 1, 2999, 3000, 3001, 9000, 10001])
                data = rng.randbytes(size)
                ph, locked = c.encrypt_bytes(key, "demo file.bin", data, opts)
                if opts.text_parts:
                    self.assertTrue(set(locked) <= set(b"01 \n"))
                dec, res = c.decrypt_bytes(key, locked)
                self.assertEqual(res["kind"], "file")
                self.assertEqual(res["name"], "demo file.bin")
                self.assertEqual(res["data"], data)
                for k in c.PHASE_KEYS[1:9]:
                    self.assertEqual(ph[k].output, dec[k].output)

    def test_parts_out_of_order_or_missing(self):
        key = c.generate_key()
        with SmallChunks(1000):
            _, locked = c.encrypt_bytes(key, "f", os.urandom(3500))
        frames, pos = [], 0
        while pos < len(locked):
            n = int.from_bytes(locked[pos:pos + 4], "big")
            frames.append(locked[pos:pos + 4 + n])
            pos += 4 + n
        self.assertEqual(len(frames), 4)
        for bad in (frames[:3], [frames[0], frames[2], frames[1], frames[3]],
                    [frames[1], frames[0], frames[2], frames[3]]):
            with self.assertRaises(c.CipherError):
                c.decrypt_bytes(key, b"".join(bad))

    def test_file_paths_and_process_pool(self):
        key = c.generate_key()
        data = os.urandom(3 * c.CHUNK_BYTES // 2)
        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "orig.dat")
            locked = os.path.join(tmp, "orig.dat" + c.LOCKED_EXT)
            back = os.path.join(tmp, "back.dat")
            with open(src, "wb") as fh:
                fh.write(data)
            ph, parts = c.encrypt_file(key, src, locked, c.Options(),
                                       progress=lambda d, t: seen.append((d, t)),
                                       workers=2)
            self.assertEqual(parts, 2)
            self.assertEqual(seen[-1], (2, 2))
            self.assertIn("Locked file ready", ph["final"].output)
            _, res = c.decrypt_file(key, locked, back, workers=2)
            self.assertEqual(res["name"], "orig.dat")
            with open(back, "rb") as fh:
                self.assertEqual(fh.read(), data)
            # a wrong key leaves nothing behind
            with self.assertRaises(c.CipherError):
                c.decrypt_file(c.generate_key(), locked, back + "2")
            self.assertFalse(os.path.exists(back + "2"))

    def test_cancel_removes_partial_file(self):
        key = c.generate_key()
        stop = threading.Event()
        with tempfile.TemporaryDirectory() as tmp, SmallChunks(2000):
            src = os.path.join(tmp, "orig.dat")
            dst = src + c.LOCKED_EXT
            with open(src, "wb") as fh:
                fh.write(os.urandom(20000))
            with self.assertRaises(c.Cancelled):
                c.encrypt_file(key, src, dst, c.Options(), workers=1,
                               progress=lambda d, t: d == 2 and stop.set(),
                               cancel=stop)
            self.assertFalse(os.path.exists(dst))


class Version1Tests(unittest.TestCase):
    """Ciphertexts made by CYS-ENC26 1.0.0.0 must still decrypt."""

    def test_v1_fixtures(self):
        with open(os.path.join(HERE, "fixtures", "v1-ciphertexts.json")) as fh:
            fx = json.load(fh)
        key = bytes.fromhex(fx["key"])
        file_data = base64.b64decode(fx["file_data_b64"])
        for case in fx["cases"]:
            ph, res = c.decrypt(case["ciphertext"], key)
            if case["kind"] == "text":
                self.assertEqual(res["text"], expected_text(fx["message"]))
            else:
                self.assertEqual((res["name"], res["data"]), (fx["file_name"], file_data))
            self.assertEqual(ph["9"].status, "done" if case["phase9"] else "skipped")
            self.assertEqual(ph["8.5"].status, "skipped")
            # and as a locked file opened from disk
            _, res2 = c.decrypt_bytes(key, (case["ciphertext"] + "\n").encode())
            self.assertEqual(res2["kind"], case["kind"])


class LimitTests(unittest.TestCase):
    def test_limits_and_estimates(self):
        self.assertEqual(c.file_limit(c.Options()), 800 * c.MB)
        self.assertEqual(c.file_limit(c.Options(use_phase10=True)), 90 * c.MB)
        self.assertEqual(c.file_limit(c.Options(use_phase10=True, compact=True)), 800 * c.MB)
        est = c.estimate_locked_size(800 * c.MB, c.Options())
        self.assertLess(est, 1.55 * 1024 * c.MB)

    def test_real_growth_is_under_estimate(self):
        key = c.generate_key()
        data = os.urandom(200_000)
        for opts in (c.Options(), c.Options(use_phase10=True),
                     c.Options(block_bits=1048576)):
            _, locked = c.encrypt_bytes(key, "r.bin", data, opts)
            self.assertLessEqual(len(locked), c.estimate_locked_size(len(data), opts))


if __name__ == "__main__":
    unittest.main()
