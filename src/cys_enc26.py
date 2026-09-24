#!/usr/bin/env python3
"""
CYS-ENC26 phase explorer.

Encrypts and decrypts text or files with the CYS-ENC26 phases and shows the
output of every phase in both directions. Every phase is reversible, whichever
optional phases are used. It is a learning tool, not a way to protect real data.
"""

import argparse
import base64
import hashlib
import hmac
import io
import lzma
import multiprocessing
import os
import re
import secrets
import shutil
import sys
import threading
from array import array
from collections import deque
from concurrent.futures import ProcessPoolExecutor

APP_NAME = "CYS-ENC26"
WATERMARK = "CYSEN26:"
FILE_TAG = "FILE|"            # version 1 files: FILE| + base32(name NUL data)
PART_TAG = "FILEPART|"        # version 2 files: FILEPART|part|parts| + base32(data)
LOCKED_EXT = ".locked.rl.cys"
MB = 1024 * 1024

BLOCK_BITS_OPTIONS = (64, 1024, 2048, 8192, 16384, 131072, 524288, 1048576)
DEFAULT_BLOCK_BITS = 1024
LARGE_BLOCK_BITS = 524288     # this size and up shows a warning

CHUNK_BYTES = 512 * 1024      # files are encrypted in parts of this size
MAX_FILE_BYTES = 800 * MB     # keeps locked files under about 1.5 GB
MAX_FILE_BYTES_P10 = 90 * MB  # Phase 10 without compact save is 9x bigger again
LARGE_LOCKED_BYTES = 1536 * MB
GROWTH = 1.9                  # worst case locked size / original (random data)
GROWTH_P10 = 17.1             # the same with Phase 10 saved as binary text
ENCRYPT_SECONDS_PER_MB = 12.5  # measured on one core, per MB of original
DECRYPT_SECONDS_PER_MB = 3.5   # per MB of locked file
MAX_PART_TEXT = 512 * MB      # guard: Phase 8.5 never expands a part beyond this
MAX_VIEW_CHARS = 200_000      # longer outputs are shortened on screen only
DIGITS = "0123456789"


def _read_version():
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "..", "VERSION"), os.path.join(here, "VERSION")):
        try:
            with open(path, encoding="utf-8") as fh:
                value = fh.read().strip()
            if value:
                return value
        except OSError:
            pass
    return "2.0.0.0"


VERSION = _read_version()

# --------------------------------------------------------------------------
# Tables from the spec
# --------------------------------------------------------------------------
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

PHASE1 = dict(zip(LETTERS, "0123456789ABCDEFGHIJKLMNOP"))
PHASE1.update(zip("123456789", "QRSTUVWXY"))
PHASE1["0"] = "Z"

# Phase 1 symbols become 4-bit binary codes, converted to numbers in Phase 8
PHASE1_SYMBOLS = {"-": "1001", "|": "1011", "+": "1010", "=": "1100", "_": "1111"}
PHASE8_4BIT_OFFSET = 64   # keeps 4-bit codes (64-79) apart from 6-bit codes (0-63)

PHASE2 = {c: 2 ** i for i, c in enumerate("ABCDEFGHIJKLMNO")}
PHASE2.update(zip("PQRSTUVWXYZ", (3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15)))
PHASE2.update({str(d): 16 + d for d in range(1, 10)})
PHASE2["0"] = 26

PHASE3_WIDTH = 5
PHASE3_SWAP = {"0": "A", "4": "D", "8": "E", "9": "X"}

# After Phase 3 only the digits 1, 2, 3, 5, 6 and 7 are left.
PHASE4 = {"1": "3", "2": "4", "3": "9", "5": "15", "6": "8", "7": "21"}
PHASE5 = {"3": "2", "4": "4", "9": "6", "15": "10", "8": "8", "21": "14"}

PHASE6_LETTERS = {
    "1": "BC", "2": "FG", "3": "HI", "4": "JK", "5": "LM",
    "6": "NO", "7": "PQ", "8": "RS", "9": "TU", "0": "VWYZ",
}
PHASE6_SYMBOLS = {
    " ": "000000", "!": "100000", "@": "000010", "#": "000110",
    "$": "110000", "%": "111000", "^": "011110", "&": "111110",
    "*": "110110", "(": "100110", ")": "100010", "?": "111100",
    ".": "001111", ",": "100001", ":": "001010",
}
PHASE7_I = "111111"

# Phase 8.5: raw LZMA2 (no header), so the output has nothing readable in it
PHASE85_FILTERS = [{"id": lzma.FILTER_LZMA2, "preset": 6}]

# Binary codes travel through the phases as single private-use characters so
# no phase can mistake their 0s and 1s for ordinary digits. They're shown as
# binary on screen.
_B4 = {sym: chr(0xE000 + i) for i, sym in enumerate(PHASE1_SYMBOLS)}
_B6 = {sym: chr(0xE010 + i) for i, sym in enumerate(PHASE6_SYMBOLS)}
_IMARK = chr(0xE03F)
_RESERVED = set(_B4.values()) | set(_B6.values()) | {_IMARK}

DISPLAY = str.maketrans({**{_B4[s]: code for s, code in PHASE1_SYMBOLS.items()},
                         **{_B6[s]: code for s, code in PHASE6_SYMBOLS.items()},
                         _IMARK: PHASE7_I})

P1_TABLE = str.maketrans({**PHASE1, **_B4})
P3_MAP = {c: "".join(PHASE3_SWAP.get(d, d) for d in f"{n * 2:0{PHASE3_WIDTH}d}")
          for c, n in PHASE2.items()}
P3_TABLE = str.maketrans(P3_MAP)
P4_TABLE = str.maketrans(PHASE4)
P5_TABLE = str.maketrans({d: PHASE5[v] for d, v in PHASE4.items()})
P6_SYM = {s: _B6[s] for s in PHASE6_SYMBOLS}
P7_TABLE = str.maketrans({**{L: chr((ord(L) - 64) % 26 + 65) for L in LETTERS if L != "I"},
                          "I": _IMARK})
P8_MAP = {**{_B4[s]: f"{int(c, 2) + PHASE8_4BIT_OFFSET:02d}" for s, c in PHASE1_SYMBOLS.items()},
          **{_B6[s]: f"{int(c, 2):02d}" for s, c in PHASE6_SYMBOLS.items()},
          _IMARK: f"{int(PHASE7_I, 2):02d}"}
P8_TABLE = str.maketrans(P8_MAP)
P10_BITS = [format(b, "08b") for b in range(256)]

# Reverse tables
R_P8 = {v: k for k, v in P8_MAP.items()}
R_P7_TABLE = str.maketrans({**{L: chr((ord(L) - 66) % 26 + 65) for L in LETTERS if L != "J"},
                            _IMARK: "I"})
R_P6_TABLE = str.maketrans({**{L: d for d, ls in PHASE6_LETTERS.items() for L in ls},
                            **{v: k for k, v in _B6.items()}})
R_P5_TO4 = {v: k for k, v in PHASE5.items()}
R_P5_TO3 = {PHASE5[v]: d for d, v in PHASE4.items()}
R_P3 = {v: k for k, v in P3_MAP.items()}
R_P1_TABLE = str.maketrans({**{v: k for k, v in PHASE1.items()},
                            **{v: k for k, v in _B4.items()}})
_DROP_BITS = str.maketrans("", "", "01")

_RE_PAIR = re.compile(r"[0-9]{2}")
_RE_P5 = re.compile(r"1[04]|[2468]")
_RE_P3 = re.compile(r"[0-9ADEX]{%d}" % PHASE3_WIDTH)

# (key, title, description) for every step shown in the app
PHASES = [
    ("0", "Key and watermark",
     "A random 128-bit key is generated (or the key you entered is used), "
     "and CYSEN26: is placed at the start of the input."),
    ("1", "Basic crypto scramble",
     "Letters and digits are swapped: A→0 … J→9, K→A … Z→P, 1→Q … 9→Y, 0→Z. "
     "The symbols - | + = _ become 4-bit binary codes."),
    ("2", "Numbered encryption cycle",
     "The first and last 8 bits of the key go in at positions chosen by the "
     "key, then each character becomes its number (A=1, B=2, C=4 … 0=26), "
     "joined by dashes."),
    ("3", "Final scramble",
     "Dashes are removed, each number is doubled and written as 5 digits, "
     "then 0→A, 4→D, 8→E and 9→X."),
    ("4", "Number shift",
     "Even digits go up 2. Odd digits are multiplied by 3."),
    ("5", "Odd number division",
     "Each odd number from Phase 4 is divided by 1.5 and rounded up."),
    ("6", "Numbers to letters",
     "Each digit becomes a random letter from its own set. A, D, E and X stay. "
     "Symbols become 6-bit binary codes."),
    ("7", "Letter shift",
     "Every letter moves forward one (Z→A). I becomes 111111."),
    ("8", "Binary to number",
     "Every binary code becomes a 2-digit number. 6-bit codes use 00-63; "
     "Phase 1's 4-bit codes add 64 (- = 1001 = 9 + 64 = 73)."),
    ("8.5", "Compression",
     "The Phase 8 output is compressed with LZMA2 (no header), which undoes "
     "most of the growth from the earlier phases."),
    ("9", "Finalized encoding",
     "Optional. A keyed shuffle and XOR, padded to the chosen block size, with "
     "the nonce stored inside. Nothing in the output is readable."),
    ("10", "Binary",
     "Optional. Every byte is written as 8 bits, 8 groups to a line. Compact "
     "save packs the bits back into bytes for the saved file."),
    ("final", "Final output",
     "The finished ciphertext when encrypting, or the recovered message or "
     "file when decrypting."),
]
PHASE_KEYS = [k for k, _, _ in PHASES]


class Phase:
    """The output of one phase plus notes about what happened in it."""

    def __init__(self, output="", notes=None, status="done", data=None):
        self.output = output
        self.notes = notes or []
        self.status = status  # "done" or "skipped"
        self.data = data      # bytes behind the output, when there are any
        self.full_length = None   # set when output was shortened


class Options:
    """What the encrypt side was asked to do."""

    def __init__(self, use_phase9=True, block_bits=DEFAULT_BLOCK_BITS,
                 use_phase10=False, compact=False):
        if block_bits not in BLOCK_BITS_OPTIONS:
            raise ValueError(f"The Phase 9 block size must be one of "
                             f"{', '.join(map(str, BLOCK_BITS_OPTIONS))} bits.")
        self.use_phase9 = use_phase9
        self.block_bits = block_bits
        self.use_phase10 = use_phase10
        self.compact = compact and use_phase10

    @property
    def text_parts(self):
        """Files are saved as binary text only with Phase 10 and no compact save."""
        return self.use_phase10 and not self.compact


class CipherError(ValueError):
    pass


class Cancelled(Exception):
    pass


_BAD = ("This isn't valid CYS-ENC26 ciphertext, or it was changed after "
        "encryption.")
_WRONG_KEY = "Decryption failed. The key is wrong or the ciphertext was changed."


def _show(s):
    return s.translate(DISPLAY)


def _hex_preview(data, n=48):
    h = data[:n].hex(" ").upper()
    return h + (" …" if len(data) > n else "")


def _pct(new, old):
    return f"{new / old * 100:.0f}%" if old else "–"


def file_limit(opts):
    """The largest original file the encrypt side takes without the bypass."""
    return MAX_FILE_BYTES_P10 if opts.text_parts else MAX_FILE_BYTES


def estimate_locked_size(size, opts):
    """Worst-case size of the locked file for an original of `size` bytes."""
    parts = max(1, -(-size // CHUNK_BYTES))
    pad = parts * (opts.block_bits // 8 + 24 if opts.use_phase9 else 4)
    base = size * GROWTH + pad
    return int(base * 9 if opts.text_parts else base) + 4096


def estimate_seconds(size, decrypting=False):
    """Rough time for encrypting an original (or decrypting a locked file)."""
    per_mb = DECRYPT_SECONDS_PER_MB if decrypting else ENCRYPT_SECONDS_PER_MB
    return size / MB * per_mb / default_workers(max(1, -(-size // CHUNK_BYTES)))


def describe_seconds(seconds):
    if seconds < 90:
        return "about a minute" if seconds > 40 else "less than a minute"
    if seconds < 90 * 60:
        return f"about {seconds / 60:.0f} minutes"
    return f"about {seconds / 3600:.1f} hours"


def default_workers(parts):
    return max(1, min(os.cpu_count() or 1, 8, parts))


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------
def generate_key():
    return secrets.token_bytes(16)


def parse_key(text):
    s = "".join(text.split())
    if s[:2].lower() == "0x":
        s = s[2:]
    if len(s) != 32:
        raise ValueError(
            f"The key must be 32 hex characters (128 bits). This one has {len(s)}.")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError("The key can only contain 0-9 and A-F.") from None


# --------------------------------------------------------------------------
# Keyed generator (Phase 2 positions and Phase 9)
# --------------------------------------------------------------------------
class KeyedStream:
    """Deterministic byte stream from HMAC-SHA256(key, label | nonce | counter)."""

    def __init__(self, key, nonce, label):
        self.key, self.nonce, self.label = key, nonce, label
        self.counter = 0
        self.buf = b""

    def _block(self):
        msg = self.label + self.nonce + self.counter.to_bytes(8, "big")
        self.counter += 1
        return hmac.new(self.key, msg, hashlib.sha256).digest()

    def read(self, n):
        chunks, have = [self.buf], len(self.buf)
        while have < n:
            block = self._block()
            chunks.append(block)
            have += len(block)
        data = b"".join(chunks)
        self.buf = data[n:]
        return data[:n]

    def randbelow(self, n):
        limit = (1 << 32) - ((1 << 32) % n)   # rejection sampling, no bias
        while True:
            x = int.from_bytes(self.read(4), "big")
            if x < limit:
                return x % n

    def words(self, n):
        a = array("I", self.read(4 * n))
        if sys.byteorder == "big":
            a.byteswap()
        return a


def _permutation(length, stream):
    perm = array("I", range(length))
    words, k = stream.words(length), 0
    for i in range(length - 1, 0, -1):          # Fisher-Yates
        n = i + 1
        limit = 4294967296 - (4294967296 % n)
        while True:
            if k >= len(words):
                words, k = stream.words(1024), 0
            x = words[k]
            k += 1
            if x < limit:
                break
        j = x % n
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def _xor(data, stream):
    ks = stream.read(len(data))
    return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(
        len(data), "big")


# --------------------------------------------------------------------------
# Phases 8.5, 9 and 10
# --------------------------------------------------------------------------
def phase85_compress(s8):
    raw = s8.encode("utf-8")
    packed = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=PHASE85_FILTERS)
    details = (f"Phase 8 output: {len(raw):,} bytes\n"
               f"Compressed: {len(packed):,} bytes ({_pct(len(packed), len(raw))} "
               f"of Phase 8)\n\nCompressed bytes:\n{_hex_preview(packed)}")
    return packed, details


def _is_phase85(payload):
    # Raw LZMA2 always starts with a control byte of 1, 2 or 128+. Uncompressed
    # Phase 8 output (version 1) always starts with a capital letter.
    return bool(payload) and (payload[0] in (1, 2) or payload[0] >= 0x80)


def phase85_decompress(packed):
    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=PHASE85_FILTERS)
    try:
        raw = d.decompress(packed, max_length=MAX_PART_TEXT)
    except lzma.LZMAError:
        raise CipherError(_BAD) from None
    if not d.eof or d.unused_data:
        raise CipherError(_BAD)
    try:
        s8 = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CipherError(_BAD) from None
    details = (f"Compressed: {len(packed):,} bytes\n"
               f"Decompressed Phase 8 output: {len(raw):,} bytes")
    return s8, details


def phase9_encrypt(data, key, block_bits=DEFAULT_BLOCK_BITS):
    """Shuffle and XOR `data` (bytes). Returns (nonce + ciphertext, details)."""
    block = block_bits // 8
    payload = len(data).to_bytes(4, "big") + data
    payload += secrets.token_bytes((-len(payload)) % block)
    nonce = secrets.token_bytes(16)

    perm = _permutation(len(payload), KeyedStream(key, nonce, b"CYS-ENC26 shuffle"))
    shuffled = bytes(payload[p] for p in perm)
    cipher = _xor(shuffled, KeyedStream(key, nonce, b"CYS-ENC26 xor"))

    details = (
        f"Phase 8.5 output: {len(data):,} bytes (+4 byte length prefix)\n"
        f"Block size: {block_bits:,} bits ({block:,} bytes)\n"
        f"Padded to: {len(payload):,} bytes = {len(payload) // block:,} block(s)\n"
        f"Nonce: {nonce.hex().upper()} (stored inside the output)\n"
        f"Generator: HMAC-SHA256(key, label + nonce + counter)\n\n"
        f"Before shuffle and XOR:\n{_hex_preview(payload)}\n\n"
        f"After shuffle:\n{_hex_preview(shuffled)}\n\n"
        f"After XOR:\n{_hex_preview(cipher)}"
    )
    return nonce + cipher, details


def _p9_shape(blob):
    # Every block size is a multiple of 64 bits, so the body is a multiple of 8.
    body = len(blob) - 16
    return body >= 8 and body % 8 == 0


def phase9_decrypt(blob, key):
    """Undo Phase 9. Returns (payload bytes, details)."""
    if not _p9_shape(blob):
        raise CipherError("This isn't Phase 9 output.")
    nonce, cipher = blob[:16], blob[16:]

    shuffled = _xor(cipher, KeyedStream(key, nonce, b"CYS-ENC26 xor"))
    perm = _permutation(len(shuffled), KeyedStream(key, nonce, b"CYS-ENC26 shuffle"))
    payload = bytearray(len(shuffled))
    for i, p in enumerate(perm):
        payload[p] = shuffled[i]

    length = int.from_bytes(payload[:4], "big")
    if length > len(payload) - 4:
        raise CipherError(_WRONG_KEY)
    details = (
        f"Nonce: {nonce.hex().upper()}\n"
        f"Ciphertext: {len(cipher):,} bytes\n"
        f"Recovered data: {length:,} bytes, padding removed\n\n"
        f"After undoing XOR:\n{_hex_preview(shuffled)}\n\n"
        f"After unshuffling:\n{_hex_preview(bytes(payload))}"
    )
    return bytes(payload[4:4 + length]), details


def phase10_encode(data):
    """Every byte as 8 bits, a space between groups, 8 groups per line."""
    groups = [P10_BITS[b] for b in data]
    return "\n".join(" ".join(groups[i:i + 8]) for i in range(0, len(groups), 8))


def _p10_shape(text):
    return bool(text.strip()) and not text.translate(_DROP_BITS).strip()


def phase10_decode(text):
    bits = "".join(text.split())
    if not bits or len(bits) % 8 or bits.translate(_DROP_BITS):
        raise CipherError(_BAD)
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


# --------------------------------------------------------------------------
# Encryption
# --------------------------------------------------------------------------
def _key_positions(key, total, part=None):
    """Four injection positions, generated from the key, the length and (in
    version 2) the part number."""
    nonce = total.to_bytes(8, "big")
    if part is not None:
        nonce += part.to_bytes(8, "big")
    stream = KeyedStream(key, nonce, b"CYS-ENC26 inject")
    picked = []
    while len(picked) < 4:
        p = stream.randbelow(total)
        if p not in picked:
            picked.append(p)
    return sorted(picked)


def _key_chars(key):
    return f"{key[0]:02X}{key[-1]:02X}"


def _encrypt_phases(key, plain, part, source_note=None):
    """Phases 0 to 8. Returns ({phase: Phase}, Phase 8 output)."""
    ph = {}
    if any(c in _RESERVED for c in plain):
        raise CipherError("The message contains characters CYS-ENC26 uses "
                          "internally (private-use range U+E000 to U+E03F).")
    data = WATERMARK + plain
    notes = ["Keep the key private. It's needed to decrypt."]
    if source_note:
        notes.append(source_note)
    ph["0"] = Phase(f"Secret key (hex):\n{key.hex().upper()}\n\n"
                    f"Input with watermark:\n{data}", notes)

    # Phase 1
    upper = data.upper()
    s1 = upper.translate(P1_TABLE)
    notes = []
    if upper != data:
        notes.append("Lowercase letters were changed to uppercase, so the "
                     "decrypted message will be in capitals.")
    unmapped = sorted({c for c in upper if c not in PHASE1 and c not in PHASE1_SYMBOLS})
    if unmapped:
        shown = " ".join(repr(c) for c in unmapped[:24])
        notes.append(f"Passing through Phase 1 unchanged: {shown}")
    ph["1"] = Phase(_show(s1), notes)

    # Phase 2
    inject = _key_chars(key)
    positions = _key_positions(key, len(s1) + len(inject), part)
    chars = list(s1)
    for p, ch in zip(positions, inject):
        chars.insert(p, ch)
    merged = "".join(chars)
    where = ", ".join(str(p + 1) for p in positions)
    ph["2"] = Phase(
        "-".join(str(PHASE2[c]) if c in PHASE2 else _show(c) for c in merged),
        [f"Key bits injected: first byte {inject[:2]}, last byte {inject[2:]}, "
         f"as the characters {' '.join(inject)} at positions {where}."])

    # Phases 3 to 5
    s3 = merged.translate(P3_TABLE)
    ph["3"] = Phase(_show(s3))
    ph["4"] = Phase(_show(s3.translate(P4_TABLE)))
    s5 = s3.translate(P5_TABLE)
    ph["5"] = Phase(_show(s5), ["Applied to each number produced in Phase 4."])

    # Phase 6 (random letter per digit; sets of 2 or 4 divide 256 evenly)
    rand = secrets.token_bytes(len(s5))
    out = []
    add = out.append
    for ch, r in zip(s5, rand):
        opts = PHASE6_LETTERS.get(ch)
        add(opts[r % len(opts)] if opts else P6_SYM.get(ch, ch))
    s6 = "".join(out)
    ph["6"] = Phase(_show(s6), ["Letters are picked at random, so the same "
                                "message encrypts differently every time."])

    # Phases 7 and 8
    s7 = s6.translate(P7_TABLE)
    ph["7"] = Phase(_show(s7))
    s8 = s7.translate(P8_TABLE)
    ph["8"] = Phase(s8)
    return ph, s8


def encrypt_unit(key, plain, opts, part=0, source_note=None, render10=True):
    """Run one message or one file part through every phase.
    Returns ({phase: Phase}, the bytes Phase 10 or base64 turn into text)."""
    ph, s8 = _encrypt_phases(key, plain, part, source_note)

    packed, details = phase85_compress(s8)
    ph["8.5"] = Phase(details, data=packed)

    if opts.use_phase9:
        blob, details = phase9_encrypt(packed, key, opts.block_bits)
        notes = []
        if opts.block_bits >= LARGE_BLOCK_BITS:
            notes.append(f"Large block size: at least {opts.block_bits // 8:,} "
                         "bytes of output for any message.")
        ph["9"] = Phase(details + "\n\nOutput (base64):\n"
                        + base64.b64encode(blob[:MAX_VIEW_CHARS]).decode(), notes, data=blob)
    else:
        blob = packed
        ph["9"] = Phase("Phase 9 was not selected.",
                        ["The Phase 8.5 output goes on without a shuffle."],
                        status="skipped")

    if opts.use_phase10:
        notes = [f"{len(blob):,} bytes written as {len(blob) * 8:,} bits."]
        if not render10:    # compact file parts that aren't shown on screen
            ph["10"] = Phase("", notes)
            return ph, blob
        if opts.compact:
            notes.append("Compact save is on: a saved locked file stores these "
                         "bits packed back into bytes.")
        ph["10"] = Phase(phase10_encode(blob), notes)
    else:
        ph["10"] = Phase("Phase 10 was not selected.",
                         ["The final output is written as base64 text."], status="skipped")
    return ph, blob


def encrypt(key, text, opts=None):
    """Encrypt a typed message. The ciphertext text is in result["final"]."""
    opts = opts or Options()
    ph, blob = encrypt_unit(key, text or "", opts)
    final = ph["10"].output if opts.use_phase10 else base64.b64encode(blob).decode()
    ph["final"] = Phase(final, data=blob)
    return ph


def message_locked_bytes(ph, opts):
    """What Save locked file writes for a typed message."""
    if opts.compact:
        blob = ph["final"].data
        return len(blob).to_bytes(4, "big") + blob
    return (ph["final"].output + "\n").encode("utf-8")


def _trim(ph):
    """Shorten long outputs (only the first part of a file is shown)."""
    for p in ph.values():
        p.data = None
        if len(p.output) > MAX_VIEW_CHARS:
            p.full_length = len(p.output)
            p.output = p.output[:MAX_VIEW_CHARS]
    return ph


def _encrypt_part(key, part, parts, name, chunk, opts, keep_phases):
    """Worker: encrypt one file part. Returns (phases or None, bytes to write)."""
    payload = (name.encode("utf-8") + b"\0" if part == 0 else b"") + chunk
    plain = f"{PART_TAG}{part}|{parts}|" + base64.b32encode(payload).decode()
    note = None
    if part == 0:
        note = (f"File '{name}' is encrypted in {parts:,} part(s) of up to "
                f"{CHUNK_BYTES // 1024:,} KB. This is part 1. Each part is turned "
                "into base32 text so every byte comes back exactly.")
    ph, blob = encrypt_unit(key, plain, opts, part, note,
                            render10=keep_phases or opts.text_parts)
    if opts.text_parts:
        out = ph["10"].output.encode("ascii") + (b"\n\n" if part < parts - 1 else b"\n")
    else:
        out = len(blob).to_bytes(4, "big") + blob
    return (_trim(ph) if keep_phases else None), out


def _run_ordered(func, jobs, workers, cancel=None):
    """Yield func(*job) for every job, in order, on `workers` processes."""
    def check():
        if cancel is not None and cancel.is_set():
            raise Cancelled()

    if workers <= 1:
        for job in jobs:
            check()
            yield func(*job)
        return
    ctx = multiprocessing.get_context("spawn")
    ex = ProcessPoolExecutor(max_workers=workers, mp_context=ctx)
    pending = deque()
    try:
        for job in jobs:
            check()
            pending.append(ex.submit(func, *job))
            while len(pending) >= workers * 2:
                yield pending.popleft().result()
                check()
        while pending:
            yield pending.popleft().result()
            check()
    finally:
        ex.shutdown(wait=True, cancel_futures=True)


def encrypt_stream(key, src, size, name, dst, opts, progress=None, cancel=None,
                   workers=None):
    """Encrypt a file read from `src` (binary, `size` bytes) into `dst`.
    Returns (phases of part 1, number of parts)."""
    parts = max(1, -(-size // CHUNK_BYTES))
    workers = default_workers(parts) if workers is None else max(1, min(workers, parts))

    def jobs():
        for part in range(parts):
            chunk = src.read(CHUNK_BYTES)
            yield (key, part, parts, name, chunk, opts, part == 0)

    first = None
    for done, (ph, out) in enumerate(_run_ordered(_encrypt_part, jobs(), workers, cancel), 1):
        if ph is not None:
            first = ph
        dst.write(out)
        if progress:
            progress(done, parts)
    return first, parts


def encrypt_file(key, src_path, dst_path, opts, progress=None, cancel=None, workers=None):
    """Encrypt the file at src_path into a locked file at dst_path.
    The partial file is deleted if anything goes wrong."""
    size = os.path.getsize(src_path)
    try:
        with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
            ph, parts = encrypt_stream(key, src, size, os.path.basename(src_path), dst,
                                       opts, progress, cancel, workers)
    except BaseException:
        _remove(dst_path)
        raise
    ph["final"] = Phase(_locked_summary(dst_path, parts, opts))
    return ph, parts


def _locked_summary(path, parts, opts):
    size = os.path.getsize(path)
    how = ("Phase 10 binary text, parts separated by a blank line"
           if opts.text_parts else "bytes (each part has a 4-byte length in front)")
    body = (f"Locked file ready: {size:,} bytes in {parts:,} part(s), stored as {how}.\n"
            "Use Save locked file… to write it.\n\n")
    with open(path, "rb") as fh:
        head = fh.read(MAX_VIEW_CHARS // 2)
    if opts.text_parts:
        body += "Start of the locked file:\n" + head.decode("ascii", "replace")
    else:
        body += "Start of the locked file (hex):\n" + _hex_preview(head, 256)
    return body


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Decryption: every phase run backward
# --------------------------------------------------------------------------
def _decrypt_phases(s8, key, part):
    """Undo Phases 8 to 0. Returns ({phase: Phase}, original input)."""
    ph = {"8": Phase(s8)}

    def pair(m):
        ch = R_P8.get(m.group())
        if ch is None:
            raise CipherError(_BAD)
        return ch

    s7 = _RE_PAIR.sub(pair, s8)
    if any(c in DIGITS for c in s7) or "J" in s7:
        raise CipherError(_BAD)
    ph["7"] = Phase(_show(s7))

    s6 = s7.translate(R_P7_TABLE)
    ph["6"] = Phase(_show(s6))

    s5 = s6.translate(R_P6_TABLE)
    ph["5"] = Phase(_show(s5))
    if any(c in DIGITS for c in _RE_P5.sub("", s5)):
        raise CipherError(_BAD)
    ph["4"] = Phase(_show(_RE_P5.sub(lambda m: R_P5_TO4[m.group()], s5)))
    s3 = _RE_P5.sub(lambda m: R_P5_TO3[m.group()], s5)
    ph["3"] = Phase(_show(s3))

    if re.search(r"[0-9ADEX]", _RE_P3.sub("", s3)):
        raise CipherError(_BAD)

    def group(m):
        ch = R_P3.get(m.group())
        if ch is None:
            raise CipherError(_BAD)
        return ch

    merged = _RE_P3.sub(group, s3)
    ph["2"] = Phase("-".join(str(PHASE2[c]) if c in PHASE2 else _show(c) for c in merged))

    if len(merged) < 4:
        raise CipherError(_BAD)
    positions = _key_positions(key, len(merged), part)
    found = "".join(merged[p] for p in positions)
    if found != _key_chars(key):
        raise CipherError(_WRONG_KEY)
    skip = set(positions)
    s1 = "".join(c for i, c in enumerate(merged) if i not in skip)
    ph["1"] = Phase(_show(s1), [
        f"Key characters {' '.join(found)} found at positions "
        f"{', '.join(str(p + 1) for p in positions)} and removed. "
        "They match this key."])

    data = s1.translate(R_P1_TABLE)
    if not data.startswith(WATERMARK):
        raise CipherError(_WRONG_KEY)
    ph["0"] = Phase(f"Secret key (hex):\n{key.hex().upper()}\n\n"
                    f"Recovered input with watermark:\n{data}",
                    ["Watermark found and removed."])
    return ph, data[len(WATERMARK):]


def _first_error(errors):
    """Report a wrong key over a shape problem, since a key check was reached."""
    for e in errors:
        if str(e) == _WRONG_KEY:
            return e
    return errors[0] if errors else CipherError(_BAD)


def _phases_from_8(s8, key, parts_to_try):
    errors = []
    candidates = [s8]
    trimmed = s8.rstrip("\r\n")   # pasted text often picks up a trailing newline
    if trimmed != s8:
        candidates.append(trimmed)
    for part in parts_to_try:
        for s in candidates:
            try:
                return _decrypt_phases(s, key, part)
            except CipherError as e:
                errors.append(e)
    raise _first_error(errors)


def _from_payload(payload, key, parts_to_try):
    """Undo Phase 8.5 (if it was used) and Phases 8 to 0."""
    if _is_phase85(payload):
        s8, details = phase85_decompress(payload)
        p85 = Phase(details, ["Recognised as Phase 8.5 output and decompressed."])
    else:
        try:
            s8 = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise CipherError(_BAD) from None
        p85 = Phase("This ciphertext wasn't compressed (made by version 1).",
                    status="skipped")
    ph, plain = _phases_from_8(s8, key, parts_to_try)
    ph["8.5"] = p85
    return ph, plain


def _from_bytes(blob, key, parts_to_try):
    """Undo Phase 9 if the bytes have its shape, or go straight to Phase 8.5."""
    errors = []
    if _p9_shape(blob):
        try:
            payload, details = phase9_decrypt(blob, key)
            ph, plain = _from_payload(payload, key, parts_to_try)
            ph["9"] = Phase(details, ["Recognised as Phase 9 output. XOR undone, "
                                      "bytes unshuffled, padding removed."])
            return ph, plain
        except CipherError as e:
            errors.append(e)
    try:
        ph, plain = _from_payload(blob, key, parts_to_try)
        ph["9"] = Phase("This ciphertext didn't use Phase 9.", status="skipped")
        return ph, plain
    except CipherError as e:
        errors.append(e)
    raise _first_error(errors)


def _from_text(text, key, parts_to_try):
    """A ciphertext written as text: Phase 10 binary, base64, or (version 1)
    plain Phase 8 output. There's no header, so each shape is tried."""
    errors = []
    if _p10_shape(text):
        try:
            ph, plain = _from_bytes(phase10_decode(text), key, parts_to_try)
            ph["10"] = Phase(text, ["Recognised as Phase 10 binary and turned "
                                    "back into bytes."])
            return ph, plain
        except CipherError as e:
            errors.append(e)
    squeezed = "".join(text.split())
    try:
        blob = base64.b64decode(squeezed, validate=True) if squeezed else b""
    except ValueError:
        blob = b""
    if blob:
        try:
            ph, plain = _from_bytes(blob, key, parts_to_try)
            ph["10"] = Phase("This ciphertext didn't use Phase 10.", status="skipped")
            return ph, plain
        except CipherError as e:
            errors.append(e)
    try:
        ph, plain = _phases_from_8(text, key, [None])
        ph["8.5"] = Phase("This ciphertext wasn't compressed (made by version 1).",
                          status="skipped")
        ph["9"] = Phase("This ciphertext didn't use Phase 9.", status="skipped")
        ph["10"] = Phase("This ciphertext didn't use Phase 10.", status="skipped")
        return ph, plain
    except CipherError as e:
        errors.append(e)
    raise _first_error(errors)


def _parse_plain(plain):
    """What a recovered part holds: ("part", n, parts, name, data), ("file",
    name, data) from version 1, or ("text", message)."""
    if plain.startswith(PART_TAG):
        try:
            n, parts, b32 = plain[len(PART_TAG):].split("|", 2)
            n, parts = int(n), int(parts)
            raw = base64.b32decode(b32)
        except ValueError:
            raise CipherError(_BAD) from None
        if n == 0:
            name_b, sep, data = raw.partition(b"\0")
            if not sep:
                raise CipherError(_BAD)
            try:
                name = os.path.basename(name_b.decode("utf-8")) or "recovered-file"
            except UnicodeDecodeError:
                raise CipherError(_BAD) from None
            return ("part", n, parts, name, data)
        return ("part", n, parts, None, raw)
    if plain.startswith(FILE_TAG):
        try:
            raw = base64.b32decode(plain[len(FILE_TAG):])
            name_b, sep, data = raw.partition(b"\0")
            if sep:
                name = os.path.basename(name_b.decode("utf-8")) or "recovered-file"
                return ("file", name, data)
        except (ValueError, UnicodeDecodeError):
            pass
    return ("text", plain)


def _decrypt_part(kind, unit, key, part, keep_phases):
    """Worker: decrypt one message or file part."""
    tries = [part] if part > 0 else [0, None]
    if kind == "bytes":
        ph, plain = _from_bytes(unit, key, tries)
        ph["10"] = Phase("This part was stored as bytes (a compact save, or "
                         "Phase 10 wasn't used).", status="skipped")
    else:
        ph, plain = _from_text(unit, key, tries)
    for k in PHASE_KEYS[:9]:
        ph[k].notes.insert(0, f"Recovered. This matches Phase {k}'s output "
                              "from encryption.")
    return (_trim(ph) if keep_phases else None), _parse_plain(plain)


def _framed_parts(fh, size):
    """Offsets of every part if the file is a chain of length-prefixed parts."""
    parts, pos = [], 0
    while pos < size:
        fh.seek(pos)
        head = fh.read(4)
        if len(head) < 4:
            return None
        length = int.from_bytes(head, "big")
        if length < 1 or pos + 4 + length > size:
            return None
        parts.append((pos + 4, length))
        pos += 4 + length
    fh.seek(0)
    return parts or None


def _text_parts(fh):
    """Phase 10 binary text, parts separated by blank lines."""
    buf = []
    for line in fh:
        if line.strip():
            buf.append(line)
        elif buf:
            yield b"".join(buf).decode("ascii")
            buf = []
    if buf:
        yield b"".join(buf).decode("ascii")


_P10_BYTES = frozenset(b"01 \t\r\n")


def iter_units(fh, size):
    """Split a locked file or pasted ciphertext into its parts.
    Returns (count or None, iterator of ("bytes" | "text", unit))."""
    fh.seek(0)
    head = fh.read(65536)
    fh.seek(0)
    if head.strip() and set(head) <= _P10_BYTES:
        return None, (("text", u) for u in _text_parts(fh))
    framed = _framed_parts(fh, size)
    if framed:
        def gen():
            for offset, length in framed:
                fh.seek(offset)
                yield ("bytes", fh.read(length))
        return len(framed), gen()
    fh.seek(0)
    try:
        text = fh.read().decode("utf-8")
    except UnicodeDecodeError:
        raise CipherError(_BAD) from None
    return 1, iter([("text", text)])


def decrypt_stream(fh, size, key, sink, progress=None, cancel=None, workers=None):
    """Decrypt a locked file or ciphertext read from `fh`. File contents are
    written to `sink` (a binary file object). Returns (phases, result), where
    result is {"kind": "text", "text": ...} or {"kind": "file", "name": ...,
    "size": ...}."""
    count, units = iter_units(fh, size)
    try:
        kind, unit = next(units)
    except StopIteration:
        raise CipherError(_BAD) from None
    # The first part is decrypted here, so a wrong key shows up right away.
    ph, parsed = _decrypt_part(kind, unit, key, 0, True)
    if progress:
        progress(1, count)

    if parsed[0] == "text":
        if next(units, None) is not None:
            raise CipherError(_BAD)
        ph["final"] = Phase(parsed[1], ["Letters come back as capitals, because "
                                        "Phase 1 works in uppercase."])
        return ph, {"kind": "text", "text": parsed[1]}

    if parsed[0] == "file":     # version 1 file, always a single part
        name, data = parsed[1], parsed[2]
        sink.write(data)
        written, parts = len(data), 1
        preview = data[:4000]
    else:
        _, n, parts, name, data = parsed
        if n != 0:
            raise CipherError(_BAD)
        sink.write(data)
        written, preview = len(data), data[:4000]
        workers = default_workers(parts - 1) if workers is None else max(1, workers)

        def jobs():
            for i, (k, u) in enumerate(units, 1):
                yield (k, u, key, i, False)

        done = 1
        for _, got in _run_ordered(_decrypt_part, jobs(), workers, cancel):
            if got[0] != "part" or got[1] != done or got[2] != parts:
                raise CipherError(_BAD)
            sink.write(got[4])
            written += len(got[4])
            done += 1
            if progress:
                progress(done, parts)
        if done != parts:
            raise CipherError("This locked file is incomplete: it has "
                              f"{done:,} of its {parts:,} parts.")

    body = (f"Recovered file: {name}\nSize: {written:,} bytes"
            f"{f' (from {parts:,} parts)' if parts > 1 else ''}\n\n"
            "Use Save original file… to write it to disk.")
    try:
        body += "\n\nPreview:\n" + preview.decode("utf-8")
    except UnicodeDecodeError:
        body += "\n\n(Binary file, no text preview.)"
    notes = ["The file comes back byte for byte, including lowercase letters."]
    if parts > 1:
        notes.append("The phases show part 1. Every part went through the same phases.")
    ph["final"] = Phase(body, notes)
    return ph, {"kind": "file", "name": name, "size": written}


def decrypt(text, key):
    """Decrypt a pasted ciphertext. Returns ({phase: Phase}, result); a file
    result carries its bytes in result["data"]."""
    raw = text.encode("utf-8")
    sink = io.BytesIO()
    ph, result = decrypt_stream(io.BytesIO(raw), len(raw), key, sink, workers=1)
    if result["kind"] == "file":
        result["data"] = sink.getvalue()
    return ph, result


def decrypt_file(key, src_path, dst_path, progress=None, cancel=None, workers=None):
    """Decrypt the locked file at src_path. A recovered file goes to dst_path;
    nothing is left there if decryption fails or the result is a message."""
    size = os.path.getsize(src_path)
    try:
        with open(src_path, "rb") as fh, open(dst_path, "wb") as sink:
            ph, result = decrypt_stream(fh, size, key, sink, progress, cancel, workers)
    except BaseException:
        _remove(dst_path)
        raise
    if result["kind"] == "file":
        result["path"] = dst_path
    else:
        _remove(dst_path)
    return ph, result


def encrypt_bytes(key, name, data, opts=None, workers=1):
    """Encrypt a file held in memory. Returns (phases of part 1, locked bytes)."""
    opts = opts or Options()
    out = io.BytesIO()
    ph, _ = encrypt_stream(key, io.BytesIO(data), len(data), name, out, opts,
                           workers=workers)
    return ph, out.getvalue()


def decrypt_bytes(key, locked, workers=1):
    """Decrypt a locked file held in memory. Returns (phases, result)."""
    sink = io.BytesIO()
    ph, result = decrypt_stream(io.BytesIO(locked), len(locked), key, sink,
                                workers=workers)
    if result["kind"] == "file":
        result["data"] = sink.getvalue()
    return ph, result


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
WORK_ROOT = os.path.join(os.path.expanduser("~"), ".cache", "cys-enc26", "work")

LIMIT_WARNING = (
    "Files over the size limit (800 MB, or 90 MB with Phase 10 and no compact "
    "save) aren't tested and can cause problems:\n\n"
    "• The locked file will be over 1.5 GB. It can be up to about 1.9 times "
    "the original, or about 17 times with Phase 10 and no compact save.\n"
    "• It will be slow: about 12 seconds per MB on one core, so a 2 GB file "
    "takes about 7 hours on one core or about 50 minutes on 8 cores.\n"
    "• It needs free disk space for the whole locked file, and the save fails "
    "partway if the disk fills up.\n"
    "• USB drives formatted as FAT32 can't hold files over 4 GB.\n"
    "• Decrypting takes a long time too.\n\n"
    "Continue anyway?")


def _size_text(n):
    for unit, size in (("GB", 1024 * MB), ("MB", MB)):
        if n >= size:
            return f"{n / size:,.1f}".removesuffix(".0") + f" {unit}"
    return f"{n / 1024:,.0f} KB"


def _work_dir():
    """A private folder for this window's temporary files. Folders left by
    windows that are no longer running are removed."""
    os.makedirs(WORK_ROOT, exist_ok=True)
    for entry in os.listdir(WORK_ROOT):
        if entry.isdigit() and int(entry) != os.getpid():
            try:
                os.kill(int(entry), 0)
            except ProcessLookupError:
                shutil.rmtree(os.path.join(WORK_ROOT, entry), ignore_errors=True)
            except OSError:
                pass
    path = os.path.join(WORK_ROOT, str(os.getpid()))
    os.makedirs(path, exist_ok=True)
    return path


def run_gui(start_mode="encrypt"):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter import font as tkfont

    # Palette: a light "lab instrument" look.
    BG = "#E7EBEF"
    PANEL = "#F7F9FA"
    FIELD = "#FFFFFF"
    INK = "#18263A"
    MUTED = "#5C6B7E"
    LINE = "#C4CDD7"
    TEAL = "#1D6F80"
    TEAL_DK = "#155564"
    AMBER = "#9A6200"
    RED = "#B23A3A"

    def pick(families, fallback):
        have = set(tkfont.families())
        return next((f for f in families if f in have), fallback)

    class App:
        def __init__(self, root):
            self.root = root
            self.results = {}
            self.current = "final"
            self.loaded = None       # {"name": str, "path": str, "size": int}
            self.recovered = None    # decrypt result
            self.last_mode = None
            self.last_opts = None
            self.output_path = None  # locked or recovered file waiting to be saved
            self.encrypted_name = None
            self.cancel_event = None
            self.work = _work_dir()
            self.mode = tk.StringVar(value=start_mode)
            self.use_p9 = tk.BooleanVar(value=True)
            self.block = tk.StringVar(value=f"{DEFAULT_BLOCK_BITS} bits")
            self.last_block = self.block.get()
            self.use_p10 = tk.BooleanVar(value=False)
            self.compact = tk.BooleanVar(value=False)
            self.bypass = tk.BooleanVar(value=False)
            self.show_key = tk.BooleanVar(value=False)
            self._setup_fonts()
            self._setup_style()
            self._build()
            self._bind()
            self._set_mode()
            self._refresh_list()
            self.show_phase("final")

        # ---- look ----
        def _setup_fonts(self):
            sans = pick(["Adwaita Sans", "Cantarell", "Noto Sans", "Inter",
                         "DejaVu Sans"], "TkDefaultFont")
            mono = pick(["Adwaita Mono", "Source Code Pro", "Noto Sans Mono",
                         "DejaVu Sans Mono", "Liberation Mono"], "TkFixedFont")
            self.f_body = (sans, 10)
            self.f_small = (sans, 9)
            self.f_bold = (sans, 10, "bold")
            self.f_h1 = (sans, 17, "bold")
            self.f_h2 = (sans, 13, "bold")
            self.f_mono = (mono, 10)

        def _setup_style(self):
            self.root.configure(bg=BG)
            s = ttk.Style(self.root)
            s.theme_use("clam")
            s.configure(".", background=BG, foreground=INK, font=self.f_body,
                        bordercolor=LINE, lightcolor=PANEL, darkcolor=LINE,
                        focuscolor=TEAL)
            s.configure("TFrame", background=BG)
            s.configure("Panel.TFrame", background=PANEL)
            s.configure("TLabel", background=BG, foreground=INK)
            s.configure("Muted.TLabel", background=PANEL, foreground=MUTED,
                        font=self.f_small)
            s.configure("Head.TLabel", background=PANEL, font=self.f_bold)
            s.configure("Panel.TLabel", background=PANEL)
            s.configure("Title.TLabel", background=BG, font=self.f_h1)
            s.configure("Sub.TLabel", background=BG, foreground=MUTED)
            s.configure("H2.TLabel", background=BG, font=self.f_h2)
            s.configure("Desc.TLabel", background=BG, foreground=MUTED)
            s.configure("Note.TLabel", background=BG, foreground=AMBER)
            s.configure("TButton", background=PANEL, padding=(8, 4), width=-4)
            s.map("TButton", background=[("active", "#E3E9EE")])
            s.configure("Run.TButton", background=TEAL, foreground="#FFFFFF",
                        font=self.f_bold, padding=(12, 9), bordercolor=TEAL_DK)
            s.map("Run.TButton",
                  background=[("disabled", "#8FB3BB"), ("active", TEAL_DK)],
                  foreground=[("disabled", "#EEF4F5")])
            s.configure("TCheckbutton", background=PANEL)
            s.map("TCheckbutton", background=[("active", PANEL)])
            s.configure("TCombobox", fieldbackground=FIELD, padding=3)
            s.configure("TEntry", fieldbackground=FIELD, padding=6)
            s.configure("TPanedwindow", background=BG)
            s.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BG,
                        arrowcolor=MUTED)
            s.configure("Horizontal.TProgressbar", background=TEAL, troughcolor=BG,
                        bordercolor=LINE)

        def _text(self, parent, **kw):
            frame = ttk.Frame(parent)
            txt = tk.Text(frame, wrap="char", bg=FIELD, fg=INK, relief="flat",
                          insertbackground=INK, selectbackground="#BFDCE2",
                          selectforeground=INK, highlightthickness=1,
                          highlightbackground=LINE, highlightcolor=TEAL,
                          padx=10, pady=8, font=self.f_mono, undo=True, **kw)
            bar = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
            txt.configure(yscrollcommand=bar.set)
            txt.pack(side="left", fill="both", expand=True)
            bar.pack(side="right", fill="y")
            return frame, txt

        # ---- layout ----
        def _build(self):
            r = self.root
            top = ttk.Frame(r, padding=(22, 16, 22, 12))
            top.pack(fill="x")
            ttk.Label(top, text="CYS-ENC26", style="Title.TLabel").pack(side="left")
            ttk.Label(top, text="See what every phase does to your data. "
                                "A learning tool, not for real secrets.",
                      style="Sub.TLabel").pack(side="left", padx=(14, 0), pady=(5, 0))
            ttk.Label(top, text=f"Version {VERSION}", style="Sub.TLabel").pack(
                side="right", pady=(5, 0))

            panes = ttk.PanedWindow(r, orient="horizontal")
            panes.pack(fill="both", expand=True, padx=16, pady=(0, 16))

            left = ttk.Frame(panes, style="Panel.TFrame", padding=16)
            panes.add(left, weight=0)

            mode_row = tk.Frame(left, bg=LINE, padx=1, pady=1)
            mode_row.pack(fill="x")
            self.mode_buttons = []
            for value, label in (("encrypt", "Encrypt"), ("decrypt", "Decrypt")):
                b = tk.Radiobutton(
                    mode_row, text=label, value=value, variable=self.mode,
                    indicatoron=False, command=self._set_mode, font=self.f_bold,
                    bg=PANEL, fg=INK, selectcolor=TEAL, activebackground="#E3E9EE",
                    relief="flat", bd=0, pady=7, highlightthickness=0)
                b.pack(side="left", fill="x", expand=True)
                self.mode_buttons.append(b)

            in_head = ttk.Frame(left, style="Panel.TFrame")
            in_head.pack(fill="x", pady=(16, 6))
            self.input_label = ttk.Label(in_head, text="Message", style="Head.TLabel")
            self.input_label.pack(side="left")
            self.clear_button = ttk.Button(in_head, text="Clear", command=self.clear_input)
            self.clear_button.pack(side="right")
            self.open_button = ttk.Button(in_head, text="Open file…", command=self.open_file)
            self.open_button.pack(side="right", padx=(0, 6))

            box, self.input = self._text(left, width=36, height=9)
            box.pack(fill="both", expand=True)
            self.count_label = ttk.Label(left, text="0 characters", style="Muted.TLabel",
                                         wraplength=300, justify="left")
            self.count_label.pack(anchor="w", pady=(4, 0))

            ttk.Label(left, text="Secret key (32 hex characters)",
                      style="Head.TLabel").pack(anchor="w", pady=(14, 6))
            self.key_entry = ttk.Entry(left, font=self.f_mono, show="•")
            self.key_entry.pack(fill="x")
            key_row = ttk.Frame(left, style="Panel.TFrame")
            key_row.pack(fill="x", pady=(6, 0))
            ttk.Button(key_row, text="New key", command=self.new_key).pack(side="left")
            ttk.Button(key_row, text="Open…", command=self.open_key).pack(side="left", padx=6)
            ttk.Button(key_row, text="Save…", command=self.save_key).pack(side="left")
            ttk.Checkbutton(key_row, text="Show", variable=self.show_key,
                            command=self._toggle_key).pack(side="right")
            self.key_hint = ttk.Label(left, style="Muted.TLabel", wraplength=300,
                                      justify="left")
            self.key_hint.pack(anchor="w", pady=(4, 0))

            # Encryption options (decryption recognises them by themselves)
            self.opt_frame = ttk.Frame(left, style="Panel.TFrame")
            self.opt_frame.pack(fill="x", pady=(12, 0))
            p9_row = ttk.Frame(self.opt_frame, style="Panel.TFrame")
            p9_row.pack(fill="x")
            self.p9_check = ttk.Checkbutton(
                p9_row, text="Use Phase 9, block size", variable=self.use_p9,
                command=self._options_changed)
            self.p9_check.pack(side="left")
            self.block_box = ttk.Combobox(
                p9_row, textvariable=self.block, state="readonly", width=13,
                values=[f"{b} bits" for b in BLOCK_BITS_OPTIONS])
            self.block_box.pack(side="left", padx=(6, 0))
            self.p10_check = ttk.Checkbutton(
                self.opt_frame, text="Use Phase 10 (binary output)",
                variable=self.use_p10, command=self._options_changed)
            self.p10_check.pack(anchor="w", pady=(6, 0))
            self.compact_check = ttk.Checkbutton(
                self.opt_frame, text="Compact save (pack the bits into bytes)",
                variable=self.compact, command=self._options_changed)
            self.compact_check.pack(anchor="w", padx=(20, 0), pady=(2, 0))
            self.bypass_check = ttk.Checkbutton(
                self.opt_frame, text="Allow files over the size limit",
                variable=self.bypass, command=self._bypass_changed)
            self.bypass_check.pack(anchor="w", pady=(6, 0))
            self.limit_label = ttk.Label(self.opt_frame, style="Muted.TLabel",
                                         wraplength=300, justify="left")
            self.limit_label.pack(anchor="w", pady=(2, 0))

            self.run_button = ttk.Button(left, style="Run.TButton", command=self.run)
            self.run_button.pack(fill="x", pady=(14, 0))
            self.progress_row = ttk.Frame(left, style="Panel.TFrame")
            self.progress = ttk.Progressbar(self.progress_row, mode="determinate",
                                            maximum=1)
            self.progress.pack(side="left", fill="x", expand=True)
            self.cancel_button = ttk.Button(self.progress_row, text="Cancel",
                                            command=self.cancel)
            self.cancel_button.pack(side="right", padx=(8, 0))
            self.status = tk.Label(left, text="", bg=PANEL, fg=MUTED, font=self.f_small,
                                   wraplength=300, justify="left", anchor="w")
            self.status.pack(fill="x", pady=(8, 0))

            right = ttk.Frame(panes, padding=(16, 0, 0, 0))
            panes.add(right, weight=1)
            right.columnconfigure(1, weight=1)
            right.rowconfigure(0, weight=1)

            rail = tk.Frame(right, bg=PANEL, highlightthickness=1,
                            highlightbackground=LINE)
            rail.grid(row=0, column=0, sticky="ns", padx=(0, 16))
            self.rail = tk.Listbox(
                rail, activestyle="none", exportselection=False, font=self.f_mono,
                bg=PANEL, fg=INK, selectbackground=TEAL, selectforeground="#FFFFFF",
                highlightthickness=0, bd=0, width=33, height=len(PHASES))
            self.rail.pack(fill="both", expand=True, padx=6, pady=6)

            viewer = ttk.Frame(right)
            viewer.grid(row=0, column=1, sticky="nsew")
            viewer.columnconfigure(0, weight=1)
            viewer.rowconfigure(3, weight=1)
            self.v_title = ttk.Label(viewer, style="H2.TLabel")
            self.v_title.grid(row=0, column=0, sticky="w")
            self.v_desc = ttk.Label(viewer, style="Desc.TLabel", justify="left")
            self.v_desc.grid(row=1, column=0, sticky="we", pady=(4, 0))
            self.v_notes = ttk.Label(viewer, style="Note.TLabel", justify="left")
            self.v_notes.grid(row=2, column=0, sticky="we", pady=(8, 8))
            box, self.output = self._text(viewer, state="disabled")
            box.grid(row=3, column=0, sticky="nsew")

            actions = ttk.Frame(viewer)
            actions.grid(row=4, column=0, sticky="we", pady=(10, 0))
            ttk.Button(actions, text="Copy", command=self.copy_phase).pack(side="left")
            ttk.Button(actions, text="Save this phase…", command=self.save_phase).pack(
                side="left", padx=6)
            ttk.Button(actions, text="Save report…", command=self.save_report).pack(
                side="right")
            self.save_button = ttk.Button(actions, text="Save output…",
                                          command=self.save_output)
            self.save_button.pack(side="right", padx=6)

            viewer.bind("<Configure>", self._rewrap)

        def _bind(self):
            self.rail.bind("<<ListboxSelect>>", self._on_select)
            self.input.bind("<<Modified>>", self._on_input_change)
            self.block_box.bind("<<ComboboxSelected>>", self._block_changed)
            self.root.bind("<Control-Return>", lambda e: self.run())
            self.root.bind("<Control-o>", lambda e: self.open_file())
            self.root.protocol("WM_DELETE_WINDOW", self.close)

        def _rewrap(self, event):
            width = max(event.width - 10, 200)
            self.v_desc.configure(wraplength=width)
            self.v_notes.configure(wraplength=width)

        def close(self):
            if self.cancel_event is not None:
                self.cancel_event.set()
            shutil.rmtree(self.work, ignore_errors=True)
            self.root.destroy()

        # ---- options ----
        def options(self):
            return Options(use_phase9=self.use_p9.get(),
                           block_bits=int(self.block.get().split()[0]),
                           use_phase10=self.use_p10.get(),
                           compact=self.compact.get())

        def _options_changed(self):
            enc = self.mode.get() == "encrypt"
            on = "normal" if enc else "disabled"
            self.p9_check.configure(state=on)
            self.p10_check.configure(state=on)
            self.bypass_check.configure(state=on)
            self.block_box.configure(
                state="readonly" if enc and self.use_p9.get() else "disabled")
            self.compact_check.configure(
                state="normal" if enc and self.use_p10.get() else "disabled")
            if not enc:
                self.limit_label.configure(
                    text="Decryption recognises the phases that were used.")
                return
            limit = file_limit(self.options())
            if self.bypass.get():
                text = f"Size limit {_size_text(limit)}, bypassed."
            else:
                text = f"Files up to {_size_text(limit)}."
            if self.use_p10.get() and not self.compact.get():
                text += " Phase 10 files are about 9 times bigger unless compact save is on."
            self.limit_label.configure(text=text)

        def _block_changed(self, _event=None):
            bits = int(self.block.get().split()[0])
            if bits >= LARGE_BLOCK_BITS and self.block.get() != self.last_block:
                size = _size_text(bits // 8)
                smallest = _size_text((bits // 8 + 16) * 4 // 3)
                if not messagebox.askokcancel(
                        APP_NAME,
                        f"Large block size ({bits:,} bits).\n\nEvery message is padded "
                        f"to at least {size}, so even a one-word message becomes about "
                        f"{smallest} of ciphertext, and files grow by up to {size} "
                        f"for each {CHUNK_BYTES // 1024} KB part. Encrypting and "
                        "decrypting also take longer.\n\nUse this block size?",
                        icon="warning"):
                    self.block.set(self.last_block)
                    return
            self.last_block = self.block.get()
            self._options_changed()

        def _bypass_changed(self):
            if self.bypass.get() and not messagebox.askokcancel(
                    APP_NAME, LIMIT_WARNING, icon="warning"):
                self.bypass.set(False)
            self._options_changed()

        # ---- state ----
        def _set_mode(self):
            enc = self.mode.get() == "encrypt"
            for b in self.mode_buttons:
                selected = b.cget("value") == self.mode.get()
                b.configure(fg="#FFFFFF" if selected else INK)
            self.root.title(f"{APP_NAME} {'Encrypt' if enc else 'Decrypt'}")
            self.run_button.configure(text="Encrypt" if enc else "Decrypt")
            self.input_label.configure(text="Message" if enc else "Ciphertext")
            self.key_hint.configure(
                text="Leave empty to create a new key." if enc
                else "Use the same key that encrypted the message.")
            self._options_changed()

        def _toggle_key(self):
            self.key_entry.configure(show="" if self.show_key.get() else "•")

        def _on_input_change(self, _event=None):
            if not self.loaded:
                n = len(self.input.get("1.0", "end-1c"))
                self.count_label.configure(
                    text=f"{n:,} character{'s' if n != 1 else ''}")
            self.input.edit_modified(False)

        def _set_status(self, text, color=MUTED):
            self.status.configure(text=text, fg=color)

        def _refresh_list(self):
            self.rail.delete(0, "end")
            for i, (key, name, _) in enumerate(PHASES):
                res = self.results.get(key)
                mark = {"done": "●", "skipped": "–"}[res.status] if res else "○"
                num = key if key != "final" else ""
                self.rail.insert("end", f" {mark} {num:<3}  {name}")
                done = res is not None and res.status == "done"
                self.rail.itemconfigure(i, foreground=INK if done else MUTED)
            self.rail.selection_clear(0, "end")
            self.rail.selection_set(PHASE_KEYS.index(self.current))

        def _on_select(self, _event):
            sel = self.rail.curselection()
            if sel:
                self.show_phase(PHASE_KEYS[sel[0]])

        def show_phase(self, key):
            self.current = key
            index = PHASE_KEYS.index(key)
            if self.rail.curselection() != (index,):
                self.rail.selection_clear(0, "end")
                self.rail.selection_set(index)
            _, name, desc = PHASES[index]
            self.v_title.configure(text=(f"Phase {key}: " if key != "final" else "") + name)
            self.v_desc.configure(text=desc)
            res = self.results.get(key)
            if res is None:
                body, notes = "", "Nothing here yet. Enter a message or open a file, then run it."
            else:
                body = res.output
                notes = list(res.notes)
                if res.full_length:
                    notes.append(f"Showing the first {len(res.output):,} of "
                                 f"{res.full_length:,} characters of part 1.")
                if len(body) > MAX_VIEW_CHARS:
                    body = (body[:MAX_VIEW_CHARS] + f"\n\n[Showing the first "
                            f"{MAX_VIEW_CHARS:,} of {len(res.output):,} characters. "
                            "Copy or Save includes everything.]")
                notes = "\n".join(notes)
            self.v_notes.configure(text=notes)
            self.output.configure(state="normal")
            self.output.delete("1.0", "end")
            self.output.insert("1.0", body)
            self.output.configure(state="disabled")

        # ---- files and keys ----
        def open_file(self):
            if str(self.run_button.cget("state")) == "disabled":
                return
            decrypting = self.mode.get() == "decrypt"
            if decrypting:
                types = [("CYS-ENC26 locked files", "*.cys"), ("All files", "*")]
            else:
                types = [("All files", "*")]
            path = filedialog.askopenfilename(title="Open a file", filetypes=types)
            if not path:
                return
            try:
                size = os.path.getsize(path)
            except OSError as e:
                messagebox.showerror(APP_NAME, f"Couldn't open the file.\n\n{e}")
                return
            if not self._size_ok(size, decrypting):
                return
            self.loaded = {"name": os.path.basename(path), "path": path, "size": size}
            self.input.configure(state="normal")
            self.input.delete("1.0", "end")
            self.input.insert("1.0", f"{self.loaded['name']}\n\nThis file will be "
                              "used as the input. Select Remove file to type a "
                              "message instead.")
            self.input.configure(state="disabled", fg=MUTED)
            self.count_label.configure(
                text=f"File loaded: {self.loaded['name']} ({size:,} bytes)")
            self.clear_button.configure(text="Remove file")
            self._set_status("File loaded.")

        def _size_ok(self, size, decrypting):
            """Checks the limits and asks about long runs. True to go ahead."""
            if not decrypting:
                limit = file_limit(self.options())
                if size > limit and not self.bypass.get():
                    extra = (" (Phase 10 without compact save makes files about 9 "
                             "times bigger)" if self.options().text_parts else "")
                    messagebox.showerror(
                        APP_NAME,
                        f"That file is {_size_text(size)}. The limit is "
                        f"{_size_text(limit)}{extra}, so the locked file stays under "
                        "about 1.5 GB.\n\nTick Allow files over the size limit to "
                        "encrypt it anyway.")
                    return False
            elif size > LARGE_LOCKED_BYTES and not messagebox.askyesno(
                    APP_NAME, f"This locked file is {_size_text(size)}. Decrypting "
                    f"it will take {describe_seconds(estimate_seconds(size, True))} "
                    "and needs free disk space for the recovered file.\n\nContinue?",
                    icon="warning"):
                return False
            seconds = estimate_seconds(size, decrypting)
            if seconds > 60 and not decrypting and not messagebox.askyesno(
                    APP_NAME, f"This file is {_size_text(size)}. Running it through "
                    f"every phase will take {describe_seconds(seconds)}.\n\nContinue?"):
                return False
            return True

        def clear_input(self):
            if self.loaded:
                self.loaded = None
                self.clear_button.configure(text="Clear")
            self.input.configure(state="normal", fg=INK)
            self.input.delete("1.0", "end")
            self._on_input_change()

        def new_key(self):
            self.key_entry.delete(0, "end")
            self.key_entry.insert(0, generate_key().hex().upper())
            self._set_status("New key created. Save it if you'll need to decrypt later.")

        def open_key(self):
            path = filedialog.askopenfilename(
                title="Open key", filetypes=[("Key files", "*.key"), ("All files", "*")])
            if not path:
                return
            try:
                with open(path, encoding="utf-8") as fh:
                    key = parse_key(fh.read())
            except (OSError, ValueError) as e:
                messagebox.showerror(APP_NAME, f"Couldn't use that key file.\n\n{e}")
                return
            self.key_entry.delete(0, "end")
            self.key_entry.insert(0, key.hex().upper())
            self._set_status("Key loaded.")

        def save_key(self):
            try:
                key = parse_key(self.key_entry.get())
            except ValueError as e:
                messagebox.showerror(APP_NAME, str(e))
                return
            path = filedialog.asksaveasfilename(
                title="Save key", defaultextension=".key", initialfile="cys-enc26.key",
                filetypes=[("Key files", "*.key")])
            if path:
                self._write(path, key.hex().upper() + "\n", "Key saved.")

        def _write(self, path, content, message):
            try:
                if isinstance(content, bytes):
                    with open(path, "wb") as fh:
                        fh.write(content)
                else:
                    with open(path, "w", encoding="utf-8", newline="") as fh:
                        fh.write(content)
                self._set_status(message)
            except OSError as e:
                messagebox.showerror(APP_NAME, f"Couldn't save the file.\n\n{e}")

        def _save_big(self, path, message):
            """Move (or copy, the second time) a finished file to `path`."""
            try:
                if os.path.dirname(os.path.abspath(self.output_path)) == self.work:
                    shutil.move(self.output_path, path)
                else:
                    shutil.copyfile(self.output_path, path)
                self.output_path = path
                self._set_status(message)
            except OSError as e:
                messagebox.showerror(APP_NAME, f"Couldn't save the file.\n\n{e}")

        def copy_phase(self):
            res = self.results.get(self.current)
            if res and res.output:
                self.root.clipboard_clear()
                self.root.clipboard_append(res.output)
                self._set_status("Copied to the clipboard.")

        def save_phase(self):
            res = self.results.get(self.current)
            if not res or not res.output:
                return
            label = f"phase{self.current}" if self.current != "final" else "final"
            path = filedialog.asksaveasfilename(
                title="Save this phase", defaultextension=".txt",
                initialfile=f"cys-enc26-{label}.txt")
            if path:
                self._write(path, res.output, "Phase saved.")

        def save_output(self):
            if not self.results:
                self._set_status("Encrypt or decrypt something first.", RED)
                return
            if self.last_mode == "encrypt":
                base = self.encrypted_name or "message"
                path = filedialog.asksaveasfilename(
                    title="Save locked file", initialfile=base + LOCKED_EXT,
                    filetypes=[("CYS-ENC26 locked files", "*.cys"), ("All files", "*")])
                if not path:
                    return
                if not path.endswith(LOCKED_EXT):
                    path += LOCKED_EXT
                if self.output_path:
                    self._save_big(path, "Locked file saved.")
                else:
                    self._write(path, message_locked_bytes(self.results, self.last_opts),
                                "Locked file saved.")
            elif self.recovered and self.recovered["kind"] == "file":
                path = filedialog.asksaveasfilename(
                    title="Save original file", initialfile=self.recovered["name"])
                if path:
                    self._save_big(path, "Original file saved.")
            else:
                path = filedialog.asksaveasfilename(
                    title="Save message", defaultextension=".txt",
                    initialfile="cys-enc26-message.txt")
                if path:
                    self._write(path, self.recovered["text"], "Message saved.")

        def save_report(self):
            if not self.results:
                return
            lines = [f"{APP_NAME} {VERSION} report ({self.last_mode})", ""]
            for key, name, desc in PHASES:
                res = self.results.get(key)
                title = f"Phase {key}: {name}" if key != "final" else name
                lines += ["=" * 72, title, "=" * 72, desc]
                if res:
                    lines += [f"Note: {n}" for n in res.notes]
                    if res.full_length:
                        lines.append(f"Note: shortened to the first {len(res.output):,} "
                                     f"of {res.full_length:,} characters of part 1.")
                    lines += ["", res.output or "(no output)"]
                lines.append("")
            path = filedialog.asksaveasfilename(
                title="Save report", defaultextension=".txt",
                initialfile="cys-enc26-report.txt")
            if path:
                self._write(path, "\n".join(lines), "Report saved.")

        # ---- running ----
        def _busy(self, on, with_progress=False):
            state = "disabled" if on else "normal"
            self.run_button.configure(state=state)
            self.open_button.configure(state=state)
            self.clear_button.configure(state=state)
            if on and with_progress:
                self.progress.configure(value=0, maximum=1)
                self.progress_row.pack(fill="x", pady=(8, 0), before=self.status)
            else:
                self.progress_row.pack_forget()

        def _on_progress(self, done, total):
            def update():
                if total:
                    self.progress.configure(maximum=total, value=done)
                    self._set_status(f"Part {done:,} of {total:,} done…")
                else:
                    self._set_status(f"Part {done:,} done…")
            self.root.after(0, update)

        def cancel(self):
            if self.cancel_event is not None:
                self.cancel_event.set()
                self._set_status("Cancelling after the parts already running…", AMBER)

        def _clear_output_file(self):
            if self.output_path and os.path.dirname(
                    os.path.abspath(self.output_path)) == self.work:
                _remove(self.output_path)
            self.output_path = None

        def run(self):
            if str(self.run_button.cget("state")) == "disabled":
                return
            mode = self.mode.get()
            loaded = self.loaded
            text = None if loaded else self.input.get("1.0", "end-1c")
            key_text = self.key_entry.get().strip()
            opts = self.options()

            if mode == "decrypt" and not loaded and not text.strip():
                self._set_status("Paste a ciphertext or open a locked file.", RED)
                return
            if not key_text:
                if mode == "decrypt":
                    self._set_status("Enter the key that encrypted this.", RED)
                    return
                self.new_key()
                key_text = self.key_entry.get()
            try:
                key = parse_key(key_text)
            except ValueError as e:
                self._set_status(str(e), RED)
                return

            out_path = None
            if loaded:
                try:
                    size = os.path.getsize(loaded["path"])
                except OSError as e:
                    self._set_status(f"Couldn't open the file. {e}", RED)
                    return
                if mode == "encrypt":
                    if size > file_limit(opts) and not self.bypass.get():
                        self._size_ok(size, False)
                        return
                    need = estimate_locked_size(size, opts)
                    free = shutil.disk_usage(self.work).free
                    if need > free:
                        messagebox.showerror(
                            APP_NAME, f"There isn't enough free disk space. The locked "
                            f"file can be up to {_size_text(need)} and only "
                            f"{_size_text(free)} is free in {self.work}.")
                        return
                out_path = os.path.join(self.work, f"run-{secrets.token_hex(4)}")
            self._clear_output_file()

            self.cancel_event = threading.Event()
            cancel = self.cancel_event
            self._busy(True, with_progress=bool(loaded))
            self._set_status("Encrypting…" if mode == "encrypt" else "Decrypting…")

            def work():
                try:
                    if mode == "encrypt" and loaded:
                        ph, _ = encrypt_file(key, loaded["path"], out_path, opts,
                                             self._on_progress, cancel)
                        result = (ph, None)
                    elif mode == "encrypt":
                        result = (encrypt(key, text, opts), None)
                    elif loaded:
                        result = decrypt_file(key, loaded["path"], out_path,
                                              self._on_progress, cancel)
                    else:
                        result = decrypt(text, key)
                    self.root.after(0, self._finish, mode, result, loaded, opts,
                                    out_path, None)
                except BaseException as e:   # shown to the user, not raised
                    self.root.after(0, self._finish, mode, None, loaded, opts,
                                    out_path, e)

            threading.Thread(target=work, daemon=True).start()

        def _finish(self, mode, result, loaded, opts, out_path, error):
            self.cancel_event = None
            self._busy(False)
            if error is not None:
                if out_path:
                    _remove(out_path)
                if isinstance(error, Cancelled):
                    self._set_status("Cancelled. Nothing was saved.", AMBER)
                elif isinstance(error, OSError):
                    self._set_status(f"Couldn't finish: {error}", RED)
                elif isinstance(error, MemoryError):
                    self._set_status("Ran out of memory.", RED)
                else:
                    self._set_status(str(error) or type(error).__name__, RED)
                return
            self.results, self.recovered = result
            self.last_mode, self.last_opts = mode, opts
            self.encrypted_name = loaded["name"] if loaded else None
            file_out = (mode == "encrypt" and loaded) or (
                self.recovered and self.recovered["kind"] == "file")
            self.output_path = out_path if file_out else None
            self.current = "final"
            self._refresh_list()
            self.show_phase("final")
            if mode == "encrypt":
                self.save_button.configure(text="Save locked file…")
                msg = "Encrypted. Select any phase to see its output."
            elif self.recovered["kind"] == "file":
                self.save_button.configure(text="Save original file…")
                msg = f"Decrypted {self.recovered['name']}. Save it with Save original file."
            else:
                self.save_button.configure(text="Save message…")
                msg = "Decrypted. Select any phase to see what it recovered."
            self._set_status(msg, TEAL)

    root = tk.Tk(className="cys-enc26")
    root.geometry("1320x860")
    root.minsize(1100, 700)
    App(root)
    root.mainloop()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cys_enc26", description=f"{APP_NAME} {VERSION}")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], default="encrypt")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    args = parser.parse_args(argv)
    run_gui(args.mode)


if __name__ == "__main__":
    main()
