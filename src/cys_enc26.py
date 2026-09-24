#!/usr/bin/env python3
"""
CYS-ENC26 phase explorer.

Encrypts and decrypts text or files with the CYS-ENC26 phases and shows the
output of every phase in both directions. Every phase is reversible, with or
without Phase 9. It is a learning tool, not a way to protect real data.
"""

import argparse
import base64
import hashlib
import hmac
import os
import re
import secrets
import sys
import threading
from array import array

APP_NAME = "CYS-ENC26"
WATERMARK = "CYSEN26:"
FILE_TAG = "FILE|"
LOCKED_EXT = ".locked.rl.cys"
BLOCK_BYTES = 128            # 1024 bits
MAX_VIEW_CHARS = 200_000     # longer outputs are shortened on screen only
MAX_FILE_BYTES = 2 * 1024 * 1024     # every phase multiplies the size about 11x
SLOW_FILE_BYTES = 512 * 1024
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
    return "1.0.0.0"


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

_RE_PAIR = re.compile(r"[0-9]{2}")
_RE_P5 = re.compile(r"1[04]|[2468]")
_RE_P3 = re.compile(r"[0-9ADEX]{%d}" % PHASE3_WIDTH)

PHASES = [
    ("Key and watermark",
     "A random 128-bit key is generated (or the key you entered is used), "
     "and CYSEN26: is placed at the start of the input."),
    ("Basic crypto scramble",
     "Letters and digits are swapped: A→0 … J→9, K→A … Z→P, 1→Q … 9→Y, 0→Z. "
     "The symbols - | + = _ become 4-bit binary codes."),
    ("Numbered encryption cycle",
     "The first and last 8 bits of the key go in at positions chosen by the "
     "key, then each character becomes its number (A=1, B=2, C=4 … 0=26), "
     "joined by dashes."),
    ("Final scramble",
     "Dashes are removed, each number is doubled and written as 5 digits, "
     "then 0→A, 4→D, 8→E and 9→X."),
    ("Number shift",
     "Even digits go up 2. Odd digits are multiplied by 3."),
    ("Odd number division",
     "Each odd number from Phase 4 is divided by 1.5 and rounded up."),
    ("Numbers to letters",
     "Each digit becomes a random letter from its own set. A, D, E and X stay. "
     "Symbols become 6-bit binary codes."),
    ("Letter shift",
     "Every letter moves forward one (Z→A). I becomes 111111."),
    ("Binary to number",
     "Every binary code becomes a 2-digit number. 6-bit codes use 00-63; "
     "Phase 1's 4-bit codes add 64 (- = 1001 = 9 + 64 = 73)."),
    ("Finalized encoding",
     "Optional. A keyed shuffle and XOR, padded to 1024-bit blocks, with the "
     "nonce stored inside. Nothing in the output is readable."),
    ("Final output",
     "The finished ciphertext when encrypting, or the recovered message or "
     "file when decrypting."),
]


class Phase:
    """The output of one phase plus notes about what happened in it."""

    def __init__(self, output="", notes=None, status="done"):
        self.output = output
        self.notes = notes or []
        self.status = status  # "done" or "skipped"


class CipherError(ValueError):
    pass


def _show(s):
    return s.translate(DISPLAY)


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


def _hex_preview(data, n=48):
    h = data[:n].hex(" ").upper()
    return h + (" …" if len(data) > n else "")


def phase9_encrypt(text, key):
    data = text.encode("utf-8")
    payload = len(data).to_bytes(4, "big") + data
    payload += secrets.token_bytes((-len(payload)) % BLOCK_BYTES)
    nonce = secrets.token_bytes(16)

    perm = _permutation(len(payload), KeyedStream(key, nonce, b"CYS-ENC26 shuffle"))
    shuffled = bytes(payload[p] for p in perm)
    cipher = _xor(shuffled, KeyedStream(key, nonce, b"CYS-ENC26 xor"))

    out = base64.b64encode(nonce + cipher).decode()
    details = (
        f"Phase 8 output: {len(data):,} bytes (+4 byte length prefix)\n"
        f"Padded to: {len(payload):,} bytes = {len(payload) // BLOCK_BYTES:,} × 1024-bit block(s)\n"
        f"Nonce: {nonce.hex().upper()} (stored inside the output)\n"
        f"Generator: HMAC-SHA256(key, label + nonce + counter)\n\n"
        f"Before shuffle and XOR:\n{_hex_preview(payload)}\n\n"
        f"After shuffle:\n{_hex_preview(shuffled)}\n\n"
        f"After XOR:\n{_hex_preview(cipher)}"
    )
    return out, details


def _p9_blob(text):
    """Return the decoded bytes if text has the shape of Phase 9 output."""
    t = "".join(text.split())
    if not t:
        return None
    try:
        blob = base64.b64decode(t, validate=True)
    except ValueError:
        return None
    body = len(blob) - 16
    if body <= 0 or body % BLOCK_BYTES:
        return None
    return blob


def phase9_decrypt(text, key):
    blob = _p9_blob(text)
    if blob is None:
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
    try:
        recovered = bytes(payload[4:4 + length]).decode("utf-8")
    except UnicodeDecodeError:
        raise CipherError(_WRONG_KEY) from None

    details = (
        f"Nonce: {nonce.hex().upper()}\n"
        f"Ciphertext: {len(cipher):,} bytes = {len(cipher) // BLOCK_BYTES:,} × 1024-bit block(s)\n"
        f"Recovered Phase 8 output: {length:,} bytes\n\n"
        f"After undoing XOR:\n{_hex_preview(shuffled)}\n\n"
        f"After unshuffling:\n{_hex_preview(bytes(payload))}"
    )
    return recovered, details


# --------------------------------------------------------------------------
# Encryption
# --------------------------------------------------------------------------
def _key_positions(key, total):
    """Four injection positions, generated from the key and the length."""
    stream = KeyedStream(key, total.to_bytes(8, "big"), b"CYS-ENC26 inject")
    picked = []
    while len(picked) < 4:
        p = stream.randbelow(total)
        if p not in picked:
            picked.append(p)
    return sorted(picked)


def _key_chars(key):
    return f"{key[0]:02X}{key[-1]:02X}"


def encrypt(key, use_phase9=True, text=None, file=None):
    """Encrypt a text message, or a file given as (name, bytes)."""
    ph = {}

    # Phase 0
    if file is not None:
        name, data = file
        plain = FILE_TAG + base64.b32encode(name.encode("utf-8") + b"\0" + data).decode()
        source_note = (f"File '{name}' ({len(data):,} bytes) was turned into base32 "
                       f"text ({len(plain) - len(FILE_TAG):,} characters) so every "
                       "byte, including lowercase and binary data, comes back exactly.")
    else:
        plain = text or ""
        if any(c in _RESERVED for c in plain):
            raise CipherError("The message contains characters CYS-ENC26 uses "
                              "internally (private-use range U+E000 to U+E03F).")
        source_note = None
    data = WATERMARK + plain
    notes = ["Keep the key private. It's needed to decrypt."]
    if source_note:
        notes.append(source_note)
    ph[0] = Phase(f"Secret key (hex):\n{key.hex().upper()}\n\n"
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
    ph[1] = Phase(_show(s1), notes)

    # Phase 2
    inject = _key_chars(key)
    positions = _key_positions(key, len(s1) + len(inject))
    chars = list(s1)
    for p, ch in zip(positions, inject):
        chars.insert(p, ch)
    merged = "".join(chars)
    where = ", ".join(str(p + 1) for p in positions)
    ph[2] = Phase(
        "-".join(str(PHASE2[c]) if c in PHASE2 else _show(c) for c in merged),
        [f"Key bits injected: first byte {inject[:2]}, last byte {inject[2:]}, "
         f"as the characters {' '.join(inject)} at positions {where}."])

    # Phases 3 to 5
    s3 = merged.translate(P3_TABLE)
    ph[3] = Phase(_show(s3))
    ph[4] = Phase(_show(s3.translate(P4_TABLE)))
    s5 = s3.translate(P5_TABLE)
    ph[5] = Phase(_show(s5), ["Applied to each number produced in Phase 4."])

    # Phase 6 (random letter per digit; sets of 2 or 4 divide 256 evenly)
    rand = secrets.token_bytes(len(s5))
    out = []
    add = out.append
    for ch, r in zip(s5, rand):
        opts = PHASE6_LETTERS.get(ch)
        add(opts[r % len(opts)] if opts else P6_SYM.get(ch, ch))
    s6 = "".join(out)
    ph[6] = Phase(_show(s6), ["Letters are picked at random, so the same "
                              "message encrypts differently every time."])

    # Phases 7 and 8
    s7 = s6.translate(P7_TABLE)
    ph[7] = Phase(_show(s7))
    s8 = s7.translate(P8_TABLE)
    ph[8] = Phase(s8)

    # Phase 9
    if use_phase9:
        final, details = phase9_encrypt(s8, key)
        ph[9] = Phase(details + "\n\nOutput:\n" + final)
    else:
        final = s8
        ph[9] = Phase("Phase 9 was not selected.",
                      ["The Phase 8 output is the final ciphertext."], status="skipped")

    ph[10] = Phase(final)
    return ph


# --------------------------------------------------------------------------
# Decryption: every phase run backward
# --------------------------------------------------------------------------
_BAD = ("This isn't valid CYS-ENC26 ciphertext, or it was changed after "
        "encryption.")
_WRONG_KEY = "Decryption failed. The key is wrong or the ciphertext was changed."


def _decrypt_phases(s8, key):
    """Undo Phases 8 to 0. Returns ({phase: Phase}, original input)."""
    ph = {8: Phase(s8)}

    def pair(m):
        ch = R_P8.get(m.group())
        if ch is None:
            raise CipherError(_BAD)
        return ch

    s7 = _RE_PAIR.sub(pair, s8)
    if any(c in DIGITS for c in s7) or "J" in s7:
        raise CipherError(_BAD)
    ph[7] = Phase(_show(s7))

    s6 = s7.translate(R_P7_TABLE)
    ph[6] = Phase(_show(s6))

    s5 = s6.translate(R_P6_TABLE)
    ph[5] = Phase(_show(s5))
    if any(c in DIGITS for c in _RE_P5.sub("", s5)):
        raise CipherError(_BAD)
    ph[4] = Phase(_show(_RE_P5.sub(lambda m: R_P5_TO4[m.group()], s5)))
    s3 = _RE_P5.sub(lambda m: R_P5_TO3[m.group()], s5)
    ph[3] = Phase(_show(s3))

    if re.search(r"[0-9ADEX]", _RE_P3.sub("", s3)):
        raise CipherError(_BAD)

    def group(m):
        ch = R_P3.get(m.group())
        if ch is None:
            raise CipherError(_BAD)
        return ch

    merged = _RE_P3.sub(group, s3)
    ph[2] = Phase("-".join(str(PHASE2[c]) if c in PHASE2 else _show(c) for c in merged))

    if len(merged) < 4:
        raise CipherError(_BAD)
    positions = _key_positions(key, len(merged))
    found = "".join(merged[p] for p in positions)
    if found != _key_chars(key):
        raise CipherError(_WRONG_KEY)
    skip = set(positions)
    s1 = "".join(c for i, c in enumerate(merged) if i not in skip)
    ph[1] = Phase(_show(s1), [
        f"Key characters {' '.join(found)} found at positions "
        f"{', '.join(str(p + 1) for p in positions)} and removed. "
        "They match this key."])

    data = s1.translate(R_P1_TABLE)
    if not data.startswith(WATERMARK):
        raise CipherError(_WRONG_KEY)
    ph[0] = Phase(f"Secret key (hex):\n{key.hex().upper()}\n\n"
                  f"Recovered input with watermark:\n{data}",
                  ["Watermark found and removed."])
    return ph, data[len(WATERMARK):]


def _phases_from_8(s8, key):
    try:
        return _decrypt_phases(s8, key)
    except CipherError:
        # A pasted ciphertext often picks up a trailing newline; try without it.
        trimmed = s8.rstrip("\r\n")
        if trimmed == s8:
            raise
        return _decrypt_phases(trimmed, key)


def decrypt(text, key):
    """Returns ({phase: Phase}, result). result is {"kind": "text", "text": ...}
    or {"kind": "file", "name": ..., "data": bytes}."""
    ph, phases = {}, None
    # There's no readable header, so Phase 9 is recognised by its shape. If
    # that route fails, the input is tried as plain Phase 8 output instead.
    if _p9_blob(text) is not None:
        try:
            s8, details = phase9_decrypt(text, key)
            phases, message = _phases_from_8(s8, key)
            ph[9] = Phase(details, ["Recognised as Phase 9 output. XOR undone, "
                                    "bytes unshuffled, padding removed."])
        except CipherError as p9_error:
            try:
                phases, message = _phases_from_8(text, key)
            except CipherError:
                raise p9_error from None
    if phases is None:
        phases, message = _phases_from_8(text, key)
    if 9 not in ph:
        ph[9] = Phase("This ciphertext didn't use Phase 9.", status="skipped")
    ph.update(phases)
    for i in range(9):
        ph[i].notes.insert(0, f"Recovered. This matches Phase {i}'s output "
                              "from encryption.")

    result = {"kind": "text", "text": message}
    if message.startswith(FILE_TAG):
        try:
            raw = base64.b32decode(message[len(FILE_TAG):])
            name_b, sep, data = raw.partition(b"\0")
            if sep:
                name = os.path.basename(name_b.decode("utf-8")) or "recovered-file"
                result = {"kind": "file", "name": name, "data": data}
        except (ValueError, UnicodeDecodeError):
            pass

    if result["kind"] == "file":
        body = (f"Recovered file: {result['name']}\n"
                f"Size: {len(result['data']):,} bytes\n\n"
                "Use Save original file… to write it to disk.")
        try:
            preview = result["data"][:4000].decode("utf-8")
            body += "\n\nPreview:\n" + preview
        except UnicodeDecodeError:
            body += "\n\n(Binary file, no text preview.)"
        ph[10] = Phase(body, ["The file comes back byte for byte, including "
                              "lowercase letters."])
    else:
        ph[10] = Phase(message, ["Letters come back as capitals, because Phase 1 "
                                 "works in uppercase."])
    return ph, result


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
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
            self.current = 10
            self.loaded = None       # {"name": str, "data": bytes}
            self.recovered = None    # decrypt result
            self.last_mode = None
            self.mode = tk.StringVar(value=start_mode)
            self.use_p9 = tk.BooleanVar(value=True)
            self.show_key = tk.BooleanVar(value=False)
            self._setup_fonts()
            self._setup_style()
            self._build()
            self._bind()
            self._set_mode()
            self._refresh_list()
            self.show_phase(10)

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
            s.configure("TEntry", fieldbackground=FIELD, padding=6)
            s.configure("TPanedwindow", background=BG)
            s.configure("Vertical.TScrollbar", background=PANEL, troughcolor=BG,
                        arrowcolor=MUTED)

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
            ttk.Button(in_head, text="Open file…", command=self.open_file).pack(
                side="right", padx=(0, 6))

            box, self.input = self._text(left, width=36, height=14)
            box.pack(fill="both", expand=True)
            self.count_label = ttk.Label(left, text="0 characters", style="Muted.TLabel",
                                         wraplength=300, justify="left")
            self.count_label.pack(anchor="w", pady=(4, 0))

            ttk.Label(left, text="Secret key (32 hex characters)",
                      style="Head.TLabel").pack(anchor="w", pady=(16, 6))
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

            self.p9_check = ttk.Checkbutton(
                left, text="Use Phase 9 (1024-bit finalized encoding)",
                variable=self.use_p9)
            self.p9_check.pack(anchor="w", pady=(14, 0))

            self.run_button = ttk.Button(left, style="Run.TButton", command=self.run)
            self.run_button.pack(fill="x", pady=(16, 0))
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
            self.root.bind("<Control-Return>", lambda e: self.run())
            self.root.bind("<Control-o>", lambda e: self.open_file())

        def _rewrap(self, event):
            width = max(event.width - 10, 200)
            self.v_desc.configure(wraplength=width)
            self.v_notes.configure(wraplength=width)

        # ---- state ----
        def _set_mode(self):
            enc = self.mode.get() == "encrypt"
            for b in self.mode_buttons:
                selected = b.cget("value") == self.mode.get()
                b.configure(fg="#FFFFFF" if selected else INK)
            self.root.title(f"{APP_NAME} {'Encrypt' if enc else 'Decrypt'}")
            self.run_button.configure(text="Encrypt" if enc else "Decrypt")
            self.input_label.configure(text="Message" if enc
                                       else "Ciphertext")
            self.p9_check.configure(state="normal" if enc else "disabled")
            self.key_hint.configure(
                text="Leave empty to create a new key." if enc
                else "Use the same key that encrypted the message.")

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
            for i, (name, _) in enumerate(PHASES):
                res = self.results.get(i)
                mark = {"done": "●", "skipped": "–"}[res.status] if res else "○"
                num = str(i) if i < 10 else " "
                self.rail.insert("end", f" {mark} {num}  {name}")
                done = res is not None and res.status == "done"
                self.rail.itemconfigure(i, foreground=INK if done else MUTED)
            self.rail.selection_set(self.current)

        def _on_select(self, _event):
            sel = self.rail.curselection()
            if sel:
                self.show_phase(sel[0])

        def show_phase(self, i):
            self.current = i
            name, desc = PHASES[i]
            self.v_title.configure(text=(f"Phase {i}: " if i < 10 else "") + name)
            self.v_desc.configure(text=desc)
            res = self.results.get(i)
            if res is None:
                body, notes = "", "Nothing here yet. Enter a message or open a file, then run it."
            else:
                body = res.output
                notes = "\n".join(res.notes)
                if len(body) > MAX_VIEW_CHARS:
                    body = (body[:MAX_VIEW_CHARS] + f"\n\n[Showing the first "
                            f"{MAX_VIEW_CHARS:,} of {len(res.output):,} characters. "
                            "Copy or Save includes everything.]")
            self.v_notes.configure(text=notes)
            self.output.configure(state="normal")
            self.output.delete("1.0", "end")
            self.output.insert("1.0", body)
            self.output.configure(state="disabled")

        # ---- files and keys ----
        def open_file(self):
            if self.mode.get() == "decrypt":
                types = [("CYS-ENC26 locked files", "*.cys"), ("All files", "*")]
            else:
                types = [("All files", "*")]
            path = filedialog.askopenfilename(title="Open a file", filetypes=types)
            if not path:
                return
            try:
                size = os.path.getsize(path)
                if size > MAX_FILE_BYTES:
                    messagebox.showerror(APP_NAME, "That file is larger than 2 MB. CYS-ENC26 "
                                         "grows data about 11 times across its phases, "
                                         "so larger files use too much memory.")
                    return
                if size > SLOW_FILE_BYTES and not messagebox.askyesno(
                        APP_NAME, f"This file is {size / 1024:,.0f} KB. Running "
                        "it through every phase may take up to a minute.\n\nContinue?"):
                    return
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError as e:
                messagebox.showerror(APP_NAME, f"Couldn't open the file.\n\n{e}")
                return
            self.loaded = {"name": os.path.basename(path), "data": data}
            self.input.configure(state="normal")
            self.input.delete("1.0", "end")
            self.input.insert("1.0", f"{self.loaded['name']}\n\nThis file will be "
                              "used as the input. Select Remove file to type a "
                              "message instead.")
            self.input.configure(state="disabled", fg=MUTED)
            self.count_label.configure(
                text=f"File loaded: {self.loaded['name']} ({len(data):,} bytes)")
            self.clear_button.configure(text="Remove file")
            self._set_status("File loaded.")

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
            label = f"phase{self.current}" if self.current < 10 else "final"
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
                self._write(path, self.results[10].output, "Locked file saved.")
            elif self.recovered and self.recovered["kind"] == "file":
                path = filedialog.asksaveasfilename(
                    title="Save original file", initialfile=self.recovered["name"])
                if path:
                    self._write(path, self.recovered["data"], "Original file saved.")
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
            for i, (name, desc) in enumerate(PHASES):
                res = self.results.get(i)
                title = f"Phase {i}: {name}" if i < 10 else name
                lines += ["=" * 72, title, "=" * 72, desc]
                if res:
                    lines += [f"Note: {n}" for n in res.notes]
                    lines += ["", res.output or "(no output)"]
                lines.append("")
            path = filedialog.asksaveasfilename(
                title="Save report", defaultextension=".txt",
                initialfile="cys-enc26-report.txt")
            if path:
                self._write(path, "\n".join(lines), "Report saved.")

        # ---- running ----
        def run(self):
            if str(self.run_button.cget("state")) == "disabled":
                return
            mode = self.mode.get()
            loaded = self.loaded
            text = None if loaded else self.input.get("1.0", "end-1c")
            key_text = self.key_entry.get().strip()

            if mode == "decrypt":
                if loaded:
                    try:
                        text = loaded["data"].decode("utf-8")
                    except UnicodeDecodeError:
                        self._set_status("That file isn't CYS-ENC26 ciphertext.", RED)
                        return
                if not text.strip():
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

            self.run_button.configure(state="disabled")
            self._set_status("Encrypting…" if mode == "encrypt" else "Decrypting…")
            use_p9 = self.use_p9.get()

            def work():
                try:
                    if mode == "encrypt":
                        if loaded:
                            result = (encrypt(key, use_p9,
                                              file=(loaded["name"], loaded["data"])), None)
                        else:
                            result = (encrypt(key, use_p9, text=text), None)
                    else:
                        result = decrypt(text, key)
                    self.root.after(0, self._finish, mode, result, loaded, None)
                except Exception as e:   # shown to the user, not raised
                    self.root.after(0, self._finish, mode, None, loaded, e)

            threading.Thread(target=work, daemon=True).start()

        def _finish(self, mode, result, loaded, error):
            self.run_button.configure(state="normal")
            if error is not None:
                self._set_status(str(error), RED)
                return
            self.results, self.recovered = result
            self.last_mode = mode
            self.encrypted_name = loaded["name"] if loaded else None
            self.current = 10
            self._refresh_list()
            self.show_phase(10)
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
    root.geometry("1320x800")
    root.minsize(1100, 640)
    app = App(root)
    app.encrypted_name = None
    root.mainloop()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cys_enc26", description=f"{APP_NAME} {VERSION}")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], default="encrypt")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    args = parser.parse_args(argv)
    run_gui(args.mode)


if __name__ == "__main__":
    main()
