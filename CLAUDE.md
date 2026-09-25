# CYS-ENC26 project context

CYS-ENC26 is a custom, phase-based encryption method designed as a learning
project, plus a Tkinter desktop app for Fedora Linux that shows the output of
every phase when encrypting and decrypting. It is not meant to protect real
secrets (AES-256-GCM or ChaCha20-Poly1305 are the right tools for that).

Current version: see `VERSION` (1.0.0.0 at handoff, tagged `v1.0.0.0`; 2.0.0.0 adds
Phases 8.5 and 10, Phase 9 block sizes and multi-part files; 2.1.0.0 adds
CYS-ENC26-FOLD, the password-locked-folder window).

## How the spec is written

Condensed, uppercase phase blocks, for example:

```
PHASE 7: LETTER SHIFT
A-B
...
THE LETTER I IS DIFFERENT
I = 111111
```

## Current spec (all phases reversible, whichever optional phases are used)

```
PHASE 0: KEY AND WATERMARK
RANDOM 128-BIT SECRET KEY
WATERMARK "CYSEN26:" ADDED TO THE START OF THE INPUT (ENCRYPTED WITH EVERYTHING ELSE)

PHASE 1: BASIC CRYPTO SCRAMBLE
INPUT IS UPPERCASED FIRST
A=0 B=1 C=2 D=3 E=4 F=5 G=6 H=7 I=8 J=9
K=A L=B M=C N=D O=E P=F Q=G R=H S=I T=J U=K V=L W=M X=N Y=O Z=P
1=Q 2=R 3=S 4=T 5=U 6=V 7=W 8=X 9=Y 0=Z
SYMBOLS BECOME 4-BIT CODES
- = 1001   | = 1011   + = 1010   = = 1100   _ = 1111
OTHER CHARACTERS PASS THROUGH UNCHANGED

PHASE 2: NUMBERED ENCRYPTION CYCLE
FIRST AND LAST BYTE OF THE KEY (4 HEX CHARACTERS) INJECTED AT 4 POSITIONS
FROM THE KEY AND THE TOTAL LENGTH
EACH CHARACTER BECOMES A NUMBER, JOINED BY DASHES
A1 B2 C4 D8 E16 F32 G64 H128 I256 J512 K1024 L2048 M4096 N8192 O16384
P3 Q5 R6 S7 T9 U10 V11 W12 X13 Y14 Z15
1-9 = 17-25   0 = 26

PHASE 3: FINAL SCRAMBLE
DASHES REMOVED
EACH NUMBER DOUBLED AND WRITTEN AS EXACTLY 5 DIGITS (2 = 00002)
0=A 4=D 8=E 9=X

PHASE 4: NUMBER SHIFT
EVEN +2, ODD X3
1-3 2-4 3-9 5-15 6-8 7-21

PHASE 5: ODD DIVISION
EACH ODD NUMBER FROM PHASE 4 / 1.5, ROUNDED UP
3-2 9-6 15-10 21-14

PHASE 6: NUMBERS TO LETTERS
EACH DIGIT BECOMES A RANDOM LETTER FROM ITS SET
1=B/C 2=F/G 3=H/I 4=J/K 5=L/M 6=N/O 7=P/Q 8=R/S 9=T/U 0=V/W/Y/Z
A, D, E AND X FROM PHASE 3 STAY AS THEMSELVES
SYMBOLS BECOME 6-BIT CODES
SPACE=000000 !=100000 @=000010 #=000110 $=110000 %=111000 ^=011110
&=111110 *=110110 (=100110 )=100010 ?=111100 .=001111 ,=100001 :=001010

PHASE 7: LETTER SHIFT
EVERY LETTER MOVES FORWARD ONE (Z-A)
THE LETTER I IS DIFFERENT
I = 111111

PHASE 8: BINARY TO NUMBER
EVERY BINARY CODE BECOMES A 2-DIGIT NUMBER
6-BIT CODES USE 00-63 (I = 63)
PHASE 1 4-BIT CODES ADD 64 SO THEY CAN'T COLLIDE
- = 73   + = 74   | = 75   = = 76   _ = 79

PHASE 8.5: COMPRESSION
PHASE 8 OUTPUT AS UTF-8 BYTES
COMPRESSED WITH RAW LZMA2, PRESET 6, NO HEADER
DECRYPTOR: FIRST BYTE 1, 2 OR 128+ IS LZMA2
A CAPITAL LETTER MEANS UNCOMPRESSED VERSION 1 PHASE 8 OUTPUT

PHASE 9 (OPTIONAL): FINALIZED ENCODING
PHASE 8.5 OUTPUT, 4-BYTE BIG-ENDIAN LENGTH PREFIX,
RANDOM PADDING UP TO THE NEXT BLOCK
BLOCK SIZE CHOSEN BY THE USER
64 1024 2048 8192 16384 131072 524288 1048576 BITS, DEFAULT 1024
524288 AND 1048576 SHOW A SIZE WARNING
RANDOM 16-BYTE NONCE PER MESSAGE OR PART
GENERATOR: HMAC-SHA256(KEY, LABEL + NONCE + 8-BYTE BIG-ENDIAN COUNTER)
FISHER-YATES SHUFFLE OF BYTE POSITIONS (LABEL "CYS-ENC26 shuffle",
LITTLE-ENDIAN UINT32 WORDS, REJECTION SAMPLING)
THEN XOR WITH A SECOND STREAM (LABEL "CYS-ENC26 xor")
OUTPUT: NONCE + DATA, NO READABLE HEADER
BLOCK SIZE IS NOT STORED: THE LENGTH PREFIX SAYS WHERE THE DATA ENDS
DECRYPTOR RECOGNISES PHASE 9 BY ITS SHAPE (BODY A MULTIPLE OF 8 BYTES)

PHASE 10 (OPTIONAL): BINARY
EVERY BYTE WRITTEN AS 8 BITS
GROUPS SEPARATED BY A SPACE, 8 GROUPS (64 BITS) PER LINE
A = 01000001
COMPACT SAVE (OPTIONAL): THE SAVED FILE STORES THE BYTES INSTEAD

TEXT OUTPUT
PHASE 10 BINARY IF USED, OTHERWISE BASE64
```

## CYS-ENC26-FOLD (2.1.0.0, src/cys_fold.py)

A second Tkinter window (`cys26 fold`) that password-locks a folder or file. It
reuses the engine (`encrypt_file`, `decrypt_file`, `parse_key`, `Options`); no
phase changes. `src/cys_fold.py` is both the engine (importable functions) and
the GUI (`run_gui`).

```
PHASE F1: PASSWORD HASH
PASSWORD AS UTF-8, RANDOM 16-BYTE SALT PER LOCK
PBKDF2-HMAC-SHA256, 600000 ROUNDS -> 32-BYTE HASH

PHASE F2: ASCII HASH TO KEY
HASH AS UPPERCASE HEX (64 ASCII CHARS)
CYS KEY = FIRST 32 CHARS (128 BIT), SO IT ALSO OPENS IN cys26 dec

PHASE F3: LOCK
FOLDER PACKED INTO ONE UNCOMPRESSED TAR (dereference=False)
TAR (OR THE FILE) RUN THROUGH encrypt_file -> <PATH>.f.cys26
ORIGINAL REMOVED ONLY AFTER THE .f.cys26 IS FULLY WRITTEN
UNLOCK: decrypt_file -> TAR EXTRACTED WITH filter="data" -> RESTORED IN PLACE

WRONG-TRY COUNTER
fails = LIST OF ISO TIMESTAMPS, PRUNED TO A ROLLING 12-HOUR WINDOW
5 WRONG TRIES IN THE WINDOW -> LOCKOUT RE-ENCRYPT

LOCKOUT / SELF-DESTRUCT (DISCARDED KEY)
RANDOM 128-CHAR PASSWORD (>=14 UPPER, 10 LOWER, 8 DIGIT, 4 SYMBOL)
HASHED -> KEY, RE-ENCRYPT THE .f.cys26, STORE ONLY THE NEW salt/check
PASSWORD AND KEY NEVER STORED -> UNRECOVERABLE
SELF-DESTRUCT: SECOND PASSWORD -> LOCKOUT RE-ENCRYPT, THEN OVERWRITE THE
  .f.cys26 ONCE WITH RANDOM BYTES AND DELETE IT (ONLY THAT FILE), RECORD
  MARKED state "destroyed"

OPENING A .f.cys26
MIME TYPE application/x-cys-enc26-folder, HANDLED BY cys-enc26-fold.desktop
SHOWS "THIS FILE IS LOCKED", THEN THE UNLOCK PASSWORD PROMPT
```

GUI threading (2.1.1.0): lock, unlock and self-destruct run on a background
thread via `run_bg`, with a modal progress bar (driven by the engine's
`progress(done, parts)` callback through `root.after`) and a Cancel button (a
`threading.Event` passed as the engine's `cancel`). The Tk main thread never
blocks on encryption, so the window stays closable. `lock_folder` writes the
record (with the salt) BEFORE deleting the original, so an interruption can
never strand a `.f.cys26` whose salt was never saved. `scan_recovery()` runs at
startup: it promotes a leftover `.rec-*.tmp` back into a real record when its
`.f.cys26` exists, removes useless temps, and flags "half-finished" locks where
both the original and its `.f.cys26` still exist.

Records: one JSON per lock in `~/.local/state/cys-enc26/fold/<id>.json` (dir
700, files 600), written atomically. Not in `~/.local/share/cys-enc26` or
`~/.cache/cys-enc26` because install and uninstall wipe those. `CYS_FOLD_STATE`
overrides the location (tests use it). `check = SHA-256(label + hash)`; the
password is never stored. Self-destruct uses its own salt/check and label.

Honest limits (documented in the README): no `cd`/file-manager auto-prompt (a
plain app can't hook filesystem access); the counter is an editable JSON file
so the real protection is PBKDF2 + password strength; secure-wipe is best
effort (SSD wear-levelling, trash, journals, backups); shell execution of a
`.f.cys26` can't be intercepted.

## File format (version 2)

```
FILES ARE SPLIT INTO 512 KB PARTS
EACH PART: FILEPART|<PART>|<PARTS>| + BASE32(DATA)
PART 0 DATA STARTS WITH THE FILE NAME AND A NUL BYTE
EACH PART RUNS THROUGH PHASES 0-10 ON ITS OWN
PHASE 2 POSITIONS: HMAC(KEY, "CYS-ENC26 inject" + LENGTH + PART NUMBER)
LOCKED FILE: EACH PART AS 4-BYTE BIG-ENDIAN LENGTH + BYTES
PHASE 10 WITHOUT COMPACT SAVE: EACH PART AS BINARY TEXT, BLANK LINE BETWEEN
TYPED MESSAGES: ONE PART (PART 0), SAVED AS TEXT UNLESS COMPACT SAVE
LIMITS: 800 MB, 90 MB WITH PHASE 10 AND NO COMPACT SAVE, BYPASS WITH A WARNING
```

## Implementation decisions

- Binary codes travel through the phases as private-use characters
  (U+E000-U+E03F) so no phase treats their 0s and 1s as digits; they're
  displayed as binary. Messages containing those characters are rejected.
- Phase 2 injection positions come from HMAC-SHA256(key, "CYS-ENC26 inject" +
  total length) with rejection sampling. The injected characters double as a
  wrong-key check during decryption.
- Version 1 files were `FILE|` + base32(filename + NUL byte + file bytes) in
  one piece, with Phase 2 positions from the length only. Version 2 decrypts
  them (and version 1 messages) by trying the version 1 rules when the
  version 2 ones don't fit; `tests/fixtures/v1-ciphertexts.json` holds real
  1.0.0.0 ciphertexts.
- Parts run on up to 8 processes (spawn start method), about 130 MB of
  memory each. Encrypting is about 12.5 s per MB on one core, most of it LZMA
  preset 6; lower presets are much faster but miss the 1.5 GB goal.
- The GUI streams files through `~/.cache/cys-enc26/work/<pid>/` and moves the
  result on Save. Cancel or a failure deletes the partial file.
- Typed messages come back in capitals because Phase 1 uppercases.
- Symbols without a code (for example `/`, `'`, newline) pass through
  unencrypted. There are unused 6-bit codes available for more symbols.

## Repository layout

```
VERSION               current version
CHANGELOG.md
README.md
cys26.conf            REPO="YOUR-GITHUB-USERNAME/cys-enc26", BRANCH="main"
install.sh            user install to ~/.local/share/cys-enc26, links ~/.local/bin/cys26,
                      app menu entry, installs python3-tkinter if missing
uninstall.sh
bin/cys26             CLI: enc, dec, fold, update, version, uninstall
src/cys_enc26.py      engine + Tkinter GUI (--mode encrypt|decrypt)
src/cys_fold.py       CYS-ENC26-FOLD engine + Tkinter GUI (cys26 fold [path])
tests/                unittest round trips, version 1 fixtures, FOLD tests
assets/cys-enc26.svg
assets/cys-enc26-fold.svg  FOLD app + .f.cys26 file-type icon
tools/set-repo.sh     sets GitHub username everywhere + git remote
tools/bump-version.sh major|minor|patch|build "note": bumps VERSION,
                      updates CHANGELOG, commits, tags vX.X.X.X
```

`cys26 update` reads `VERSION` from
`raw.githubusercontent.com/<REPO>/<BRANCH>/VERSION`, compares with `sort -V`,
and if newer downloads the branch tarball and runs its `install.sh --quiet`.
Otherwise it prints "CYS-ENC26 is already up to date (version X)".

## Versioning

`MAJOR.MINOR.PATCH.BUILD`, starting at 1.0.0.0. Release with
`tools/bump-version.sh <part> "note"`:

- major: incompatible changes (old ciphertext won't decrypt)
- minor: new features
- patch: bug fixes
- build: small tweaks (text, styling, docs)

## Testing

```bash
python3 -m unittest discover -s tests
```

The engine can be driven without the GUI:

```python
import cys_enc26 as c
key = c.generate_key()
opts = c.Options(use_phase9=True, block_bits=1024, use_phase10=False, compact=False)
ct = c.encrypt(key, "HELLO", opts)["final"].output
phases, result = c.decrypt(ct, key)          # result["text"]
ph, locked = c.encrypt_bytes(key, "a.bin", data, opts)
phases, result = c.decrypt_bytes(key, locked)  # result["name"], result["data"]
```

Phase results are keyed "0" to "8", "8.5", "9", "10" and "final". Worker
processes use spawn, so scripts that call the engine with more than one
worker need an `if __name__ == "__main__":` guard.

Testing done before 1.0.0.0: 3,000 random text round trips (with and without
Phase 9), each phase's recovered output matching encryption; 400 random binary
file round trips plus a full GUI flow; installer, `cys26 version`,
`cys26 update` (against a simulated GitHub server) and `cys26 dec` window
launch. For 2.0.0.0: the unittest suite, plus a headless GUI run (Xvfb)
covering messages, multi-part files, Phase 10, compact save, block size and
bypass warnings, cancel and version 1 files. For 2.1.0.0: the unittest suite
(15 FOLD tests: derivation vector, check/verify, record round trip, folder /
empty-folder / single-file / symlink round trips, wrong-password, restore
conflict, window pruning, 5-try lockout, lockout password classes,
self-destruct wiping only the .f.cys26, recovery key), plus a headless (Xvfb)
launch of the FOLD window and of opening a locked .f.cys26.

## Working in the Claude project copy

The copy at `/mnt/project-files/cys-enc26` lives on a shared folder that
doesn't keep executable bits and adds provenance metadata to SVG files. The
repo there has `core.fileMode false` and `assets/cys-enc26.svg` marked
`skip-worktree`, so neither shows up in `git status` or gets committed. The
committed modes and SVG in history are the correct ones.

## Next steps

- Tags can't be pushed from Claude's cloud sessions; push them from a local
  checkout after merging (`git tag -a vX.X.X.X <commit> -m "Version X.X.X.X"`).
- Possible improvements: codes for more symbols, lowercase support for typed
  messages, faster phases (Phase 6 and LZMA are the slow parts).
