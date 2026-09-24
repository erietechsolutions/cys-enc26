# CYS-ENC26 project context

CYS-ENC26 is a custom, phase-based encryption method designed as a learning
project, plus a Tkinter desktop app for Fedora Linux that shows the output of
every phase when encrypting and decrypting. It is not meant to protect real
secrets (AES-256-GCM or ChaCha20-Poly1305 are the right tools for that).

Current version: see `VERSION` (1.0.0.0 at handoff, tagged `v1.0.0.0`).

## How the spec is written

Condensed, uppercase phase blocks, for example:

```
PHASE 7: LETTER SHIFT
A-B
...
THE LETTER I IS DIFFERENT
I = 111111
```

## Current spec (all phases reversible, with or without Phase 9)

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

PHASE 9 (OPTIONAL): FINALIZED ENCODING
PHASE 8 OUTPUT AS UTF-8 BYTES, 4-BYTE BIG-ENDIAN LENGTH PREFIX,
RANDOM PADDING UP TO THE NEXT 128-BYTE (1024-BIT) BLOCK
RANDOM 16-BYTE NONCE PER MESSAGE
GENERATOR: HMAC-SHA256(KEY, LABEL + NONCE + 8-BYTE BIG-ENDIAN COUNTER)
FISHER-YATES SHUFFLE OF BYTE POSITIONS (LABEL "CYS-ENC26 shuffle",
LITTLE-ENDIAN UINT32 WORDS, REJECTION SAMPLING)
THEN XOR WITH A SECOND STREAM (LABEL "CYS-ENC26 xor")
OUTPUT: BASE64(NONCE + DATA), NO READABLE HEADER
DECRYPTOR RECOGNISES PHASE 9 BY ITS SHAPE, FALLS BACK TO PLAIN PHASE 8
```

## Implementation decisions

- Binary codes travel through the phases as private-use characters
  (U+E000-U+E03F) so no phase treats their 0s and 1s as digits; they're
  displayed as binary. Messages containing those characters are rejected.
- Phase 2 injection positions come from HMAC-SHA256(key, "CYS-ENC26 inject" +
  total length) with rejection sampling. The injected characters double as a
  wrong-key check during decryption.
- Files are encrypted as `FILE|` + base32(filename + NUL byte + file bytes), so
  they come back byte for byte. Encrypted files export as
  `<name>.locked.rl.cys`. File limit is 2 MB (data grows about 11x; a 2 MB file
  takes about 30 seconds and 1 GB of RAM).
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
bin/cys26             CLI: enc, dec, update, version, uninstall
src/cys_enc26.py      engine + Tkinter GUI (--mode encrypt|decrypt)
assets/cys-enc26.svg
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

The engine can be driven without the GUI:

```python
import cys_enc26 as c
key = c.generate_key()
ct = c.encrypt(key, use_phase9=True, text="HELLO")[10].output
phases, result = c.decrypt(ct, key)   # result["text"], or result["name"]/["data"] for files
```

Testing done before 1.0.0.0: 3,000 random text round trips (with and without
Phase 9), each phase's recovered output matching encryption; 400 random binary
file round trips plus a full GUI flow; installer, `cys26 version`,
`cys26 update` (against a simulated GitHub server) and `cys26 dec` window
launch.

## Working in the Claude project copy

The copy at `/mnt/project-files/cys-enc26` lives on a shared folder that
doesn't keep executable bits and adds provenance metadata to SVG files. The
repo there has `core.fileMode false` and `assets/cys-enc26.svg` marked
`skip-worktree`, so neither shows up in `git status` or gets committed. The
committed modes and SVG in history are the correct ones.

## Next steps

1. Push to GitHub: create an empty public repo `cys-enc26`, then run
   `./tools/set-repo.sh <username>` and `git push -u origin main --tags`.
2. Install with
   `curl -fsSL https://raw.githubusercontent.com/<username>/cys-enc26/main/install.sh | bash`.
3. Possible improvements: codes for more symbols, lowercase support for typed
   messages, faster handling of large files.
