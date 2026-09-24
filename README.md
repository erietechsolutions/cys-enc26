# CYS-ENC26

A custom, phase-based encryption method with a desktop app that shows what
every phase does to your data, in both directions. Built for Fedora Linux.

> CYS-ENC26 is a learning project. It hasn't been reviewed by cryptographers,
> so don't rely on it to protect real secrets. Use AES-256-GCM or
> ChaCha20-Poly1305 for that.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/erietechsolutions/cys-enc26/main/install.sh | bash
```

Or from a downloaded copy:

```bash
git clone https://github.com/erietechsolutions/cys-enc26.git
cd cys-enc26
./install.sh
```

The installer puts CYS-ENC26 in `~/.local/share/cys-enc26`, adds the `cys26`
command to `~/.local/bin`, adds an app menu entry, and installs
`python3-tkinter` if it's missing (this asks for your password).

## Commands

| Command | What it does |
|---|---|
| `cys26 enc` | Opens the encryption window |
| `cys26 dec` | Opens the decryption window |
| `cys26 update` | Checks GitHub for a newer version and installs it |
| `cys26 version` | Shows the installed version |
| `cys26 uninstall` | Removes CYS-ENC26 (keys and locked files are kept) |

## Using the app

**Encrypting.** Type a message or use *Open file…*. Leave the key empty to
create a new one, and use *Save…* next to the key to keep it. Pick the
options you want, select *Encrypt*, then *Save locked file…* to export a
`.locked.rl.cys` file.

| Option | What it does |
|---|---|
| Use Phase 9, block size | Keyed shuffle and XOR, padded to the chosen block size. 524288 and 1048576 bits ask first, because even a one-word message becomes about 87 KB or 175 KB. |
| Use Phase 10 | Writes the output as 8-bit binary groups, 8 to a line. |
| Compact save | With Phase 10, packs the bits back into bytes in the saved file, so it's 9 times smaller. The window still shows the binary. |
| Allow files over the size limit | Lets bigger files through after a warning about size, time and disk space. |

**Decrypting.** Paste the ciphertext or open a `.locked.rl.cys` file, enter
the same key, and select *Decrypt*. There's nothing to pick: the phases that
were used are recognised from the ciphertext. Files come back exactly as they
were, with their original name; use *Save original file…*. Typed messages
come back in capitals. Locked files made by version 1.0.0.0 still decrypt.

Select any phase in the list to see its output and notes. *Save report…*
writes every phase to one text file.

**File sizes.** Files are encrypted in 512 KB parts on up to 8 CPU cores, with
a progress bar and *Cancel*. A locked file is about 1.75 times the original
(about 16 times with Phase 10 and no compact save). To keep locked files under
about 1.5 GB, the limit is 800 MB, or 90 MB with Phase 10 and no compact save.
Encrypting takes about 12 seconds per MB on one core. For big files the phase
view shows part 1, since every part goes through the same phases.

## The phases

| Phase | Rule |
|---|---|
| 0 | A random 128-bit key; `CYSEN26:` is added to the start of the input |
| 1 | A→0 … J→9, K→A … Z→P, 1→Q … 9→Y, 0→Z; `-`=1001, `\|`=1011, `+`=1010, `=`=1100, `_`=1111 |
| 2 | Key's first and last byte injected at key-chosen positions; characters become numbers (A=1, B=2, C=4 … 0=26) |
| 3 | Dashes removed; numbers doubled and written as 5 digits; 0→A, 4→D, 8→E, 9→X |
| 4 | Even digits +2, odd digits ×3 |
| 5 | Each odd number from Phase 4 ÷ 1.5, rounded up |
| 6 | Digits become random letters (1=B/C, 2=F/G, 3=H/I, 4=J/K, 5=L/M, 6=N/O, 7=P/Q, 8=R/S, 9=T/U, 0=V/W/Y/Z); symbols become 6-bit codes |
| 7 | Letters shift forward one (Z→A); I becomes 111111 |
| 8 | Binary codes become 2-digit numbers; 4-bit codes from Phase 1 add 64 |
| 8.5 | The Phase 8 output is compressed (LZMA2, no header) |
| 9 | Optional: keyed shuffle and XOR, padded to 64 to 1048576-bit blocks (HMAC-SHA256 generator) |
| 10 | Optional: every byte written as 8 bits, 8 groups per line |

Files are split into 512 KB parts, and each part is converted to base32 text
before Phase 0 so every byte survives.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Versions and updates

Versions use `MAJOR.MINOR.PATCH.BUILD`, starting at `1.0.0.0`. The current
version is in `VERSION`, and `CHANGELOG.md` lists what changed.

To release a new version:

```bash
tools/bump-version.sh patch "Fix the Phase 8 note"
git push && git push --tags
```

`cys26 update` compares the installed version with `VERSION` on the `main`
branch and installs the newer one. GitHub can take a few minutes to serve a
new `VERSION` file after a push.
