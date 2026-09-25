# Changelog

## 2.1.0.0 (2026-09-25)

- New CYS-ENC26-FOLD window (`cys26 fold`): password-lock a folder or file.
  The moment a password is set the item is packed and encrypted to a single
  `.f.cys26` file, so a file browser or the shell shows no contents until it
  is unlocked. Restored byte for byte with the right password.
- The secret key is derived from the password: PBKDF2-HMAC-SHA256 (600,000
  rounds, per-lock salt), then the ASCII (hex) form of the hash; the first 32
  characters are the 128-bit CYS key, so a lock also opens in `cys26 dec`.
- Five wrong passwords within 12 hours re-encrypt the item with a discarded
  128-character random key, making it unrecoverable by design.
- Optional self-destruct code: a second password that re-encrypts with a
  discarded key and then securely wipes and deletes only the `.f.cys26` file.
- Opening a `.f.cys26` file shows "THIS FILE IS LOCKED" and prompts to unlock
  (a registered file type / MIME handler); custom file icon.
- Lock records live in `~/.local/state/cys-enc26/fold`, left alone by install,
  update and uninstall.

## 2.0.0.0 (2026-09-24)

- New Phase 8.5: the Phase 8 output is compressed with LZMA2, so locked files
  are about 1.75 times the original instead of about 11 times.
- Phase 9 block size can be chosen: 64, 1024, 2048, 8192, 16384, 131072,
  524288 or 1048576 bits (1024 is the default). The two largest show a size
  warning.
- New optional Phase 10: the output written as 8-bit binary groups, 8 per
  line, with an optional compact save that packs the bits back into bytes.
- Files are encrypted in 512 KB parts on up to 8 CPU cores, with a progress bar
  and a Cancel button. Memory stays around 130 MB per core at any file size.
- File limit raised from 2 MB to 800 MB (90 MB with Phase 10 and no compact
  save), with an option to go over it after a warning.
- Fixed: the decrypt window refused locked files over 2 MB.
- Locked files from 1.0.0.0 still decrypt. Files made by 2.0.0.0 don't open
  in 1.0.0.0.

## 1.0.0.0 (2026-09-23)

- First release.
- Phases 0 to 9, all reversible, with or without Phase 9.
- Phase 1 symbol codes: - = 1001, | = 1011, + = 1010, = = 1100, _ = 1111.
- File encryption to `.locked.rl.cys` files, restored byte for byte on decryption.
- `cys26 enc`, `cys26 dec`, `cys26 update`, `cys26 version` and `cys26 uninstall`.
