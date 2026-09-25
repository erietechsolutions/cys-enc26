#!/usr/bin/env python3
"""
CYS-ENC26-FOLD: password-locked folders (and single files) for CYS-ENC26.

Locking a folder packs it into one archive, encrypts it with the CYS-ENC26
phases and leaves a single ``.f.cys26`` file where the folder was, so a file
browser or the shell shows no contents until it is unlocked. The secret key is
derived from the ASCII (hex) form of the hashed password, so it also opens in
the normal ``cys26 dec`` window.

This is a learning tool built on the CYS-ENC26 phase engine, not a way to
protect real data. See the honest limits in the README.

The module is both the engine (import it and call the functions) and the FOLD
window (run it, optionally with a path to open).
"""

import base64
import hashlib
import json
import os
import secrets
import string
import sys
import tarfile
import tempfile
import threading
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cys_enc26 as engine

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
FOLD_EXT = ".f.cys26"           # encrypted folders / files locked by FOLD
PBKDF2_ROUNDS = 600_000         # PBKDF2-HMAC-SHA256 rounds, ~0.5 s per try
SALT_BYTES = 16
HASH_BYTES = 32                 # 64 ASCII hex chars; key uses the first 32
CHECK_LABEL = b"CYS-ENC26-FOLD check"
DESTRUCT_LABEL = b"CYS-ENC26-FOLD self-destruct"

MAX_TRIES = 5                   # wrong tries inside the window before lockout
WINDOW_HOURS = 12               # rolling window the wrong tries are counted in

# Auto-generated lockout password: length and minimum character classes.
LOCKOUT_LEN = 128
LOCKOUT_MIN_UPPER = 14
LOCKOUT_MIN_LOWER = 10
LOCKOUT_MIN_DIGIT = 8
LOCKOUT_MIN_SYMBOL = 4
LOCKOUT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

RECORD_VERSION = 1


# --------------------------------------------------------------------------
# Where lock records live
# --------------------------------------------------------------------------
def state_dir():
    """The folder that holds one JSON record per lock.

    Uses ~/.local/state/cys-enc26/fold, which install and uninstall leave
    alone (unlike ~/.local/share/cys-enc26 and ~/.cache/cys-enc26). Overridable
    with CYS_FOLD_STATE for tests. Created private (0700) if missing.
    """
    override = os.environ.get("CYS_FOLD_STATE")
    if override:
        base = override
    else:
        xdg = os.environ.get("XDG_STATE_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "state")
        base = os.path.join(xdg, "cys-enc26", "fold")
    os.makedirs(base, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def _record_path(lock_id):
    return os.path.join(state_dir(), f"{lock_id}.json")


def new_id():
    return secrets.token_hex(4)


def write_record(rec):
    """Write a record atomically (temp file, fsync, rename) with 0600 files."""
    path = _record_path(rec["id"])
    fd, tmp = tempfile.mkstemp(dir=state_dir(), prefix=".rec-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(rec, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path


def read_record(lock_id):
    with open(_record_path(lock_id)) as fh:
        return json.load(fh)


def list_records():
    """Every readable record, newest first."""
    recs = []
    for name in os.listdir(state_dir()):
        if name.endswith(".json"):
            try:
                with open(os.path.join(state_dir(), name)) as fh:
                    recs.append(json.load(fh))
            except (OSError, ValueError):
                continue
    recs.sort(key=lambda r: r.get("created", ""), reverse=True)
    return recs


def delete_record(lock_id):
    try:
        os.remove(_record_path(lock_id))
    except FileNotFoundError:
        pass


def find_by_locked_path(path):
    """The record whose locked file is `path`, or None."""
    target = os.path.abspath(path)
    for rec in list_records():
        if os.path.abspath(rec.get("locked_path", "")) == target:
            return rec
    return None


# --------------------------------------------------------------------------
# Step 1: password hash and key (Phases F1/F2)
# --------------------------------------------------------------------------
def derive(password, salt, rounds=None):
    """PHASE F1/F2: password -> (32-byte hash, 16-byte CYS key).

    F1: PBKDF2-HMAC-SHA256(password, salt, rounds) -> 32 bytes.
    F2: hash as uppercase hex (64 ASCII chars); the CYS key is the first 32
    of them (CYS keys are 128 bit / 32 hex), so it also works in cys26 dec.
    """
    if rounds is None:
        rounds = PBKDF2_ROUNDS
    if isinstance(password, str):
        password = password.encode("utf-8")
    hash_bytes = hashlib.pbkdf2_hmac("sha256", password, salt, rounds, dklen=HASH_BYTES)
    ascii_hex = hash_bytes.hex().upper()
    key = engine.parse_key(ascii_hex[:32])
    return hash_bytes, key


def _check(hash_bytes, label):
    return hashlib.sha256(label + hash_bytes).hexdigest()


def verify(rec, password, label=CHECK_LABEL, salt_field="salt", check_field="check"):
    """Return (ok, hash, key) for `password` against the stored check value."""
    salt = bytes.fromhex(rec[salt_field])
    hash_bytes, key = derive(password, salt, rec.get("rounds", PBKDF2_ROUNDS))
    expected = rec.get(check_field)
    ok = bool(expected) and secrets.compare_digest(_check(hash_bytes, label), expected)
    return ok, hash_bytes, key


def _options_from(rec):
    o = rec.get("options", {})
    return engine.Options(use_phase9=o.get("phase9", True),
                          block_bits=o.get("block_bits", engine.DEFAULT_BLOCK_BITS),
                          use_phase10=o.get("phase10", False),
                          compact=o.get("compact", False))


# --------------------------------------------------------------------------
# Step 2: lock and unlock a folder (or single file)
# --------------------------------------------------------------------------
def _tar_folder(folder, tar_path):
    """Pack `folder` into one uncompressed tar (Phase 8.5 compresses later).

    Symlinks are stored as links, not followed. Empty and nested folders are
    kept. The single top-level name is the folder's own name.
    """
    with tarfile.open(tar_path, "w", dereference=False) as tar:
        tar.add(folder, arcname=os.path.basename(folder.rstrip("/")))


def _extract_tar(tar_path, dest_parent):
    with tarfile.open(tar_path, "r") as tar:
        # filter="data" (3.11.4+/3.12) blocks absolute paths, .., device files.
        tar.extractall(dest_parent, filter="data")


def locked_path_for(path):
    return os.path.abspath(path.rstrip("/")) + FOLD_EXT


def _too_big(size, opts):
    return size > engine.file_limit(opts)


def lock_folder(path, password, selfdestruct=None, opts=None,
                progress=None, cancel=None, allow_over_limit=False):
    """Lock the folder (or file) at `path`.

    Packs it, encrypts it to ``<path>.f.cys26`` with the key from `password`,
    then removes the original only after the locked file is fully written.
    Writes and returns the lock record. `selfdestruct`, if given, is a second
    password that self-destructs the lock.
    """
    path = os.path.abspath(path.rstrip("/"))
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    is_folder = os.path.isdir(path)
    opts = opts or engine.Options()
    dest = locked_path_for(path)
    if os.path.exists(dest):
        raise FileExistsError(dest)

    salt = secrets.token_bytes(SALT_BYTES)
    hash_bytes, key = derive(password, salt)

    tmp_tar = None
    try:
        if is_folder:
            fd, tmp_tar = tempfile.mkstemp(prefix="cysfold-", suffix=".tar")
            os.close(fd)
            _tar_folder(path, tmp_tar)
            src = tmp_tar
        else:
            src = path
        if not allow_over_limit and _too_big(os.path.getsize(src), opts):
            raise ValueError("Over the size limit. Set allow_over_limit to lock it anyway.")
        engine.encrypt_file(key, src, dest, opts, progress=progress, cancel=cancel)
    finally:
        if tmp_tar and os.path.exists(tmp_tar):
            os.remove(tmp_tar)

    rec = {
        "version": RECORD_VERSION,
        "id": new_id(),
        "path": path,
        "kind": "folder" if is_folder else "file",
        "salt": salt.hex(),
        "rounds": PBKDF2_ROUNDS,
        "check": _check(hash_bytes, CHECK_LABEL),
        "selfdestruct_salt": None,
        "selfdestruct_check": None,
        "fails": [],
        "state": "locked",
        "locked_path": dest,
        "options": {"phase9": opts.use_phase9, "block_bits": opts.block_bits,
                    "phase10": opts.use_phase10, "compact": opts.compact},
        "created": _now(),
    }
    if selfdestruct:
        sd_salt = secrets.token_bytes(SALT_BYTES)
        sd_hash, _ = derive(selfdestruct, sd_salt)
        rec["selfdestruct_salt"] = sd_salt.hex()
        rec["selfdestruct_check"] = _check(sd_hash, DESTRUCT_LABEL)

    # Write the record (which holds the salt, the only way to derive the key
    # from the password) BEFORE removing the original. If anything interrupts
    # us after this, the .f.cys26 can still be opened. The worst leftover is a
    # copy of the original alongside a valid lock, which the recovery scan and
    # unlock handle, never a .f.cys26 whose salt was never saved.
    write_record(rec)

    if is_folder:
        import shutil
        shutil.rmtree(path)
    else:
        os.remove(path)
    return rec


def unlock_folder(rec, password, dest_parent=None, progress=None, cancel=None):
    """Unlock with the right password. Restores the folder/file, then removes
    the locked file and the record. Returns the restored path."""
    ok, _, key = verify(rec, password)
    if not ok:
        raise PermissionError("Wrong password.")
    return _restore(rec, key, dest_parent, progress, cancel)


def _restore(rec, key, dest_parent, progress, cancel):
    locked = rec["locked_path"]
    original = rec["path"]
    parent = dest_parent or os.path.dirname(original)
    if rec["kind"] == "folder":
        fd, tmp_tar = tempfile.mkstemp(prefix="cysfold-", suffix=".tar")
        os.close(fd)
        try:
            engine.decrypt_file(key, locked, tmp_tar, progress=progress, cancel=cancel)
            if os.path.exists(original) and not dest_parent:
                raise FileExistsError(
                    f"{original} already exists. Choose another place to restore to.")
            os.makedirs(parent, exist_ok=True)
            _extract_tar(tmp_tar, parent)
            restored = os.path.join(parent, os.path.basename(original))
        finally:
            if os.path.exists(tmp_tar):
                os.remove(tmp_tar)
    else:
        restored = os.path.join(parent, os.path.basename(original))
        if os.path.exists(restored) and not dest_parent:
            raise FileExistsError(
                f"{restored} already exists. Choose another place to restore to.")
        os.makedirs(parent, exist_ok=True)
        engine.decrypt_file(key, locked, restored, progress=progress, cancel=cancel)

    _remove(locked)
    delete_record(rec["id"])
    return restored


# --------------------------------------------------------------------------
# Step 3: wrong-try counter and the 5-in-12-hours lockout
# --------------------------------------------------------------------------
def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prune_fails(fails, now=None):
    """Keep only wrong tries inside the rolling window."""
    now = now or datetime.now(timezone.utc)
    kept = []
    for stamp in fails:
        try:
            when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if (now - when).total_seconds() <= WINDOW_HOURS * 3600:
            kept.append(stamp)
    return kept


def register_wrong_try(rec, progress=None, cancel=None):
    """Record one wrong try. If it reaches the limit inside the window, run the
    lockout re-encryption. Returns (locked_out, tries_in_window)."""
    fails = _prune_fails(rec.get("fails", []))
    fails.append(_now())
    rec["fails"] = fails
    if len(fails) >= MAX_TRIES and rec.get("state") == "locked":
        lockout_reencrypt(rec, progress=progress, cancel=cancel)
        return True, len(fails)
    write_record(rec)
    return False, len(fails)


def make_lockout_password():
    """A random 128-char password with the required character classes."""
    picks = (
        [secrets.choice(string.ascii_uppercase) for _ in range(LOCKOUT_MIN_UPPER)]
        + [secrets.choice(string.ascii_lowercase) for _ in range(LOCKOUT_MIN_LOWER)]
        + [secrets.choice(string.digits) for _ in range(LOCKOUT_MIN_DIGIT)]
        + [secrets.choice(LOCKOUT_SYMBOLS) for _ in range(LOCKOUT_MIN_SYMBOL)]
    )
    pool = string.ascii_letters + string.digits + LOCKOUT_SYMBOLS
    picks += [secrets.choice(pool) for _ in range(LOCKOUT_LEN - len(picks))]
    secrets.SystemRandom().shuffle(picks)
    return "".join(picks)


def lockout_reencrypt(rec, progress=None, cancel=None):
    """Re-encrypt the locked file with a throwaway 128-char password whose
    hash nobody keeps, then store its salt/check so no password ever verifies
    again. The data is unrecoverable after this by design."""
    password = make_lockout_password()
    salt = secrets.token_bytes(SALT_BYTES)
    hash_bytes, key = derive(password, salt)
    opts = _options_from(rec)
    locked = rec["locked_path"]

    tmp = locked + ".relock"
    try:
        # The current locked file is opaque data; re-lock it as a file.
        engine.encrypt_file(key, locked, tmp, opts, progress=progress, cancel=cancel)
        os.replace(tmp, locked)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    rec["salt"] = salt.hex()
    rec["rounds"] = PBKDF2_ROUNDS
    rec["check"] = _check(hash_bytes, CHECK_LABEL)
    rec["kind"] = "file"          # it is now a re-wrapped blob, not the tar
    rec["fails"] = []
    # password, hash_bytes and key go out of scope and are never stored.
    write_record(rec)
    return rec


# --------------------------------------------------------------------------
# Step 4: self-destruct
# --------------------------------------------------------------------------
def is_selfdestruct(rec, password):
    if not rec.get("selfdestruct_check"):
        return False
    ok, _, _ = verify(rec, password, label=DESTRUCT_LABEL,
                      salt_field="selfdestruct_salt", check_field="selfdestruct_check")
    return ok


def self_destruct(rec, progress=None, cancel=None):
    """Throwaway re-encrypt, then securely wipe and delete ONLY the .f.cys26
    file. No other files are touched. The record is kept and marked
    'destroyed' (it holds no key or password)."""
    lockout_reencrypt(rec, progress=progress, cancel=cancel)   # discard-key re-encrypt
    _secure_wipe(rec["locked_path"])
    rec["state"] = "destroyed"
    rec["fails"] = []
    write_record(rec)
    return rec


def _secure_wipe(path):
    """Overwrite the file once with random bytes, then delete it. Best effort:
    on an SSD the old blocks can survive wear-levelling (see README)."""
    if not os.path.exists(path):
        return
    size = os.path.getsize(path)
    try:
        with open(path, "r+b") as fh:
            written = 0
            while written < size:
                block = os.urandom(min(1024 * 1024, size - written))
                fh.write(block)
                written += len(block)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    _remove(path)


def _remove(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------------
# Recovery key
# --------------------------------------------------------------------------
def recovery_key(rec, password):
    """The 32-char CYS key for this lock, for use in the normal decrypt window.
    A folder comes out of cys26 dec as the packed tar."""
    ok, _, key = verify(rec, password)
    if not ok:
        raise PermissionError("Wrong password.")
    return key.hex().upper()


# --------------------------------------------------------------------------
# Recovery scan (heals state left behind by an interrupted operation)
# --------------------------------------------------------------------------
def scan_recovery():
    """Look for state left behind by a crash or force-quit and heal what is safe.

    - Promote a leftover atomic-write temp (`.rec-*.tmp`) into a real record
      when it holds a valid salt and its .f.cys26 exists but has no record yet.
      (This recovers locks stranded by the pre-fix version, where the record
      was written after the original was deleted.) Otherwise the temp is
      removed.
    - Report "half-finished" locks where both the original path and its
      .f.cys26 still exist, so the GUI can offer to finish or roll them back.

    Returns {"promoted": [ids], "removed_tmp": n, "half_finished": [recs]}.
    """
    base = state_dir()
    existing = {os.path.abspath(r.get("locked_path", "")): r for r in list_records()}
    promoted, removed_tmp = [], 0
    for name in os.listdir(base):
        if not name.startswith(".rec-") or not name.endswith(".tmp"):
            continue
        tmp = os.path.join(base, name)
        rec = None
        try:
            with open(tmp) as fh:
                rec = json.load(fh)
        except (OSError, ValueError):
            rec = None
        locked = os.path.abspath(rec.get("locked_path", "")) if rec else ""
        if (rec and rec.get("salt") and rec.get("id") and locked
                and os.path.exists(locked) and locked not in existing):
            write_record(rec)                 # promote to <id>.json
            existing[locked] = rec
            promoted.append(rec["id"])
        else:
            removed_tmp += 1
        _remove(tmp)
    half_finished = [r for r in list_records()
                     if r.get("state") == "locked"
                     and os.path.exists(r.get("path", ""))
                     and os.path.exists(r.get("locked_path", ""))]
    return {"promoted": promoted, "removed_tmp": removed_tmp,
            "half_finished": half_finished}


# --------------------------------------------------------------------------
# Step 5: the FOLD window
# --------------------------------------------------------------------------
def run_gui(target=None):
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk

    BG = "#E7EBEF"
    PANEL = "#F7F9FA"
    INK = "#18263A"
    MUTED = "#5C6B7E"
    TEAL = "#1D6F80"
    RED = "#B23A3A"

    root = tk.Tk()
    root.title("CYS-ENC26-FOLD")
    root.geometry("760x520")
    root.configure(bg=BG)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Treeview", rowheight=26, fieldbackground=PANEL, background=PANEL)
    style.configure("TButton", padding=6)

    header = tk.Label(root, text="CYS-ENC26-FOLD", bg=BG, fg=INK,
                      font=("TkDefaultFont", 17, "bold"))
    header.pack(anchor="w", padx=16, pady=(14, 0))
    tk.Label(root, text="Password-lock a folder or file. Learning tool, not for real secrets.",
             bg=BG, fg=MUTED).pack(anchor="w", padx=16, pady=(0, 10))

    cols = ("name", "kind", "state", "tries", "path")
    tree = ttk.Treeview(root, columns=cols, show="headings", height=12)
    for c, w in zip(cols, (170, 70, 100, 60, 320)):
        tree.heading(c, text=c.capitalize())
        tree.column(c, width=w, anchor="w")
    tree.pack(fill="both", expand=True, padx=16)

    def refresh():
        tree.delete(*tree.get_children())
        for rec in list_records():
            tries = len(_prune_fails(rec.get("fails", [])))
            exists = os.path.exists(rec.get("locked_path", "")) or rec.get("state") == "destroyed"
            state = rec.get("state", "locked")
            if state == "locked" and not exists:
                state = "missing"
            tree.insert("", "end", iid=rec["id"],
                        values=(os.path.basename(rec["path"]), rec["kind"], state,
                                tries, rec["path"]))

    def selected_rec():
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("CYS-ENC26-FOLD", "Pick a lock from the list first.")
            return None
        try:
            return read_record(sel[0])
        except (OSError, ValueError):
            messagebox.showerror("CYS-ENC26-FOLD", "That lock record can't be read.")
            return None

    def ask_password(prompt):
        return simpledialog.askstring("CYS-ENC26-FOLD", prompt, show="•", parent=root)

    def run_bg(title, work, done):
        """Run work(progress, cancel) on a background thread with a modal
        progress dialog and a Cancel button, so the window never freezes. When
        it finishes, call done(result, exc, cancelled) on the main thread."""
        dlg = tk.Toplevel(root)
        dlg.title("CYS-ENC26-FOLD")
        dlg.configure(bg=BG)
        dlg.transient(root)
        dlg.resizable(False, False)
        tk.Label(dlg, text=title, bg=BG, fg=INK,
                 font=("TkDefaultFont", 11, "bold")).pack(padx=28, pady=(20, 6))
        status = tk.Label(dlg, text="Working…", bg=BG, fg=MUTED)
        status.pack(padx=28)
        pb = ttk.Progressbar(dlg, mode="indeterminate", length=340)
        pb.pack(padx=28, pady=12)
        pb.start(12)
        cancel_event = threading.Event()

        def on_cancel():
            cancel_event.set()
            status.config(text="Cancelling…")
        ttk.Button(dlg, text="Cancel", command=on_cancel).pack(pady=(0, 18))
        dlg.protocol("WM_DELETE_WINDOW", on_cancel)
        dlg.grab_set()

        st = {"parts": None}

        def progress(done_n, parts):
            def upd():
                if st["parts"] is None:
                    st["parts"] = parts
                    pb.stop()
                    pb.config(mode="determinate", maximum=max(1, parts))
                pb["value"] = done_n
                status.config(text=f"{done_n} of {parts} part(s)")
            root.after(0, upd)

        holder = {}

        def worker():
            try:
                holder["result"] = work(progress, cancel_event)
            except engine.Cancelled:
                holder["cancelled"] = True
            except BaseException as exc:            # noqa: BLE001
                holder["exc"] = exc
            holder["finished"] = True

        threading.Thread(target=worker, daemon=True).start()

        def poll():
            if not holder.get("finished"):
                root.after(100, poll)
                return
            try:
                dlg.grab_release()
            except tk.TclError:
                pass
            dlg.destroy()
            done(holder.get("result"), holder.get("exc"), holder.get("cancelled", False))
        root.after(100, poll)

    def do_add():
        folder = filedialog.askdirectory(title="Folder to lock")
        path = folder
        if not folder:
            path = filedialog.askopenfilename(title="Or pick a file to lock")
        if not path:
            return
        pw = ask_password(f"Set a password for {os.path.basename(path.rstrip('/'))}:")
        if not pw:
            return
        pw2 = ask_password("Re-enter the password:")
        if pw != pw2:
            messagebox.showerror("CYS-ENC26-FOLD", "The passwords didn't match.")
            return
        sd = ask_password("Optional self-destruct code (leave blank for none):")
        sd = sd or None
        if sd and sd == pw:
            messagebox.showerror("CYS-ENC26-FOLD",
                                 "The self-destruct code must differ from the password.")
            return
        size = _tree_size(path)
        over = size > engine.MAX_FILE_BYTES
        if over and not messagebox.askyesno("CYS-ENC26-FOLD", engine.LIMIT_WARNING):
            return

        def work(progress, cancel):
            return lock_folder(path, pw, selfdestruct=sd, allow_over_limit=over,
                               progress=progress, cancel=cancel)

        def done(result, exc, cancelled):
            if cancelled:
                messagebox.showinfo("CYS-ENC26-FOLD",
                                    "Cancelled. Nothing was locked; your files are untouched.")
            elif exc:
                messagebox.showerror("CYS-ENC26-FOLD", f"Couldn't lock it:\n{exc}")
            else:
                messagebox.showinfo("CYS-ENC26-FOLD", "Locked. The original is now encrypted.")
            refresh()
        run_bg(f"Locking {os.path.basename(path.rstrip('/'))}…", work, done)

    def _attempt_unlock(rec):
        pw = ask_password(f"Password for {os.path.basename(rec['path'])}:")
        if pw is None:
            return
        if is_selfdestruct(rec, pw):
            if not messagebox.askyesno(
                    "CYS-ENC26-FOLD",
                    "That is the self-destruct code. The folder will be made "
                    "unrecoverable and its locked file deleted. Continue?"):
                return

            def sd_work(progress, cancel):
                return self_destruct(rec, progress=progress, cancel=cancel)

            def sd_done(result, exc, cancelled):
                if exc and not cancelled:
                    messagebox.showerror("CYS-ENC26-FOLD", f"Self-destruct failed:\n{exc}")
                else:
                    messagebox.showinfo("CYS-ENC26-FOLD", "Self-destructed. The data is gone.")
                refresh()
            run_bg("Self-destructing…", sd_work, sd_done)
            return

        def work(progress, cancel):
            try:
                restored = unlock_folder(rec, pw, progress=progress, cancel=cancel)
                return ("ok", restored)
            except PermissionError:
                locked_out, tries = register_wrong_try(rec, progress=progress, cancel=cancel)
                return ("bad", (locked_out, tries))

        def done(result, exc, cancelled):
            if cancelled:
                messagebox.showinfo("CYS-ENC26-FOLD", "Cancelled.")
            elif exc:
                messagebox.showerror("CYS-ENC26-FOLD", f"Couldn't unlock it:\n{exc}")
            elif result[0] == "ok":
                messagebox.showinfo("CYS-ENC26-FOLD", f"Unlocked to:\n{result[1]}")
            else:
                locked_out, tries = result[1]
                if locked_out:
                    messagebox.showerror(
                        "CYS-ENC26-FOLD",
                        f"Wrong password {MAX_TRIES} times in {WINDOW_HOURS} hours. "
                        "The folder was re-encrypted with a discarded key and is now "
                        "unrecoverable.")
                else:
                    messagebox.showerror(
                        "CYS-ENC26-FOLD",
                        f"Wrong password. {MAX_TRIES - tries} tries left before the "
                        f"folder is made unrecoverable.")
            refresh()
        run_bg(f"Unlocking {os.path.basename(rec['path'])}…", work, done)

    def do_unlock():
        rec = selected_rec()
        if rec:
            if rec.get("state") == "destroyed":
                messagebox.showinfo("CYS-ENC26-FOLD", "This lock was self-destructed.")
                return
            _attempt_unlock(rec)

    def do_recovery():
        rec = selected_rec()
        if not rec or rec.get("state") == "destroyed":
            return
        pw = ask_password("Password (to show the recovery key):")
        if pw is None:
            return
        try:
            key = recovery_key(rec, pw)
            messagebox.showinfo(
                "CYS-ENC26-FOLD",
                f"Recovery key (opens {os.path.basename(rec['locked_path'])} in "
                f"cys26 dec):\n\n{key}\n\nA folder comes out as a .tar file.")
        except PermissionError:
            messagebox.showerror("CYS-ENC26-FOLD", "Wrong password.")

    def do_remove():
        rec = selected_rec()
        if not rec:
            return
        if messagebox.askyesno(
                "CYS-ENC26-FOLD",
                "Remove this lock record? The .f.cys26 file is left on disk; "
                "you'll need the password (or recovery key) to open it later."):
            delete_record(rec["id"])
            refresh()

    bar = tk.Frame(root, bg=BG)
    bar.pack(fill="x", padx=16, pady=12)
    for text, cmd in (("Add lock", do_add), ("Unlock", do_unlock),
                      ("Show recovery key", do_recovery), ("Remove lock", do_remove)):
        ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=(0, 8))

    refresh()

    # Heal anything an interrupted operation left behind, and tell the user.
    try:
        healed = scan_recovery()
    except OSError:
        healed = {"promoted": [], "removed_tmp": 0, "half_finished": []}
    if healed["promoted"] or healed["half_finished"]:
        refresh()
        lines = []
        if healed["promoted"]:
            lines.append(f"Recovered {len(healed['promoted'])} lock record(s) left "
                         "unsaved by an interrupted lock. You can unlock them normally.")
        for r in healed["half_finished"]:
            lines.append(
                f"'{os.path.basename(r['path'])}' has both the original and a "
                f"half-written {FOLD_EXT} file. Your original is intact; the "
                f"partial locked file at {r['locked_path']} can be deleted, or "
                "remove the lock and try again.")
        root.after(200, lambda: messagebox.showinfo("CYS-ENC26-FOLD", "\n\n".join(lines)))

    # Launched on a .f.cys26 file: "THIS FILE IS LOCKED", then straight to prompt.
    if target and os.path.abspath(target).endswith(FOLD_EXT):
        rec = find_by_locked_path(target)
        root.after(150, lambda: _opened_locked(target, rec, messagebox,
                                               _attempt_unlock, refresh))

    root.mainloop()


def _opened_locked(target, rec, messagebox, attempt, refresh):
    messagebox.showwarning("CYS-ENC26-FOLD", "THIS FILE IS LOCKED")
    if rec is None:
        messagebox.showinfo(
            "CYS-ENC26-FOLD",
            "No lock record was found for this file (it may have been moved). "
            "Open its lock in the list, or use its recovery key in cys26 dec.")
        return
    if rec.get("state") == "destroyed":
        messagebox.showinfo("CYS-ENC26-FOLD", "This lock was self-destructed.")
        return
    attempt(rec)
    refresh()


def _tree_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for root_dir, _dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root_dir, f)
            if not os.path.islink(fp):
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
    return total


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("-v", "--version"):
        print(f"CYS-ENC26-FOLD {engine.VERSION}")
        return
    target = argv[0] if argv else None
    run_gui(target)


if __name__ == "__main__":
    main()
