"""FoldCrypt — encrypt folders with AES (Fernet), PBKDF2 KDF & SHA-256 manifests.

Lock flow: zip the folder, record a SHA-256 + size manifest of every file,
derive a Fernet key from the password (PBKDF2-HMAC-SHA256, 480,000
iterations, fresh 16-byte salt), encrypt the zip, and write a ``.fsl`` file
(16-byte salt followed by the Fernet blob). The original folder is deleted.
Unlock flow: derive the same key, decrypt, extract, and re-hash every
restored file against the manifest — any drift fails loudly and the locked
file is kept. A Tkinter GUI (FoldCryptApp) wraps the same two functions.
"""

import os
import sys
import shutil
import base64
import hashlib
import json
import threading
import zipfile
import tkinter as tk
from tkinter import filedialog, ttk
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("The 'cryptography' library is required. Install it using: pip install cryptography")
    sys.exit(1)

def get_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt.

    PBKDF2-HMAC-SHA256, 32-byte output, 480,000 iterations; the result is
    URL-safe base64-encoded as Fernet requires. Same password + salt
    always yields the same key; a different salt (fresh 16 random bytes
    per lock) yields a different key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hide_file(path):
    """Mark a file hidden on Windows (FILE_ATTRIBUTE_HIDDEN); no-op elsewhere.

    Failures are swallowed on purpose — hiding is cosmetic and must never
    break a lock/unlock that has already succeeded.
    """
    if os.name == 'nt':
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass

# Integrity manifest: at lock time every file's SHA-256 + size is
# recorded in a manifest stored inside the encrypted archive. Fernet's
# HMAC proves the archive blob is untouched, but it cannot prove the
# *extracted tree* is complete and correct — a short write, a failing
# disk or a partial extraction would otherwise hand back a subtly
# wrong folder with a "success" message. The manifest closes that gap:
# unlock re-hashes every restored file and fails loudly on any drift.
MANIFEST_NAME = "foldcrypt-manifest.json"
MANIFEST_VERSION = 1

def _sha256_of(path: Path) -> str:
    """SHA-256 hex digest of a file, streamed in 1 MiB chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def build_manifest(source_folder: Path) -> dict:
    """Map every file under source_folder to its SHA-256 + size,
    keyed by POSIX-style relative path (stable across OSes)."""
    files = {}
    for path in sorted(source_folder.rglob("*")):
        if path.is_file():
            rel = path.relative_to(source_folder).as_posix()
            files[rel] = {"sha256": _sha256_of(path), "size": path.stat().st_size}
    return {"version": MANIFEST_VERSION, "files": files}

def verify_extracted(dest_folder: Path, manifest: dict) -> list:
    """Compare an extracted folder against its lock-time manifest.
    Returns human-readable problems (empty list = intact): files that
    are missing, files whose content changed, unexpected extra files."""
    expected = manifest.get("files", {})
    problems = []
    actual = {}
    for path in sorted(dest_folder.rglob("*")):
        if path.is_file():
            rel = path.relative_to(dest_folder).as_posix()
            if rel == MANIFEST_NAME:
                continue
            actual[rel] = path
    for rel, meta in expected.items():
        path = actual.get(rel)
        if path is None:
            problems.append(f"missing after extraction: {rel}")
        elif path.stat().st_size != meta.get("size") or _sha256_of(path) != meta.get("sha256"):
            problems.append(f"content changed: {rel}")
    for rel in actual:
        if rel not in expected:
            problems.append(f"unexpected extra file: {rel}")
    return problems

class AutoCloseDialog(tk.Toplevel):
    """A small centred result dialog that closes itself after ``timeout`` seconds.

    Shows a green tick (success) or red cross (error) plus the message, with
    a countdown button the user can also click to dismiss early.
    """

    def __init__(self, parent, title, message, timeout=5, is_error=False):
        """Build the centred dialog and start the countdown to auto-close."""
        super().__init__(parent)
        self.title(title)
        self.geometry("350x180")
        self.resizable(False, False)
        
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 175
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 90
        self.geometry(f"+{x}+{y}")
        
        self.attributes('-topmost', True)
        
        self.timeout = timeout
        
        color = "#d32f2f" if is_error else "#2e7d32"
        icon_text = "❌" if is_error else "✅"
        
        tk.Label(self, text=icon_text, font=("Inter", 24), fg=color).pack(pady=(15, 0))
        tk.Label(self, text=message, font=("Inter", 10), wraplength=300, justify="center").pack(pady=10)
        
        self.btn_ok = tk.Button(self, text=f"Close ({self.timeout}s)", width=15, command=self.destroy)
        self.btn_ok.pack(pady=5)
        
        self.update_timer()
        
    def update_timer(self):
        """Tick the countdown once a second; destroy the dialog at zero."""
        if not self.winfo_exists():
            return
        if self.timeout > 0:
            self.btn_ok.config(text=f"Close ({self.timeout}s)")
            self.timeout -= 1
            self.after(1000, self.update_timer)
        else:
            self.destroy()

def show_popup(parent, title, message, is_error=False):
    """Show a 5-second auto-closing result dialog (red styling on error)."""
    AutoCloseDialog(parent, title, message, timeout=5, is_error=is_error)

def lock_folder(source_folder: Path, password: str, update_progress):
    """Lock a folder into a single encrypted ``.fsl`` file and delete the original.

    Steps: zip the folder, build the SHA-256 integrity manifest and append
    it to the zip, derive the key from the password with a fresh salt,
    Fernet-encrypt the zip, and write ``salt + ciphertext`` to
    ``<name>.fsl`` (``.<name>.fsl`` on non-Windows, hidden on Windows).
    Raises if a locked file for the folder already exists or the folder
    contains a file named ``foldcrypt-manifest.json`` (reserved).
    ``update_progress`` is a ``(percent, text)`` callback for the GUI.
    """
    update_progress(5, "Preparing...")
    parent_dir = source_folder.parent
    folder_name = source_folder.name
    
    if os.name == 'nt':
        output_file = parent_dir / f"{folder_name}.fsl"
    else:
        output_file = parent_dir / f".{folder_name}.fsl"

    if output_file.exists():
        raise Exception("A locked file for this folder already exists.")

    if (source_folder / MANIFEST_NAME).is_file():
        raise Exception(f"'{MANIFEST_NAME}' is reserved for FoldCrypt's integrity manifest. Please rename that file in the folder and try again.")

    update_progress(15, "Zipping folder (This may take a moment)...")
    temp_zip = parent_dir / f"{folder_name}_temp.zip"
    shutil.make_archive(
        base_name=str(parent_dir / f"{folder_name}_temp"),
        format='zip',
        root_dir=source_folder
    )

    update_progress(30, "Building integrity manifest...")
    manifest = build_manifest(source_folder)
    with zipfile.ZipFile(temp_zip, "a") as zf:
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=1, sort_keys=True))

    update_progress(40, "Generating secure key...")
    salt = os.urandom(16)
    key = get_key(password, salt)
    f = Fernet(key)
    
    update_progress(50, "Encrypting files... (Please wait)")
    with open(temp_zip, 'rb') as zf:
        data = zf.read()
        
    encrypted_data = f.encrypt(data)
    
    update_progress(80, "Writing secured file...")
    with open(output_file, 'wb') as lf:
        lf.write(salt)
        lf.write(encrypted_data)
        
    hide_file(output_file)
    
    update_progress(95, "Cleaning up original files...")
    os.remove(temp_zip)
    shutil.rmtree(source_folder)
    
    if os.name == 'nt':
        import subprocess
        subprocess.run(['explorer', '/select,', str(output_file.resolve())])
        
    update_progress(100, "Finished Encryption")


def unlock_file(source_file: Path, password: str, update_progress):
    """Decrypt a ``.fsl`` file and restore the original folder next to it.

    Derives the key from the password and the salt stored in the file's
    first 16 bytes; a wrong password raises "Incorrect password". After
    extraction every restored file is re-hashed against the lock-time
    manifest — on any mismatch the restored copy is left untrusted and the
    locked file is kept. Archives made before manifests existed are
    restored without verification. The ``.fsl`` file is deleted on success.
    ``update_progress`` is a ``(percent, text)`` callback for the GUI.
    """
    update_progress(5, "Preparing...")
    parent_dir = source_file.parent
    folder_name = source_file.stem
    if not os.name == 'nt' and folder_name.startswith('.'):
        folder_name = folder_name[1:]
        
    dest_folder = parent_dir / folder_name

    if dest_folder.exists():
        raise Exception(f"A folder named '{folder_name}' already exists here. Please move it before unlocking.")

    update_progress(15, "Reading encrypted file...")
    with open(source_file, 'rb') as lf:
        salt = lf.read(16)
        encrypted_data = lf.read()
        
    update_progress(40, "Verifying password...")
    key = get_key(password, salt)
    f = Fernet(key)
    
    update_progress(50, "Decrypting files... (Please wait)")
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except Exception:
        raise Exception("Incorrect password. Access Denied.")
    
    update_progress(75, "Extracting restored files...")
    temp_zip = parent_dir / "temp_extract.zip"
    with open(temp_zip, 'wb') as tz:
        tz.write(decrypted_data)
        
    os.makedirs(dest_folder)
    shutil.unpack_archive(temp_zip, extract_dir=dest_folder, format='zip')

    update_progress(85, "Verifying file integrity...")
    manifest_path = dest_folder / MANIFEST_NAME
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            problems = verify_extracted(dest_folder, manifest)
        except Exception:
            os.remove(temp_zip)
            raise Exception("Integrity manifest could not be read or verified — the restored folder cannot be trusted. The locked file has been kept.")
        manifest_path.unlink()
        if problems:
            os.remove(temp_zip)
            shown = "; ".join(problems[:5])
            more = f" (+{len(problems) - 5} more)" if len(problems) > 5 else ""
            raise Exception(f"Integrity check FAILED — restored files do not match what was locked: {shown}{more}. The locked file has been kept; do not rely on the restored copy.")
    else:
        update_progress(88, "Legacy archive (no integrity manifest) — skipping verification.")

    update_progress(95, "Cleaning up...")
    os.remove(temp_zip)
    os.remove(source_file)
    
    if os.name == 'nt':
        import subprocess
        subprocess.run(['explorer', '/select,', str(dest_folder.resolve())])
        
    update_progress(100, "Finished Decryption")


class FoldCryptApp:
    """Tkinter front end: Lock/Unlock tabs, progress bar, and job threading.

    Crypto work runs on a daemon worker thread (see ``start_job``) so the
    UI stays responsive; all widget updates from that thread go through
    ``update_progress_ui`` / ``root.after`` back onto the main thread.
    """

    def __init__(self, root):
        """Build the window, both tabs, and the shared progress bar."""
        self.root = root
        
        # Apply modern Google Font globally across the entire application interface
        self.root.option_add("*Font", ("Inter", 10))
        
        self.root.title("FoldCrypt - Smart Locker")
        self.root.geometry("620x450")
        self.root.configure(padx=20, pady=20)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind('<Return>', self.handle_return_key)
        self.root.bind('<Key>', self.reset_progress_on_interaction)
        self.root.bind('<Button-1>', self.reset_progress_on_interaction)
        
        # Title Layout - Centered
        title_frame = tk.Frame(root)
        title_frame.pack(pady=(0, 15))
        
        self.logo_img = None
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logo.png')
            if os.path.exists(icon_path):
                self.logo_img = tk.PhotoImage(file=icon_path)
                width = self.logo_img.width()
                if width > 64:
                    factor = width // 48
                    if factor > 0:
                        self.logo_img = self.logo_img.subsample(factor, factor)
                self.root.iconphoto(True, self.logo_img)
            else:
                ico_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logo.ico')
                if os.path.exists(ico_path):
                    self.root.iconbitmap(ico_path)
        except Exception:
            pass
            
        if self.logo_img:
            # Place the logo and text in separate labels side-by-side to force strict vertical symmetry
            tk.Label(title_frame, image=self.logo_img).pack(side="left", padx=(0, 10))
            tk.Label(title_frame, text="FoldCrypt", font=("Inter", 18, "bold")).pack(side="left")
        else:
            tk.Label(title_frame, text="FoldCrypt", font=("Inter", 18, "bold")).pack()
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)
        
        self.frame_lock = ttk.Frame(self.notebook, padding=15)
        self.frame_unlock = ttk.Frame(self.notebook, padding=15)
        
        self.notebook.add(self.frame_lock, text="Lock Folder")
        self.notebook.add(self.frame_unlock, text="Unlock Folder")
        
        self.setup_lock_tab()
        self.setup_unlock_tab()
        
        self.progress_percent = tk.IntVar(value=0)
        
        self.status_var = tk.StringVar(value="Progress:")
        tk.Label(root, textvariable=self.status_var, font=("Inter", 9), fg="gray").pack(anchor="w", pady=(10, 0))
        
        self.progress = ttk.Progressbar(root, mode='determinate', variable=self.progress_percent, maximum=100)
        self.progress.pack(fill="x", pady=5)
        
    def _create_eye(self, parent, entry):
        """Return a press-and-hold eye icon that reveals ``entry``'s password.

        The password is shown only while the mouse button is held down and
        masked again on release. Falls back to a lock/eye emoji label when
        the ``eye_open.png`` / ``eye_closed.png`` assets are missing.
        """
        eye = tk.Label(parent, cursor="hand2")
        
        # Load the custom eye icons
        try:
            if not hasattr(self, 'eye_open_img'):
                open_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'eye_open.png')
                closed_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'eye_closed.png')
                
                # We subsample aggressively assuming the user images are around 512px
                img_open = tk.PhotoImage(file=open_path)
                img_closed = tk.PhotoImage(file=closed_path)
                
                factor = max(1, img_open.width() // 24)
                
                self.eye_open_img = img_open.subsample(factor, factor)
                self.eye_closed_img = img_closed.subsample(factor, factor)
                
            eye.config(image=self.eye_closed_img)
            use_img = True
        except Exception:
            # Fallback if image doesn't exist
            eye.config(text="🔒", font=("Segoe UI Emoji", 12), fg="#555")
            use_img = False
            
        def on_press(e):
            entry.config(show="")
            if use_img: eye.config(image=self.eye_open_img)
            else: eye.config(text="👁️")
            
        def on_release(e):
            entry.config(show="*")
            if use_img: eye.config(image=self.eye_closed_img)
            else: eye.config(text="🔒")
            
        eye.bind('<ButtonPress-1>', on_press)
        eye.bind('<ButtonRelease-1>', on_release)
        return eye
        
    def handle_return_key(self, event):
        """Run the active tab's action when Enter is pressed anywhere."""
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:
            self.lock_action()
        else:
            self.unlock_action()
            
    def reset_progress_on_interaction(self, event=None):
        """Clear a finished-job status line as soon as the user types or clicks."""
        if "Finished" in self.status_var.get():
            self.update_progress_ui(0, "")
            
    def on_closing(self):
        """Quit immediately, killing any still-running daemon worker thread."""
        self.root.destroy()
        os._exit(0)
        
    def setup_lock_tab(self):
        """Build the Lock tab: folder picker, password + confirm, Lock button."""
        # Create a container frame that automatically centers itself in the tab
        container = tk.Frame(self.frame_lock)
        container.pack(expand=True)
        
        # Enforce exact width and right-anchor for perfect justification
        label_kwargs = {"width": 16, "anchor": "e"}
        
        tk.Label(container, text="Select Folder:", **label_kwargs).grid(row=0, column=0, sticky="e", pady=5)
        self.lock_folder_var = tk.StringVar()
        tk.Entry(container, textvariable=self.lock_folder_var, width=35).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(container, text="Browse", command=self.browse_lock_folder).grid(row=0, column=2, padx=5, sticky="w")
        
        tk.Label(container, text="Password:", **label_kwargs).grid(row=1, column=0, sticky="e", pady=5)
        self.lock_pwd = tk.StringVar()
        self.lock_pwd_entry = tk.Entry(container, textvariable=self.lock_pwd, show="*", width=35)
        self.lock_pwd_entry.grid(row=1, column=1, padx=5, pady=5)
        self._create_eye(container, self.lock_pwd_entry).grid(row=1, column=2, sticky="w")
        
        tk.Label(container, text="Confirm Password:", **label_kwargs).grid(row=2, column=0, sticky="e", pady=5)
        self.lock_pwd_confirm = tk.StringVar()
        self.lock_pwd_confirm_entry = tk.Entry(container, textvariable=self.lock_pwd_confirm, show="*", width=35)
        self.lock_pwd_confirm_entry.grid(row=2, column=1, padx=5, pady=5)
        self._create_eye(container, self.lock_pwd_confirm_entry).grid(row=2, column=2, sticky="w")
        
        tk.Button(container, text="Lock", bg="#f44336", fg="white", font=("Inter", 10, "bold"), width=15,
                  command=self.lock_action).grid(row=3, column=0, columnspan=3, pady=20)
                  
    def setup_unlock_tab(self):
        """Build the Unlock tab: .fsl file picker, password, Unlock button."""
        # Create a container frame that automatically centers itself in the tab
        container = tk.Frame(self.frame_unlock)
        container.pack(expand=True)
        
        label_kwargs = {"width": 16, "anchor": "e"}
        
        tk.Label(container, text="Select .fsl File:", **label_kwargs).grid(row=0, column=0, sticky="e", pady=5)
        self.unlock_file_var = tk.StringVar()
        tk.Entry(container, textvariable=self.unlock_file_var, width=35).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(container, text="Browse", command=self.browse_unlock_file).grid(row=0, column=2, padx=5, sticky="w")
        
        tk.Label(container, text="Password:", **label_kwargs).grid(row=1, column=0, sticky="e", pady=5)
        self.unlock_pwd = tk.StringVar()
        self.unlock_pwd_entry = tk.Entry(container, textvariable=self.unlock_pwd, show="*", width=35)
        self.unlock_pwd_entry.grid(row=1, column=1, padx=5, pady=5)
        self._create_eye(container, self.unlock_pwd_entry).grid(row=1, column=2, sticky="w")
        
        tk.Button(container, text="Unlock", bg="#4CAF50", fg="white", font=("Inter", 10, "bold"), width=15,
                  command=self.unlock_action).grid(row=2, column=0, columnspan=3, pady=20)

    def browse_lock_folder(self):
        """Let the user pick the folder to lock; ignore a cancelled dialog."""
        folder = filedialog.askdirectory(title="Select Folder to Lock")
        if folder:
            self.lock_folder_var.set(folder)
            
    def browse_unlock_file(self):
        """Let the user pick a .fsl file to unlock; ignore a cancelled dialog."""
        file = filedialog.askopenfilename(title="Select .fsl File", filetypes=[("FoldCrypt Locked", "*.fsl"), ("All files", "*.*")])
        if file:
            self.unlock_file_var.set(file)

    def update_progress_ui(self, percent, text):
        """Thread-safe progress update: marshal ``_set_progress`` onto the UI thread."""
        self.root.after(0, self._set_progress, percent, text)

    def _set_progress(self, percent, text):
        """Apply a progress update on the UI thread (bar + status line)."""
        self.progress_percent.set(percent)
        if percent == 0 and text == "":
            self.status_var.set("Progress:")
        elif percent >= 100:
            self.status_var.set(f"{text}")
        else:
            self.status_var.set(f"Progress: {percent}% - {text}")

    def start_job(self, target_func, success_msg):
        """Run ``target_func`` on a daemon worker thread; report via popups.

        Success and failure are marshalled back onto the UI thread with
        ``root.after`` — Tkinter widgets must never be touched from the
        worker directly.
        """
        self.update_progress_ui(0, "Starting...")
        
        def worker():
            try:
                target_func()
                self.root.after(0, self.on_job_success, success_msg)
            except Exception as e:
                self.root.after(0, self.on_job_error, str(e))
                
        threading.Thread(target=worker, daemon=True).start()
        
    def on_job_success(self, msg):
        """Show the success dialog (runs on the UI thread via ``after``)."""
        show_popup(self.root, "Success", msg, is_error=False)

    def on_job_error(self, err_msg):
        """Reset the progress bar and show the error dialog (UI thread)."""
        self.update_progress_ui(0, "")
        show_popup(self.root, "Error", err_msg, is_error=True)

    def lock_action(self):
        """Validate the Lock tab inputs, then encrypt the folder in the background.

        Rejects a missing/invalid folder and empty or mismatched passwords
        with an error popup; clears the fields once the job is dispatched.
        """
        folder_str = self.lock_folder_var.get().strip()
        pwd = self.lock_pwd.get()
        pwd_conf = self.lock_pwd_confirm.get()
        
        if not folder_str or not os.path.isdir(folder_str):
            show_popup(self.root, "Input error", "Select a valid folder to lock.", is_error=True)
            return
            
        if not pwd or pwd != pwd_conf:
            show_popup(self.root, "Password error", "Passwords do not match or are empty.", is_error=True)
            return
            
        folder = Path(folder_str)
            
        self.start_job(
            lambda: lock_folder(folder, pwd, self.update_progress_ui),
            "Folder has been successfully locked, encrypted, and hidden!"
        )
        self.lock_folder_var.set("")
        self.lock_pwd.set("")
        self.lock_pwd_confirm.set("")

    def unlock_action(self):
        """Validate the Unlock tab inputs, then decrypt the .fsl file in the background.

        Rejects a missing/not-a-file selection and an empty password with an
        error popup; clears the fields once the job is dispatched.
        """
        source_str = self.unlock_file_var.get().strip()
        pwd = self.unlock_pwd.get()
        
        if not source_str:
            show_popup(self.root, "Input error", "Select a valid .fsl file.", is_error=True)
            return
            
        source = Path(source_str)
        if not source.is_file():
            show_popup(self.root, "Input error", "Select a valid .fsl file.", is_error=True)
            return
            
        if not pwd:
            show_popup(self.root, "Password error", "Enter your password.", is_error=True)
            return
            
        self.start_job(
            lambda: unlock_file(source, pwd, self.update_progress_ui),
            "Folder successfully decrypted and restored to its original place!"
        )
        self.unlock_file_var.set("")
        self.unlock_pwd.set("")

if __name__ == "__main__":
    root = tk.Tk()
    app = FoldCryptApp(root)
    root.mainloop()
