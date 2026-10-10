import os
import sys
import shutil
import base64
import threading
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
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hide_file(path):
    if os.name == 'nt':
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass

class AutoCloseDialog(tk.Toplevel):
    def __init__(self, parent, title, message, timeout=5, is_error=False):
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
        if not self.winfo_exists():
            return
        if self.timeout > 0:
            self.btn_ok.config(text=f"Close ({self.timeout}s)")
            self.timeout -= 1
            self.after(1000, self.update_timer)
        else:
            self.destroy()

def show_popup(parent, title, message, is_error=False):
    AutoCloseDialog(parent, title, message, timeout=5, is_error=is_error)

def lock_folder(source_folder: Path, password: str, update_progress):
    update_progress(5, "Preparing...")
    parent_dir = source_folder.parent
    folder_name = source_folder.name
    
    if os.name == 'nt':
        output_file = parent_dir / f"{folder_name}.fsl"
    else:
        output_file = parent_dir / f".{folder_name}.fsl"

    if output_file.exists():
        raise Exception("A locked file for this folder already exists.")

    update_progress(15, "Zipping folder (This may take a moment)...")
    temp_zip = parent_dir / f"{folder_name}_temp.zip"
    shutil.make_archive(
        base_name=str(parent_dir / f"{folder_name}_temp"),
        format='zip',
        root_dir=source_folder
    )
    
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
    
    update_progress(95, "Cleaning up...")
    os.remove(temp_zip)
    os.remove(source_file)
    
    if os.name == 'nt':
        import subprocess
        subprocess.run(['explorer', '/select,', str(dest_folder.resolve())])
        
    update_progress(100, "Finished Decryption")


class FoldCryptApp:
    def __init__(self, root):
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
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:
            self.lock_action()
        else:
            self.unlock_action()
            
    def reset_progress_on_interaction(self, event=None):
        if "Finished" in self.status_var.get():
            self.update_progress_ui(0, "")
            
    def on_closing(self):
        self.root.destroy()
        os._exit(0)
        
    def setup_lock_tab(self):
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
        folder = filedialog.askdirectory(title="Select Folder to Lock")
        if folder:
            self.lock_folder_var.set(folder)
            
    def browse_unlock_file(self):
        file = filedialog.askopenfilename(title="Select .fsl File", filetypes=[("FoldCrypt Locked", "*.fsl"), ("All files", "*.*")])
        if file:
            self.unlock_file_var.set(file)

    def update_progress_ui(self, percent, text):
        self.root.after(0, self._set_progress, percent, text)
        
    def _set_progress(self, percent, text):
        self.progress_percent.set(percent)
        if percent == 0 and text == "":
            self.status_var.set("Progress:")
        elif percent >= 100:
            self.status_var.set(f"{text}")
        else:
            self.status_var.set(f"Progress: {percent}% - {text}")

    def start_job(self, target_func, success_msg):
        self.update_progress_ui(0, "Starting...")
        
        def worker():
            try:
                target_func()
                self.root.after(0, self.on_job_success, success_msg)
            except Exception as e:
                self.root.after(0, self.on_job_error, str(e))
                
        threading.Thread(target=worker, daemon=True).start()
        
    def on_job_success(self, msg):
        show_popup(self.root, "Success", msg, is_error=False)
        
    def on_job_error(self, err_msg):
        self.update_progress_ui(0, "")
        show_popup(self.root, "Error", err_msg, is_error=True)

    def lock_action(self):
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
