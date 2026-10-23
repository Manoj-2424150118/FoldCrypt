# 🛡️ FoldCrypt

**FoldCrypt** is a premium, cross-platform, smart locker application that securely encrypts, compresses, and hides your sensitive folders behind AES cryptography and a sleek, user-friendly graphical interface. 

Instead of just changing system permissions, FoldCrypt physically zips and encrypts your entire folder structure using robust **Fernet (AES-128)** encryption with heavily salted **PBKDF2HMAC** key derivation. The result is a highly secure, portable `.fsl` (FoldCrypt Secure Locker) file that perfectly protects your data.

## ✨ Features
* **Bank-Grade Encryption:** Uses python's `cryptography` library for AES encryption and PBKDF2 hashing.
* **In-Place Archiving:** Instantly zips folders and converts them into a single, encrypted `.fsl` file.
* **Portability:** Your encrypted `.fsl` file can be safely moved to a USB drive, another computer, or cloud storage. It will decrypt flawlessly anywhere as long as you have the password.
* **Invisible by Default:** Automatically applies system-level hidden attributes to the locked `.fsl` files to keep them completely out of sight.
* **Premium UX/UI:**
  * Clean, centralized Tkinter interface using modern Google **Inter** typography.
  * Real-time deterministic progress bars for live visual feedback during heavy IO operations.
  * Interactive **"Eye"** icons to toggle password visibility.
  * Intelligent, auto-closing custom dialog boxes that destroy themselves after 5 seconds to prevent desktop clutter.
* **Explorer Integration:** Forces Windows File Explorer to instantly focus and highlight newly locked or unlocked items to give you immediate visual confirmation.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have Python 3.8 or higher installed on your machine. Tkinter ships
with Python, so the only third-party dependency is the `cryptography` library —
listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```

### Installation
Clone this repository and navigate to the project folder:
```bash
git clone https://github.com/Manoj-2424150118/FoldCrypt.git
cd FoldCrypt
```
Make sure `logo.png`, `eye_open.png`, and `eye_closed.png` are in the same directory as the main script for the UI to load perfectly.

### Running the Application
Launch the graphical interface natively by executing:
```bash
pythonw main.py
```
*(Note: Using `pythonw` instead of `python` ensures the background terminal console is suppressed for a pure GUI experience).*

---

## 🔐 Security Design

FoldCrypt does not rely on folder permissions — the folder's bytes are actually
encrypted. The pipeline in `main.py` (`lock_folder` / `unlock_file` / `get_key`) is:

1. **Archive:** the folder is zipped (`shutil.make_archive`) into a temporary archive.
2. **Key derivation:** your password is run through **PBKDF2HMAC-SHA256** with a fresh
   16-byte random salt (`os.urandom`) and **480,000 iterations**, producing a 32-byte
   key (URL-safe Base64-encoded, as Fernet expects).
3. **Encryption:** the archive is encrypted with **Fernet** — AES-128-CBC with an
   HMAC-SHA256 authentication tag, so tampering with the `.fsl` file is detected on
   unlock instead of silently producing corrupt output.
4. **Cleanup:** the temporary zip and the original folder are deleted, leaving only
   the `.fsl` file.

### `.fsl` file format

```
┌────────────────────┬───────────────────────────────────┐
│ Salt (16 bytes)    │ Fernet token (encrypted ZIP data) │
└────────────────────┴───────────────────────────────────┘
```

The salt is stored in the clear as the first 16 bytes — it is not secret; it only
needs to be unique per lock so the same password never derives the same key twice.
On Windows the `.fsl` file also gets the system *hidden* attribute; on other
platforms it is written with a leading dot (`.<folder>.fsl`).

A wrong password fails Fernet's HMAC verification, and the app reports
*"Incorrect password. Access Denied."* — there is **no password recovery**, by design.

> ⚠️ **Important:** locking a folder deletes the original unencrypted folder, and
> unlocking deletes the `.fsl` file. Keep a backup of anything irreplaceable, and
> never lose the password — without it the data cannot be recovered.

---

## 📁 Project Structure

| File | Purpose |
| --- | --- |
| `main.py` | The whole application — key derivation, lock/unlock engine, and the Tkinter GUI (`FoldCryptApp`) |
| `requirements.txt` | Python dependencies (just `cryptography`) |
| `logo.png` | App / window icon |
| `eye_open.png` / `eye_closed.png` | Password-visibility toggle icons (text/emoji fallback if missing) |
| `LICENSE` | MIT License |

---

## 🔒 How to Use

### To Lock a Folder:
1. Open the **Lock Folder** tab.
2. Click **Browse** and select the folder you want to secure.
3. Enter your desired password in both fields (you can click the eye icon to verify).
4. Click **Lock**. 
5. The application will compress your folder, encrypt it, securely delete the original unencrypted files, and output a hidden `.fsl` file in the exact same directory. 

### To Unlock a Folder:
1. Open the **Unlock Folder** tab.
2. Click **Browse** and select your `.fsl` file.
3. Enter the exact password used to lock it.
4. Click **Unlock**.
5. The application will decrypt the file, extract the original folder, and securely remove the `.fsl` file.

---

## 🖼️ UI Assets & Customization
FoldCrypt dynamically loads `.png` assets to render its UI. 
- **`logo.png`**: Loaded natively into the Window title bar and taskbar (auto-scaled).
- **`eye_open.png` / `eye_closed.png`**: Custom interactive icons for the password entry masking.

If these images are missing, FoldCrypt seamlessly falls back to standard text and unicode emojis (`👁️`, `🔒`, etc.) ensuring the app never breaks.

## ❓ Troubleshooting

- **"A locked file for this folder already exists."** — a `.fsl` file with the same
  folder name is already in that directory. Unlock or move it before locking again.
- **"A folder named '…' already exists here."** — unlocking would overwrite an
  existing folder, so FoldCrypt refuses. Move or rename that folder first.
- **"Incorrect password. Access Denied."** — the password doesn't match the one used
  to lock the file (Fernet HMAC verification failed). Passwords are case-sensitive
  and there is no reset option.
- **The window opens without icons** — make sure `logo.png`, `eye_open.png`, and
  `eye_closed.png` sit next to `main.py`; the UI falls back to text/emoji icons if
  they are missing.

---

## 🛠️ Built With
* [Python 3](https://www.python.org/) - Core logic
* [Tkinter](https://docs.python.org/3/library/tkinter.html) - Graphical User Interface
* [Cryptography](https://cryptography.io/en/latest/) - AES Fernet Encryption Engine

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
