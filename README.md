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
Make sure you have Python 3.8 or higher installed on your machine. You will also need the `cryptography` library.
```bash
pip install cryptography
```

### Installation
Clone this repository and navigate to the project folder:
```bash
git clone https://github.com/yourusername/FoldCrypt.git
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

## 🛠️ Built With
* [Python 3](https://www.python.org/) - Core logic
* [Tkinter](https://docs.python.org/3/library/tkinter.html) - Graphical User Interface
* [Cryptography](https://cryptography.io/en/latest/) - AES Fernet Encryption Engine

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
