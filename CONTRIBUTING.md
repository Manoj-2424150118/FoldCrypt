# Contributing to FoldCrypt

Thanks for helping improve FoldCrypt. This guide covers the setup, the
test suite, and the ground rules that keep a folder-encryption tool safe
to change. Everything here is grounded in `README.md`, `SECURITY.md`,
and the CI workflow (`.github/workflows/tests.yml`).

## Setup

- **Python 3.8+**, with Tkinter (ships with standard python.org installs
  and most OS Pythons).
- The only third-party dependency is `cryptography` (Fernet + PBKDF2HMAC),
  declared in `requirements.txt`:

```bash
git clone https://github.com/Manoj-2424150118/FoldCrypt.git
cd FoldCrypt
pip install -r requirements.txt
```

Keep `logo.png`, `eye_open.png`, and `eye_closed.png` next to `main.py` —
the GUI loads them from there and falls back to text/emoji icons if they
are missing.

## Run

```bash
python main.py        # any platform
pythonw main.py       # Windows: same, without a background console window
```

## Tests

The cryptographic core is tested headlessly — no GUI is launched:

```bash
python -m unittest discover -s tests -v    # 11 tests
```

| Test file | Covers |
|---|---|
| `tests/test_lock_unlock.py` (5 tests) | Key derivation (deterministic per password+salt, salt/password sensitivity, 32-byte key); full lock→unlock round-trip restoring exact bytes; wrong password refused with the `.fsl` kept; lock refused when a `.fsl` already exists |
| `tests/test_integrity_manifest.py` (6 tests) | Manifest build/verify units; tampered, missing and unexpected-extra file detection; reserved manifest-name refusal; full round-trip leaving no manifest behind; legacy (pre-manifest) archives still unlock |

**Run the full suite before opening a PR, and keep it green.** CI runs the
same command on Python 3.12 (workflow `Tests`, on pushes and PRs touching
`**.py`, `requirements.txt`, or the workflow itself). If you add or remove
a test, update the test count and the test table in `README.md` to match —
the README states "11 tests" and the per-file breakdown.

## How the code is organised

Everything lives in `main.py`: the cryptographic core (`get_key`,
`lock_folder`, `unlock_file`, `build_manifest`, `verify_extracted`) is
GUI-independent and headlessly testable; the Tkinter layer
(`FoldCryptApp`) runs the core on a worker thread and reports progress
through a callback. Prefer changing the core over the GUI when a fix can
be expressed there, and cover it with a headless test.

Compatibility rules — do not break these without a deliberate, documented
decision:

- **Legacy archives must keep unlocking.** Archives locked by older
  versions (no manifest) unlock normally, with verification skipped and
  reported. A change that refuses them is a breaking change.
- **The manifest format is version 1** (`foldcrypt-manifest.json`:
  SHA-256 + size per file, keyed by POSIX relative path). If the format
  ever changes, bump the version and keep v1 readable.
- **Lock refuses when a `.fsl` already exists** and when the folder
  contains the reserved manifest filename; **unlock refuses to overwrite
  an existing folder** and keeps the `.fsl` when verification fails.
  These refusals protect the user's only copy — do not weaken them.

## Ground rules

- **Never commit secrets.** No passwords, keys, salts from real locks, or
  real `.fsl` files. Test only on throwaway folders and throwaway
  passwords — locking **permanently deletes the original folder**, and
  there is **no password recovery**.
- **Do not roll your own crypto.** FoldCrypt's guarantees rest on the
  `cryptography` library's Fernet and PBKDF2 implementations. Changes
  touch parameters and plumbing, never primitives.
- **Report vulnerabilities privately.** Do not open a public issue for a
  security flaw — follow `SECURITY.md` (GitHub private vulnerability
  reporting).
- **Keep the docs honest.** The README documents the threat model, the
  `.fsl` format, and the honest limitations (no recovery, locking deletes
  the original). If a change alters behaviour, update the README section
  that describes it in the same PR.

## Pull requests

- Keep PRs focused: one change, one purpose.
- Use conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`,
  `refactor:`, `perf:` with the `foldcrypt` scope where it helps, e.g.
  `fix(foldcrypt): …`).
- Describe what you tested (`python -m unittest discover -s tests -v`
  output) in the PR.
