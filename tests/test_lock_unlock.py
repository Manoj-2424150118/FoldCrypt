"""Headless round-trip tests for FoldCrypt's lock/unlock core.

Covers main.lock_folder / main.unlock_file without launching the Tk GUI:
the functions only need an update_progress callback, so they run under
plain unittest. The GUI (FoldCryptApp) is deliberately not exercised here.

Run:  python3 -m unittest discover -s tests -v   (needs `cryptography`)
"""

import base64
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402


def _noop(_percent, _text):
    pass


class TestGetKey(unittest.TestCase):
    def test_deterministic_for_same_password_and_salt(self):
        self.assertEqual(main.get_key("pw", b"0" * 16),
                         main.get_key("pw", b"0" * 16))

    def test_salt_and_password_sensitive(self):
        key = main.get_key("pw", b"0" * 16)
        self.assertNotEqual(key, main.get_key("pw", b"1" * 16))
        self.assertNotEqual(key, main.get_key("other", b"0" * 16))
        # PBKDF2 length=32, urlsafe-base64 encoded.
        self.assertEqual(len(base64.urlsafe_b64decode(key)), 32)


class TestLockUnlockRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="foldcrypt-test-"))
        self.src = self.tmp / "secret"
        (self.src / "nested").mkdir(parents=True)
        (self.src / "hello.txt").write_text("hello foldcrypt\n")
        (self.src / "nested" / "data.bin").write_bytes(bytes(range(256)))
        self.original = {
            p.relative_to(self.src): p.read_bytes()
            for p in self.src.rglob("*") if p.is_file()
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _locked_file(self):
        # On non-Windows, lock_folder writes a dot-prefixed .fsl file.
        name = f".{self.src.name}.fsl" if os.name != "nt" \
            else f"{self.src.name}.fsl"
        return self.tmp / name

    def test_round_trip_restores_bytes(self):
        main.lock_folder(self.src, "correct horse", _noop)
        locked = self._locked_file()
        self.assertTrue(locked.is_file())
        self.assertFalse(self.src.exists())  # lock removes the source
        # First 16 bytes are the salt, the rest the Fernet ciphertext.
        self.assertGreater(locked.stat().st_size, 16)

        main.unlock_file(locked, "correct horse", _noop)
        self.assertFalse(locked.exists())  # unlock removes the .fsl file
        restored = {
            p.relative_to(self.tmp / "secret"): p.read_bytes()
            for p in (self.tmp / "secret").rglob("*") if p.is_file()
        }
        self.assertEqual(restored, self.original)

    def test_wrong_password_refused_and_locked_file_kept(self):
        main.lock_folder(self.src, "correct horse", _noop)
        locked = self._locked_file()
        copy = self.tmp / "copy.fsl"
        shutil.copyfile(locked, copy)
        with self.assertRaises(Exception) as ctx:
            main.unlock_file(copy, "wrong password", _noop)
        self.assertIn("Incorrect password", str(ctx.exception))
        self.assertTrue(copy.is_file())
        self.assertFalse((self.tmp / "copy").exists())

    def test_lock_refuses_when_locked_file_exists(self):
        main.lock_folder(self.src, "correct horse", _noop)
        # Recreate a source folder with the same name and lock again.
        self.src.mkdir()
        (self.src / "x.txt").write_text("x")
        with self.assertRaises(Exception):
            main.lock_folder(self.src, "correct horse", _noop)


if __name__ == "__main__":
    unittest.main()
