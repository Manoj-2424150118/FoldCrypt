"""Integrity-manifest tests for FoldCrypt.

The manifest is what lets unlock *prove* the restored folder matches
what was locked, instead of trusting that extraction went well.
Covered here: manifest build/verify units, tamper/missing/extra
detection, the reserved-name guard, a full round trip (manifest must
not leak into the restored folder), and backward compatibility with
archives locked before the manifest existed.

Run:  python3 -m unittest discover -s tests -v   (needs `cryptography`)
"""

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


def _make_tree(root: Path) -> dict:
    (root / "nested").mkdir(parents=True)
    (root / "hello.txt").write_text("hello foldcrypt\n")
    (root / "nested" / "data.bin").write_bytes(bytes(range(256)))
    return {
        p.relative_to(root): p.read_bytes()
        for p in root.rglob("*") if p.is_file()
    }


class TestManifestUnits(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="foldcrypt-manifest-"))
        self.src = self.tmp / "docs"
        self.src.mkdir()
        _make_tree(self.src)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_build_and_verify_clean_tree(self):
        manifest = main.build_manifest(self.src)
        self.assertEqual(manifest["version"], main.MANIFEST_VERSION)
        self.assertEqual(set(manifest["files"]), {"hello.txt", "nested/data.bin"})
        self.assertEqual(main.verify_extracted(self.src, manifest), [])

    def test_verify_detects_changed_content(self):
        manifest = main.build_manifest(self.src)
        target = self.src / "hello.txt"
        target.write_bytes(b"hello foldcrypt?")  # same length, different bytes
        problems = main.verify_extracted(self.src, manifest)
        self.assertTrue(any("content changed: hello.txt" in p for p in problems), problems)

    def test_verify_detects_missing_and_extra(self):
        manifest = main.build_manifest(self.src)
        (self.src / "nested" / "data.bin").unlink()
        (self.src / "surprise.txt").write_text("not in the manifest")
        problems = main.verify_extracted(self.src, manifest)
        self.assertTrue(any("missing" in p and "data.bin" in p for p in problems), problems)
        self.assertTrue(any("extra" in p and "surprise.txt" in p for p in problems), problems)


class TestManifestRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="foldcrypt-manifest-rt-"))
        self.src = self.tmp / "secret"
        self.src.mkdir()
        self.original = _make_tree(self.src)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _locked_file(self):
        name = f".{self.src.name}.fsl" if os.name != "nt" else f"{self.src.name}.fsl"
        return self.tmp / name

    def test_round_trip_verifies_and_leaves_no_manifest(self):
        main.lock_folder(self.src, "correct horse", _noop)
        main.unlock_file(self._locked_file(), "correct horse", _noop)
        restored_root = self.tmp / "secret"
        restored = {
            p.relative_to(restored_root): p.read_bytes()
            for p in restored_root.rglob("*") if p.is_file()
        }
        self.assertEqual(restored, self.original)
        self.assertNotIn(Path(main.MANIFEST_NAME), restored)

    def test_reserved_manifest_name_is_refused(self):
        (self.src / main.MANIFEST_NAME).write_text("{}")
        with self.assertRaises(Exception) as ctx:
            main.lock_folder(self.src, "correct horse", _noop)
        self.assertIn("reserved", str(ctx.exception))
        self.assertTrue(self.src.exists())  # nothing was locked or deleted

    def test_legacy_archive_without_manifest_still_unlocks(self):
        # Build an .fsl exactly the way pre-manifest FoldCrypt did:
        # zip the folder, Fernet-encrypt, prepend the salt.
        from cryptography.fernet import Fernet

        zip_base = self.tmp / "legacy_temp"
        shutil.make_archive(base_name=str(zip_base), format="zip", root_dir=self.src)
        salt = os.urandom(16)
        token = Fernet(main.get_key("correct horse", salt)).encrypt(
            (self.tmp / "legacy_temp.zip").read_bytes()
        )
        legacy = self._locked_file()
        legacy.write_bytes(salt + token)
        shutil.rmtree(self.src)

        main.unlock_file(legacy, "correct horse", _noop)
        restored_root = self.tmp / "secret"
        restored = {
            p.relative_to(restored_root): p.read_bytes()
            for p in restored_root.rglob("*") if p.is_file()
        }
        self.assertEqual(restored, self.original)


if __name__ == "__main__":
    unittest.main()
