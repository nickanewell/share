"""Offline artwork preservation/security checks; never touches production."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("brand_overlay", HERE / "brand_overlay.py")
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rival-brand-test-")
        self.root = Path(self.temp.name).resolve()
        self.source, self.target, self.outside = [self.root / name for name in ("source", "target", "outside")]
        for root in (self.source, self.target, self.outside):
            root.mkdir()
        self.contents = {p: ("approved artwork: " + p).encode() for p in overlay.ASSETS}
        for p, content in self.contents.items():
            path = self.source / p
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.manifest = {"format": "rival-it-brand-overlay", "version": 1,
                         "assets": {p: hashlib.sha256(v).hexdigest() for p, v in self.contents.items()}}

    def tearDown(self):
        self.temp.cleanup()

    def apply(self, **kwargs):
        return overlay.apply_overlay(kwargs.get("source", self.source), kwargs.get("target", self.target),
                                     kwargs.get("manifest", self.manifest))

    def assert_target_empty(self):
        self.assertEqual(list(self.target.iterdir()), [])

    def test_replaces_upstream_artwork_byte_exact_and_is_idempotent(self):
        for p in self.contents:
            path = self.target / p
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"upstream artwork")
        code = self.target / "Header.svelte"
        code.write_text("upstream code remains unchanged")
        expected = [{"path": p, "sha256": self.manifest["assets"][p]} for p in sorted(self.contents)]
        self.assertEqual(self.apply(), expected)
        self.assertEqual(self.apply(), expected)
        for p, content in self.contents.items():
            self.assertEqual((self.target / p).read_bytes(), content)
        self.assertEqual(code.read_text(), "upstream code remains unchanged")

    def test_tampered_source_fails_before_any_write(self):
        (self.source / sorted(self.contents)[-1]).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "hash/size"):
            self.apply()
        self.assert_target_empty()

    def test_missing_source_fails_before_any_write(self):
        (self.source / sorted(self.contents)[-1]).unlink()
        with self.assertRaises((ValueError, OSError)):
            self.apply()
        self.assert_target_empty()

    def test_traversal_and_unapproved_code_paths_are_rejected(self):
        for path in ("../outside/art.svg", "/outside/art.svg", "packages/frontend/src/app.html"):
            bad = copy.deepcopy(self.manifest)
            bad["assets"][path] = "0" * 64
            with self.assertRaisesRegex(ValueError, "approved artwork paths"):
                self.apply(manifest=bad)
            self.assert_target_empty()

    def test_destination_symlink_ancestor_cannot_escape(self):
        (self.target / "packages").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.apply()
        self.assertEqual(list(self.outside.iterdir()), [])
        self.assertEqual(list(self.target.iterdir()), [self.target / "packages"])

    def test_source_symlink_and_non_directory_ancestor_are_rejected(self):
        asset = self.source / sorted(self.contents)[-1]
        asset.unlink()
        external = self.outside / "artwork"
        external.write_bytes(self.contents[str(asset.relative_to(self.source))])
        asset.symlink_to(external)
        with self.assertRaises(OSError):
            self.apply()
        self.assert_target_empty()
        (self.target / "packages").write_text("not a directory")
        asset.unlink()
        asset.write_bytes(external.read_bytes())
        with self.assertRaises(OSError):
            self.apply()
        self.assertEqual(list(self.target.iterdir()), [self.target / "packages"])

    def test_destination_asset_symlink_is_rejected_before_other_writes(self):
        asset = self.target / sorted(self.contents)[-1]
        asset.parent.mkdir(parents=True)
        external = self.outside / "untouched"
        external.write_bytes(b"do not change")
        asset.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.apply()
        self.assertEqual(external.read_bytes(), b"do not change")
        self.assertEqual(len(list(self.target.rglob("*"))), len(asset.relative_to(self.target).parts))

    def test_overlapping_and_symlink_roots_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            self.apply(target=self.source)
        link = self.root / "target-link"
        link.symlink_to(self.target, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.apply(target=link)
        ancestor = self.root / "ancestor-link"
        ancestor.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directories"):
            self.apply(target=ancestor / "target")
        self.assert_target_empty()

    def test_manifest_is_strict_and_rejects_duplicate_keys(self):
        for mutation in ({"version": True}, {"extra": 1}, {"assets": {}}):
            bad = dict(self.manifest, **mutation)
            with self.assertRaises(ValueError):
                self.apply(manifest=bad)
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text('{"version":1,"version":2}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            overlay.load_manifest(manifest_path)
        link = self.root / "manifest-link.json"
        link.symlink_to(manifest_path)
        with self.assertRaises(OSError):
            overlay.load_manifest(link)
        self.assert_target_empty()

    def test_checked_in_manifest_matches_approved_assets(self):
        manifest = overlay.load_manifest(HERE / "brand-manifest.json")
        repository = HERE.parents[1]
        for path, expected in manifest["assets"].items():
            self.assertEqual(hashlib.sha256((repository / path).read_bytes()).hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
