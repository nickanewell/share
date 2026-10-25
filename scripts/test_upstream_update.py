"""Offline selection and local Git safety tests; no GitHub writes or network."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("updater", Path(__file__).with_name("upstream_update.py"))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class ReleaseSelectionTests(unittest.TestCase):
    def test_only_newer_stable_same_major_is_proposed(self):
        def release(tag, **flags):
            return dict(tag_name=tag, draft=False, prerelease=False, published_at="2026-10-24", **flags)
        releases = [release("v2.9.3"), release("v2.10.0"), release("v2.9.9"), release("v3.0.0"),
                    release("v2.11.0-rc.1"), release("bad\ntag"), release("v2.09.9")]
        releases += [dict(tag_name="v2.99.0", draft=True, prerelease=False, published_at="2026-10-24"),
                     dict(tag_name="v2.98.0", draft=False, prerelease=True, published_at="2026-10-24"),
                     dict(tag_name="v2.97.0", draft=False, prerelease=False, published_at=None)]
        result = updater.select_release(releases, {"current_tag": "v2.9.3", "major": 2})
        self.assertEqual(result, dict(available=True, tag="v2.10.0", branch="automation/upstream-v2.10.0", major_available="v3.0.0"))

    def test_no_downgrades_or_shell_shaped_tags(self):
        result = updater.select_release(
            [dict(tag_name=tag, published_at="2026-10-24") for tag in ("v2.9.2", "v2.9.3", "v2.9.4;echo bad", "--help")],
            {"current_tag": "v2.9.3", "major": 2},
        )
        self.assertFalse(result["available"])


class DeltaSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cryptgeon-update-test-")
        self.root = Path(self.temp.name)
        self.g("init", "--initial-branch=main")
        self.g("config", "user.name", "Local test")
        self.g("config", "user.email", "test@example.invalid")
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / ".github/workflows/release.yml").write_text("disabled in fork\n")
        (self.root / "app.txt").write_text("first\nsecond\nthird\n")
        (self.root / "branding.svg").write_text("upstream mark\n")
        self.commit("base")
        self.base = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.config = {"protected_paths": ["branding.svg"]}

    def tearDown(self):
        self.temp.cleanup()

    def g(self, *args, **kwargs):
        return updater.git(self.root, *args, **kwargs)

    def commit(self, message):
        self.g("add", ".")
        self.g("commit", "-m", message)

    def upstream(self, branding=False):
        self.g("switch", "-c", "upstream")
        (self.root / "app.txt").write_text("updated\nsecond\nthird\n")
        (self.root / ".github/workflows/release.yml").write_text("publish to upstream\n")
        if branding:
            (self.root / "branding.svg").write_text("changed upstream mark\n")
        self.commit("release")
        target = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.g("switch", "-c", "fork", self.base)
        (self.root / "branding.svg").write_text("Rival IT mark\n")
        (self.root / "custom.txt").write_text("fork-only patch\n")
        self.commit("fork changes")
        return target

    def test_preserves_branding_local_patches_and_fork_workflows(self):
        target = self.upstream()
        head = self.g("rev-parse", "HEAD").stdout
        updater.apply_delta(self.root, self.base, target, self.config)
        self.assertEqual((self.root / "app.txt").read_text(), "updated\nsecond\nthird\n")
        self.assertEqual((self.root / "branding.svg").read_text(), "Rival IT mark\n")
        self.assertEqual((self.root / "custom.txt").read_text(), "fork-only patch\n")
        self.assertEqual((self.root / ".github/workflows/release.yml").read_text(), "disabled in fork\n")
        self.assertEqual(self.g("rev-parse", "HEAD").stdout, head, "Applying a delta must not commit or push")

    def test_protected_branding_change_stops_before_applying(self):
        target = self.upstream(branding=True)
        with self.assertRaisesRegex(RuntimeError, "protected branding"):
            updater.apply_delta(self.root, self.base, target, self.config)
        self.assertFalse(self.g("status", "--porcelain").stdout)
        self.assertEqual((self.root / "app.txt").read_text(), "first\nsecond\nthird\n")

    def test_conflicting_local_security_patch_stops_without_commit(self):
        target = self.upstream()
        (self.root / "app.txt").write_text("fork security patch\nsecond\nthird\n")
        self.commit("local security patch")
        head = self.g("rev-parse", "HEAD").stdout
        with self.assertRaises(RuntimeError):
            updater.apply_delta(self.root, self.base, target, self.config)
        self.assertEqual(self.g("rev-parse", "HEAD").stdout, head)
        self.assertTrue(self.g("ls-files", "--unmerged").stdout)

    def test_dirty_tree_stops_before_applying(self):
        target = self.upstream()
        (self.root / "untracked.txt").write_text("work in progress\n")
        with self.assertRaisesRegex(RuntimeError, "clean working tree"):
            updater.apply_delta(self.root, self.base, target, self.config)
        self.assertEqual((self.root / "app.txt").read_text(), "first\nsecond\nthird\n")

    def test_create_only_lease_rejects_a_racing_existing_branch(self):
        with tempfile.TemporaryDirectory(prefix="cryptgeon-bare-test-") as bare:
            subprocess.run(["git", "init", "--bare", bare], check=True, capture_output=True)
            branch = "refs/heads/automation/upstream-v2.9.4"
            self.g("push", bare, "HEAD:" + branch)
            original = self.g("rev-parse", "HEAD").stdout.decode().strip()
            (self.root / "app.txt").write_text("new proposal\n")
            self.commit("new proposal")
            result = self.g("push", "--force-with-lease=" + branch + ":", bare, "HEAD:" + branch, check=False)
            self.assertNotEqual(result.returncode, 0)
            remote = subprocess.run(["git", "--git-dir", bare, "rev-parse", branch], check=True, capture_output=True)
            self.assertEqual(remote.stdout.decode().strip(), original)


if __name__ == "__main__":
    unittest.main()
