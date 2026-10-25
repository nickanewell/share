"""Offline source-preparation fixtures; no network, registry or production writes."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
spec = importlib.util.spec_from_file_location("prepare_release", HERE / "prepare_release.py")
prep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prep)
spec = importlib.util.spec_from_file_location("brand_overlay", HERE / "brand_overlay.py")
brand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brand)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rival-source-test-")
        self.root = Path(self.temp.name).resolve()
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        self.g(self.upstream, "init", "--initial-branch=main")
        self.write(self.upstream, "app.txt", "first\nsecond\nthird\n")
        self.write(self.upstream, "Dockerfile", "upstream recipe\n")
        self.write(self.upstream, ".github/workflows/publish.yml", "upstream publishing\n")
        self.write(self.upstream, "test/security/cli-download.test.mjs", "upstream tests\n")
        self.write(self.upstream, "packages/frontend/src/app.html", "upstream title\n")
        for path in prep.SECURITY_PATHS:
            self.write(self.upstream, path, "original\nsecond\nthird\n")
        for path in brand.ASSETS:
            self.write(self.upstream, path, "upstream artwork\n")
        self.fixture = b"materialized trusted LFS fixture"
        self.pointer = ("version https://git-lfs.github.com/spec/v1\noid sha256:"
                        + hashlib.sha256(self.fixture).hexdigest() + "\nsize " + str(len(self.fixture)) + "\n")
        self.write(self.upstream, "test/assets/example.bin", self.pointer)
        self.commit(self.upstream, "base")
        self.base = self.sha(self.upstream)
        self.g(self.upstream, "tag", "v2.9.3")
        self.control = self.root / "control"
        self.g(self.root, "clone", str(self.upstream), str(self.control), local=True)
        self.write(self.control, ".upstream-sync.json", json.dumps({
            "repository": prep.UPSTREAM, "major": 2, "current_tag": "v2.9.3",
            "current_commit": self.base,
            "protected_paths": ["packages/frontend/src/app.html", *sorted(brand.ASSETS),
                                "packages/frontend/static/branding"],
        }))
        for path in prep.REQUIRED_CONTRACTS:
            if not (self.control / path).exists():
                self.write(self.control, path, "trusted contract\n")
        self.write(self.control, "Dockerfile", "trusted recipe\n")
        self.write(self.control, ".dockerignore", "trusted exclusions\n")
        self.write(self.control, ".github/workflows/publish.yml", "trusted workflow\n")
        self.write(self.control, "test/security/cli-download.test.mjs", "trusted security test\n")
        self.write(self.control, "packages/frontend/src/app.html", "Rival IT title\n")
        self.write(self.control, prep.SECURITY_PATHS[0], "fork security patch\nsecond\nthird\n")
        for path in brand.ASSETS:
            self.write(self.control, path, "approved artwork: " + path)
        manifest = {"format": "rival-it-brand-overlay", "version": 1, "assets": {
            path: hashlib.sha256((self.control / path).read_bytes()).hexdigest() for path in brand.ASSETS}}
        self.write(self.control, "deploy/automatic/brand-manifest.json", json.dumps(manifest))
        self.write(self.control, "scripts/upstream_update.py", (REPO / "scripts/upstream_update.py").read_text())
        self.commit(self.control, "trusted fork")
        self.control_sha = self.sha(self.control)
        # Materialization is clean by the LFS pointer contract, without running
        # any local clean/smudge program. Candidate checkout retains the pointer.
        self.write(self.control, "test/assets/example.bin", self.fixture)
        self.output = self.root / "output"
        self.output.mkdir()
        self.candidate = self.output / "candidate"

    def tearDown(self):
        self.temp.cleanup()

    def g(self, root, *args, **kwargs):
        return prep.git(root, *args, **kwargs)

    def write(self, root, path, content):
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content.encode() if isinstance(content, str) else content)

    def commit(self, root, message):
        self.g(root, "add", ".")
        self.g(root, "-c", "user.name=Local fixture", "-c", "user.email=test@example.invalid", "commit", "-m", message)

    def sha(self, root):
        return self.g(root, "rev-parse", "HEAD").stdout.decode().strip()

    def release(self, changes=None):
        changes = changes or {"app.txt": "updated\nsecond\nthird\n"}
        for path, content in changes.items():
            self.write(self.upstream, path, content)
        self.commit(self.upstream, "release")
        self.g(self.upstream, "tag", "v2.9.4")
        return self.sha(self.upstream)

    def prepare(self, sha, **kwargs):
        return prep.prepare_from_refs(self.control, self.candidate, "v2.9.4", sha, self.upstream, **kwargs)

    def assert_no_artifacts(self):
        self.assertFalse((self.output / "source.bundle").exists())
        self.assertFalse((self.output / "release-input.json").exists())

    def test_prepares_exact_source_and_preserves_all_trusted_contracts(self):
        changes = {"app.txt": "updated\nsecond\nthird\n", "Dockerfile": "malicious upstream recipe\n",
                   ".github/workflows/publish.yml": "publish to inherited registry\n",
                   "test/security/cli-download.test.mjs": "security checks removed\n"}
        changes.update({path: "new upstream artwork\n" for path in brand.ASSETS})
        target = self.release(changes)
        before = prep.contract_digest(self.control)
        result = self.prepare(target)
        self.assertEqual((self.candidate / "app.txt").read_text(), changes["app.txt"])
        self.assertEqual((self.candidate / "Dockerfile").read_text(), "trusted recipe\n")
        self.assertEqual((self.candidate / prep.SECURITY_PATHS[0]).read_text(), "fork security patch\nsecond\nthird\n")
        for path in brand.ASSETS:
            self.assertEqual((self.candidate / path).read_bytes(), (self.control / path).read_bytes())
        self.assertEqual((self.candidate / "test/assets/example.bin").read_text(), self.pointer)
        self.assertEqual(result["security_contract_sha256"], before)
        self.assertEqual(prep.contract_digest(self.candidate), before)
        self.assertEqual(set(result), {"format", "schema_version", "repository", "control_commit", "source_commit",
                                      "upstream_repository", "upstream_tag", "upstream_commit", "branding_sha256",
                                      "security_contract_sha256", "file_format_version", "release_parent"})
        self.assertEqual(result["format"], "rival-it-share-source")
        self.assertEqual(result["control_commit"], self.control_sha)
        self.assertEqual(result["upstream_commit"], target)
        self.assertEqual(result["file_format_version"], 2)
        self.assertIsNone(result["release_parent"])
        self.assertEqual(json.loads((self.output / "release-input.json").read_text()), result)
        self.assertEqual(self.g(self.candidate, "bundle", "list-heads", str(self.output / "source.bundle")).stdout.decode().strip(),
                         result["source_commit"] + " refs/heads/automation-candidate")
        prep.require_clean(self.candidate)

    def test_conflicting_custom_security_patch_stops_without_publication(self):
        target = self.release({prep.SECURITY_PATHS[0]: "upstream rewrite\nsecond\nthird\n"})
        with self.assertRaises((ValueError, RuntimeError)):
            self.prepare(target)
        self.assert_no_artifacts()

    def test_even_nonconflicting_security_change_requires_manual_review(self):
        target = self.release({prep.SECURITY_PATHS[1]: "original\nsecond\nnew security-sensitive behavior\n"})
        with self.assertRaisesRegex(ValueError, "security contract"):
            self.prepare(target)
        self.assert_no_artifacts()

    def test_backend_and_create_security_wiring_changes_require_review(self):
        previous = None
        for index, path in enumerate(("packages/backend/src/main.rs",
                                      "packages/frontend/src/lib/views/Create.svelte")):
            with self.subTest(path=path):
                if previous:
                    self.write(self.upstream, previous, "original\nsecond\nthird\n")
                self.write(self.upstream, path, "original\nsecond\nchanged security wiring\n")
                self.commit(self.upstream, "change wiring")
                tag = f"v2.9.{4 + index}"
                self.g(self.upstream, "tag", tag)
                with self.assertRaisesRegex(ValueError, "security contract"):
                    prep.prepare_from_refs(self.control, self.candidate, tag, self.sha(self.upstream), self.upstream)
                self.assert_no_artifacts()
                shutil.rmtree(self.candidate)
                previous = path

    def test_branding_integration_code_is_not_blindly_overwritten(self):
        target = self.release({"packages/frontend/src/app.html": "upstream security-sensitive head change\n"})
        with self.assertRaisesRegex(RuntimeError, "protected branding"):
            self.prepare(target)
        self.assert_no_artifacts()

    def test_expected_target_and_baseline_tag_are_both_pinned(self):
        target = self.release()
        with self.assertRaisesRegex(ValueError, "tag moved"):
            self.prepare("f" * 40)
        self.assert_no_artifacts()
        shutil.rmtree(self.candidate)
        self.g(self.upstream, "tag", "-f", "v2.9.3", target)
        with self.assertRaisesRegex(ValueError, "tag moved"):
            self.prepare(target)
        self.assert_no_artifacts()

    def test_unsupported_major_and_dirty_control_stop_before_clone(self):
        target = self.release()
        with self.assertRaisesRegex(ValueError, "major-2"):
            prep.prepare_from_refs(self.control, self.candidate, "v3.0.0", target, self.upstream)
        self.assertFalse(self.candidate.exists())
        self.write(self.control, "app.txt", "unsaved work")
        with self.assertRaisesRegex(ValueError, "Working tree differs"):
            self.prepare(target)
        self.assertFalse(self.candidate.exists())

    def test_upstream_symlink_is_rejected_before_applying_delta(self):
        (self.upstream / "escape").symlink_to("../outside")
        target = self.release()
        with self.assertRaisesRegex(ValueError, "symlinks and submodules"):
            self.prepare(target)
        self.assert_no_artifacts()

    def test_new_tool_configuration_is_rejected(self):
        target = self.release({"packages/frontend/.npmrc": "onload-script=untrusted\n"})
        with self.assertRaisesRegex(ValueError, "tool configuration"):
            self.prepare(target)
        self.assert_no_artifacts()

    def test_release_parent_is_history_only_and_guarded(self):
        target = self.release()
        self.g(self.control, "switch", "-c", "automation/release-v2")
        self.write(self.control, "untrusted-parent-only.txt", "never inherit this tree")
        self.commit(self.control, "old release branch")
        parent = self.sha(self.control)
        self.g(self.control, "switch", "--detach", self.control_sha)
        self.write(self.control, "test/assets/example.bin", self.fixture)
        result = self.prepare(target, release_parent=parent)
        self.assertFalse((self.candidate / "untrusted-parent-only.txt").exists())
        parents = self.g(self.candidate, "show", "-s", "--format=%P", result["source_commit"]).stdout.decode().split()
        self.assertEqual(parents, [self.control_sha, parent])
        self.assertEqual(result["release_parent"], parent)

    def test_changed_release_branch_guard_does_not_publish(self):
        target = self.release()
        self.g(self.control, "branch", "automation/release-v2", self.base)
        with self.assertRaisesRegex(ValueError, "release branch changed"):
            self.prepare(target, release_parent=self.control_sha)
        self.assert_no_artifacts()

    def test_lfs_normalization_rejects_corrupted_materialized_fixture(self):
        first = prep.contract_digest(self.control)
        self.write(self.control, "test/assets/example.bin", self.pointer)
        self.assertEqual(prep.contract_digest(self.control), first)
        self.write(self.control, "test/assets/example.bin", b"corrupted")
        with self.assertRaisesRegex(ValueError, "Working tree differs"):
            prep.contract_digest(self.control)

    def test_existing_artifacts_and_shell_shaped_commit_are_rejected(self):
        target = self.release()
        with self.assertRaisesRegex(ValueError, "commit identities"):
            self.prepare("--upload-pack=bad")
        self.assertFalse(self.candidate.exists())
        (self.output / "source.bundle").write_bytes(b"keep existing")
        with self.assertRaisesRegex(ValueError, "Fresh exclusive artifact"):
            self.prepare(target)
        self.assertEqual((self.output / "source.bundle").read_bytes(), b"keep existing")


if __name__ == "__main__":
    unittest.main()
