"""Local Git/archive fixtures and mocked external publication; no network."""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("publish_release", HERE / "publish_release.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
prep = publisher.sibling("prepare_release")
brand = publisher.sibling("brand_overlay")


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rival-publish-test-")
        self.root = Path(self.temp.name).resolve()
        self.control, self.candidate, self.artifacts = [self.root / p for p in ("control", "candidate", "artifacts")]
        self.control.mkdir(); self.artifacts.mkdir()
        self.output, self.remote = self.root / "release-output", self.root / "remote.git"
        self.g(self.control, "init", "--initial-branch=main")
        for path in prep.REQUIRED_CONTRACTS:
            self.write(self.control / path, b"trusted maintained contract\n")
        self.write(self.control / ".gitignore", b"__pycache__/\n*.pyc\n")
        for path in brand.ASSETS:
            self.write(self.control / path, ("approved artwork: " + path).encode())
        assets = {path: hashlib.sha256((self.control / path).read_bytes()).hexdigest() for path in brand.ASSETS}
        self.write(self.control / "deploy/automatic/brand-manifest.json", json.dumps({"format": "rival-it-brand-overlay", "version": 1, "assets": assets}).encode())
        self.write(self.control / "app.txt", b"old app\n")
        self.commit(self.control, "reviewed controls")
        control_sha = self.sha(self.control)
        self.g(self.root, "clone", str(self.control), str(self.candidate))
        self.write(self.candidate / "app.txt", b"updated app\n")
        self.commit(self.candidate, "prepared candidate")
        self.g(self.candidate, "branch", "automation-candidate")
        self.source = {"format": "rival-it-share-source", "schema_version": 1,
                       "repository": publisher.REPOSITORY, "control_commit": control_sha,
                       "source_commit": self.sha(self.candidate), "upstream_repository": "cupcakearmy/cryptgeon",
                       "upstream_tag": "v2.9.4", "upstream_commit": "e" * 40,
                       "branding_sha256": hashlib.sha256((self.control / "deploy/automatic/brand-manifest.json").read_bytes()).hexdigest(),
                       "security_contract_sha256": prep.contract_digest(self.control),
                       "file_format_version": 2, "release_parent": None}
        self.g(self.candidate, "bundle", "create", str(self.artifacts / "source.bundle"), publisher.CANDIDATE)
        self.g(self.root, "init", "--bare", str(self.remote))
        self.gates = {"format": "rival-it-share-gates", "schema_version": 1,
                      "source_commit": self.source["source_commit"],
                      "image": "rival-it-share:gate-" + self.source["source_commit"],
                      "image_id": "", "passed": True, "checks": list(publisher.CHECKS)}
        self.export_image()
        self.write_records()
        self.environ = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": publisher.REPOSITORY,
                        "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": control_sha,
                        "GITHUB_REPOSITORY_ID": "123456789", "RIVAL_ALLOW_PUBLISH": "true",
                        "GITHUB_TOKEN": "synthetic-token-never-valid"}
        self.calls, self.api_calls, self.docker_configs = [], [], []
        self.existing_release, self.tag_collision, self.branch_override = None, None, None
        self.upstream_moved, self.bad_loaded_image, self.fail_push, self.fail_upload = False, False, False, None
        self.race_on_push = False
        self.remote_draft = None

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def g(self, root, *args):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Local fixture",
                               "-c", "user.email=fixture@example.invalid", "-C", str(root), *args],
                              capture_output=True, check=True, env=publisher.base_env(self.root)).stdout

    def commit(self, root, message):
        self.g(root, "add", "."); self.g(root, "commit", "-m", message)

    def sha(self, root):
        return self.g(root, "rev-parse", "HEAD").decode().strip()

    def write_records(self):
        (self.artifacts / "release-input.json").write_text(json.dumps(self.source))
        (self.artifacts / "gates.json").write_text(json.dumps(self.gates))

    def export_image(self, *, unexpected_tag=False, tamper=False, index=False):
        labels = {"org.opencontainers.image.source": "https://github.com/" + publisher.REPOSITORY,
                  "org.opencontainers.image.revision": self.source["source_commit"]}
        config = json.dumps({"config": {"Labels": labels}}).encode()
        digest = hashlib.sha256(config).hexdigest()
        self.gates["image_id"] = "sha256:" + digest
        manifest = [{"Config": digest + ".json", "RepoTags": ["unapproved:tag" if unexpected_tag else self.gates["image"]],
                     "Layers": ["layer/layer.tar"]}]
        with tarfile.open(self.artifacts / "image.tar", "w") as archive:
            entries = {"manifest.json": json.dumps(manifest).encode(), digest + ".json": config + (b"tamper" if tamper else b""),
                       "layer/layer.tar": b"synthetic opaque layer bytes"}
            if index:
                entries["index.json"] = b"{}"
            for name, data in entries.items():
                member = tarfile.TarInfo(name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def runner(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if argv[0] == "docker":
            self.docker_configs.append(Path(kwargs["env"]["DOCKER_CONFIG"]))
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
            if argv[1] == "login":
                self.assertEqual(kwargs["input"], (self.environ["GITHUB_TOKEN"] + "\n").encode())
                config = json.loads((self.docker_configs[-1] / "config.json").read_text())
                self.assertEqual(config, {"auths": {"ghcr.io": {}}, "credsStore": "", "credHelpers": {}})
            data, code = b"", 0
            if argv[1:3] == ["image", "inspect"]:
                data = json.dumps({"Id": "sha256:" + "0" * 64 if self.bad_loaded_image else self.gates["image_id"],
                                   "Config": {"Labels": {"org.opencontainers.image.revision": self.source["source_commit"]}}}).encode()
            if argv[1] == "push":
                code = 1 if self.fail_push else 0
                data = ("candidate-" + self.source["source_commit"] + ": digest: sha256:" + "f" * 64 + " size: 529\n").encode()
                if code:
                    kwargs["stderr"].write(self.environ["GITHUB_TOKEN"].encode())
            kwargs["stdout"].write(data)
            return subprocess.CompletedProcess(argv, code)
        if argv[0] == "git" and "ls-remote" in argv:
            if "https://github.com/cupcakearmy/cryptgeon.git" in argv:
                value = "1" * 40 if self.upstream_moved else self.source["upstream_commit"]
                data = (value + "\trefs/tags/" + self.source["upstream_tag"] + "\n").encode()
                kwargs["stdout"].write(data)
                return subprocess.CompletedProcess(argv, 0)
            ref = argv[-1]
            if ref == publisher.BRANCH and self.branch_override:
                kwargs["stdout"].write((self.branch_override + "\t" + ref + "\n").encode())
                return subprocess.CompletedProcess(argv, 0)
            if ref.startswith("refs/tags/") and self.tag_collision:
                kwargs["stdout"].write((self.tag_collision + "\t" + ref + "\n").encode())
                return subprocess.CompletedProcess(argv, 0)
        if publisher.REMOTE in argv:
            if self.race_on_push and "push" in argv:
                # A competing creator installs an ancestor after our last read.
                # A normal FF push would accept this; create-only lease must not.
                self.g(self.remote, "fetch", str(self.control), self.source["control_commit"])
                self.g(self.remote, "update-ref", publisher.BRANCH, self.source["control_commit"])
            argv = [str(self.remote) if a == publisher.REMOTE else a for a in argv]
        return subprocess.run(argv, **kwargs)

    def api(self, token):
        self.assertEqual(token, self.environ["GITHUB_TOKEN"])
        outer = self
        class MockAPI:
            def request(self, method, path, data=None, **kwargs):
                outer.api_calls.append((method, path, data, kwargs))
                if method == "GET":
                    return outer.existing_release
                if method == "POST" and path.endswith("/releases"):
                    outer.remote_draft = {"id": 123, "draft": True, "tag_name": data["tag_name"]}
                    return dict(outer.remote_draft)
                if kwargs.get("upload"):
                    name = path.split("?name=")[1]
                    if name == outer.fail_upload:
                        raise publisher.PublishError("mock upload failure; draft retained")
                    return {"name": name, "size": len(data), "state": "uploaded"}
                if method == "PATCH":
                    outer.remote_draft["draft"] = False
                    return dict(outer.remote_draft)
                raise AssertionError("Unexpected mocked API operation")
        return MockAPI()

    def prepare(self, publish=False):
        return publisher.prepare(self.control, self.artifacts, self.output, publish=publish,
                                 environ=self.environ, runner=self.runner, api_factory=self.api)

    def release(self, verifier=None):
        bundle = self.root / "release.sigstore.jsonl"
        bundle.write_text('{"mock":"attestation fixture"}')
        return publisher.release(self.control, self.artifacts, self.output, bundle, publish=True,
                                 environ=self.environ, runner=self.runner, api_factory=self.api,
                                 verifier=verifier or (lambda path, _bundle, _policy, **_: json.loads(path.read_text())))

    def writes(self):
        return [a for a, _ in self.calls if a[0] == "docker" or "push" in a] + [m for m, *_ in self.api_calls if m != "GET"]

    def test_plan_validates_real_git_bundle_and_archive_without_external_operations(self):
        result = self.prepare()
        self.assertEqual(result["mode"], "plan")
        self.assertFalse(self.output.exists())
        self.assertEqual(self.writes(), [])
        self.assertFalse(any("ls-remote" in a for a, _ in self.calls))

    def test_all_actions_guards_are_required_before_any_external_write(self):
        for key in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA", "RIVAL_ALLOW_PUBLISH", "GITHUB_TOKEN"):
            old = self.environ.pop(key)
            with self.assertRaises(publisher.PublishError):
                self.prepare(True)
            self.environ[key] = old
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.api_calls, [])

    def test_incomplete_or_forged_gate_record_publishes_nothing(self):
        for changes in ({"passed": 1}, {"checks": list(publisher.CHECKS)[:-1]}, {"source_commit": "a" * 40}):
            record = dict(self.gates, **changes)
            (self.artifacts / "gates.json").write_text(json.dumps(record))
            with self.assertRaises(publisher.PublishError):
                self.prepare(True)
        self.assertEqual(self.writes(), [])

    def test_changed_trusted_contract_or_brand_pin_stops_before_writes(self):
        self.source["security_contract_sha256"] = "0" * 64
        self.write_records()
        with self.assertRaisesRegex(publisher.PublishError, "trusted branding/security"):
            self.prepare(True)
        self.assertEqual(self.writes(), [])

    def test_tampered_or_ambiguously_tagged_archive_never_loads(self):
        for kwargs in ({"tamper": True}, {"unexpected_tag": True}, {"index": True}):
            self.export_image(**kwargs)
            self.write_records()
            with self.assertRaises(publisher.PublishError):
                self.prepare(True)
        self.assertEqual(self.writes(), [])

    def test_unexpected_bundle_ref_rejected_before_any_external_operation(self):
        (self.artifacts / "source.bundle").unlink()
        self.g(self.candidate, "bundle", "create", str(self.artifacts / "source.bundle"), "--all")
        with self.assertRaisesRegex(publisher.PublishError, "exactly the approved candidate"):
            self.prepare(True)
        self.assertEqual(self.writes(), [])

    def test_stale_branch_tag_release_or_upstream_identity_stops_before_docker(self):
        for key, value in (("branch_override", "a" * 40), ("tag_collision", "b" * 40),
                           ("existing_release", {"draft": True}), ("upstream_moved", True)):
            setattr(self, key, value)
            with self.assertRaises(publisher.PublishError):
                self.prepare(True)
            setattr(self, key, None if key != "upstream_moved" else False)
        self.assertEqual(self.writes(), [])

    def test_prepare_uses_ephemeral_credentials_and_exact_create_only_lease(self):
        result = self.prepare(True)
        self.assertEqual(result["mode"], "prepared")
        self.assertEqual(result["image"], publisher.IMAGE + "@sha256:" + "f" * 64)
        self.assertTrue((self.output / "release.json").is_file())
        self.assertTrue(all(not path.exists() for path in self.docker_configs))
        pushes = [(a, k) for a, k in self.calls if a[0] == "git" and "push" in a]
        self.assertEqual(len(pushes), 1)
        args, kwargs = pushes[0]
        self.assertIn("--force-with-lease=" + publisher.BRANCH + ":", args)
        self.assertEqual(kwargs["env"]["GITHUB_TOKEN"], self.environ["GITHUB_TOKEN"])
        self.assertIn("GIT_ASKPASS", kwargs["env"])
        self.assertFalse(any(self.environ["GITHUB_TOKEN"] in arg for args, _ in self.calls for arg in args))
        self.assertFalse(any("run" in args for args, _ in self.calls if args[0] == "docker"))
        self.assertEqual([method for method, *_ in self.api_calls], ["GET"])

    def test_loaded_image_mismatch_or_registry_error_never_writes_source_or_release(self):
        self.bad_loaded_image = True
        with self.assertRaisesRegex(publisher.PublishError, "Loaded image identity"):
            self.prepare(True)
        self.assertFalse(any("push" in args for args, _ in self.calls))
        self.assertFalse(any(method != "GET" for method, *_ in self.api_calls))
        self.assertFalse((self.output / "release.json").exists())

    def test_atomic_create_lease_rejects_concurrent_ancestor_branch_creation(self):
        self.race_on_push = True
        with self.assertRaises(publisher.PublishError):
            self.prepare(True)
        actual = self.g(self.remote, "rev-parse", publisher.BRANCH).decode().strip()
        self.assertEqual(actual, self.source["control_commit"])
        self.assertFalse((self.output / "release.json").exists())
        self.assertFalse(any(method != "GET" for method, *_ in self.api_calls))

    def test_registry_failure_does_not_leak_token_in_exception_or_create_release(self):
        self.fail_push = True
        with self.assertRaises(publisher.PublishError) as caught:
            self.prepare(True)
        self.assertNotIn(self.environ["GITHUB_TOKEN"], str(caught.exception))
        self.assertFalse(any(args[0] == "git" and "push" in args for args, _ in self.calls))
        self.assertFalse(any(method != "GET" for method, *_ in self.api_calls))

    def test_release_requires_signature_gate_and_uploads_exact_three_assets_before_publication(self):
        self.prepare(True)
        seen = []
        def verified(path, bundle, policy, **kwargs):
            seen.append((path.read_bytes(), bundle.read_bytes(), policy))
            return json.loads(path.read_text())
        result = self.release(verified)
        self.assertEqual(result["mode"], "published")
        self.assertEqual(seen[0][0], (self.output / "release.json").read_bytes())
        self.assertEqual(seen[0][2]["repository_id"], self.environ["GITHUB_REPOSITORY_ID"])
        writes = [(m, p, d, k) for m, p, d, k in self.api_calls if m != "GET"]
        self.assertEqual([m for m, *_ in writes], ["POST", "POST", "POST", "POST", "PATCH"])
        self.assertTrue(writes[0][2]["draft"])
        self.assertEqual([p.split("?name=")[1] for _, p, _, k in writes if k.get("upload")],
                         ["release.json", "release.sigstore.jsonl", "source.bundle"])
        self.assertFalse(self.remote_draft["draft"])

    def test_failed_signature_prevents_all_release_api_writes(self):
        self.prepare(True)
        def failed(*_, **__):
            raise ValueError("mock cryptographic verification failed")
        with self.assertRaisesRegex(ValueError, "cryptographic"):
            self.release(failed)
        self.assertFalse(any(method != "GET" for method, *_ in self.api_calls))
        self.assertFalse((self.output / "release-attempt.json").exists())

    def test_partial_asset_failure_leaves_draft_and_is_not_retried(self):
        self.prepare(True)
        self.fail_upload = "release.sigstore.jsonl"
        with self.assertRaisesRegex(publisher.PublishError, "draft retained"):
            self.release()
        self.assertTrue(self.remote_draft["draft"])
        self.assertFalse(any(method == "PATCH" for method, *_ in self.api_calls))
        count = len([m for m, *_ in self.api_calls if m == "POST"])
        with self.assertRaisesRegex(publisher.PublishError, "already recorded"):
            self.release()
        self.assertEqual(len([m for m, *_ in self.api_calls if m == "POST"]), count)

    def test_input_symlinks_and_authenticated_redirects_or_other_endpoints_rejected(self):
        actual = self.artifacts / "gates.json"
        renamed = self.root / "gates-real.json"
        actual.rename(renamed); actual.symlink_to(renamed)
        with self.assertRaisesRegex(publisher.PublishError, "symlinks"):
            self.prepare(True)
        self.assertEqual(self.writes(), [])
        with self.assertRaisesRegex(publisher.PublishError, "redirects"):
            publisher.NoRedirect().redirect_request(None, None, 302, "", {}, "https://attacker.invalid")
        api = publisher.GitHub("synthetic-never-sent")
        for path in ("/repos/attacker/share/releases", "/repos/nickanewell/share/../../other", "/repos/nickanewell/share/releases/1/assets?name=../secret"):
            with self.assertRaisesRegex(publisher.PublishError, "destination"):
                api.request("POST", path, b"", upload=True)


if __name__ == "__main__":
    unittest.main()
