"""Offline verifier policy tests. No signature claims, credentials or network."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("release_provenance", HERE / "provenance.py")
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rival-provenance-test-")
        self.root = Path(self.temp.name).resolve()
        self.manifest, self.bundle = self.root / "release.json", self.root / "release.sigstore.jsonl"
        self.policy = {"repository": provenance.REPOSITORY, "repository_id": "123456789",
                       "signer_workflow": provenance.SIGNER, "allowed_control_commit": "a" * 40,
                       "branding_sha256": "b" * 64, "security_contract_sha256": "c" * 64,
                       "allowed_major": 2, "file_format_version": 2}
        self.release = {"format": "rival-it-share-release", "schema_version": 1,
                        "repository": provenance.REPOSITORY, "control_commit": "a" * 40,
                        "source_commit": "d" * 40, "upstream_repository": provenance.UPSTREAM,
                        "upstream_tag": "v2.9.4", "upstream_commit": "e" * 40,
                        "image": "ghcr.io/nickanewell/share@sha256:" + "f" * 64,
                        "branding_sha256": "b" * 64, "security_contract_sha256": "c" * 64,
                        "file_format_version": 2}
        self.write()
        self.bundle.write_text('{"untrusted":"mock bundle, never cryptographically verified"}\n')
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def write(self):
        self.manifest.write_text(json.dumps(self.release, sort_keys=True) + "\n")

    def output(self, digest=None):
        identity = "https://github.com/" + provenance.SIGNER + "@" + provenance.REF
        certificate = {
            "subjectAlternativeName": identity, "issuer": provenance.ISSUER,
            "buildSignerURI": identity, "buildConfigURI": identity,
            "buildConfigDigest": "a" * 40, "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": "https://github.com/" + provenance.REPOSITORY,
            "sourceRepositoryDigest": "a" * 40, "sourceRepositoryRef": provenance.REF,
            "sourceRepositoryIdentifier": self.policy["repository_id"],
        }
        return [{"verificationResult": {
            "signature": {"certificate": certificate},
            "verifiedTimestamps": [{"type": "transparency-log", "uri": "https://rekor.sigstore.dev",
                                    "timestamp": "2026-10-25T14:00:00Z"}],
            "statement": {"_type": "https://in-toto.io/Statement/v1", "predicateType": provenance.PREDICATE,
                          "subject": [{"name": "release.json", "digest": {"sha256": digest or hashlib.sha256(self.manifest.read_bytes()).hexdigest()}}],
                          "predicate": {"buildDefinition": {"buildType": provenance.BUILD_TYPE,
                              "externalParameters": {"workflow": {
                                  "repository": "https://github.com/" + provenance.REPOSITORY,
                                  "path": ".github/workflows/automatic-release.yml", "ref": provenance.REF}}}}},
        }}]

    def runner(self, output=None, code=0, during=None):
        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if during:
                during(argv)
            data = self.output() if output is None else output
            kwargs["stdout"].write(data if isinstance(data, bytes) else json.dumps(data).encode())
            return subprocess.CompletedProcess(argv, code)
        return run

    def verify(self, runner=None):
        return provenance.verify_release(self.manifest, self.bundle, self.policy,
                                         runner=runner or self.runner())

    def test_success_requires_complete_crypto_command_and_sanitized_environment(self):
        self.assertEqual(self.verify(), self.release)
        argv, kwargs = self.calls[0]
        self.assertEqual(argv[:3], ["/usr/bin/gh", "attestation", "verify"])
        for flag, value in (("--repo", provenance.REPOSITORY), ("--signer-workflow", provenance.SIGNER),
                            ("--source-ref", provenance.REF), ("--source-digest", "a" * 40),
                            ("--cert-oidc-issuer", provenance.ISSUER), ("--predicate-type", provenance.PREDICATE)):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--bundle", argv)
        self.assertIn("--deny-self-hosted-runners", argv)
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["timeout"], 45)
        self.assertNotIn("GH_TOKEN", kwargs["env"])
        self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
        self.assertEqual(kwargs["env"]["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(kwargs["env"]["HOME"], kwargs["env"]["GH_CONFIG_DIR"])

    def test_nonzero_verifier_exit_rejects_even_convincing_output(self):
        with self.assertRaisesRegex(ValueError, "cryptographic provenance verification failed"):
            self.verify(self.runner(code=1))

    def test_missing_or_timed_out_binary_fails_closed(self):
        for error in (FileNotFoundError("gh absent"), subprocess.TimeoutExpired("gh", 45)):
            def failed(*_, **__):
                raise error
            with self.assertRaisesRegex(ValueError, "unavailable or timed out"):
                self.verify(failed)

    def test_ci_success_or_unsigned_labels_are_not_provenance(self):
        for data in ({"success": True, "image": self.release["image"]}, [], [{}], b"Verification succeeded!"):
            with self.assertRaises(ValueError):
                self.verify(self.runner(output=data))

    def test_certificate_identity_fields_cannot_be_spoofed(self):
        for key in ("subjectAlternativeName", "issuer", "buildSignerURI", "buildConfigURI", "buildConfigDigest",
                    "runnerEnvironment", "sourceRepositoryURI", "sourceRepositoryDigest", "sourceRepositoryRef",
                    "sourceRepositoryIdentifier"):
            data = self.output()
            data[0]["verificationResult"]["signature"]["certificate"][key] = "different"
            with self.assertRaisesRegex(ValueError, "publisher certificate"):
                self.verify(self.runner(output=data))

    def test_signer_digest_if_present_must_match_control_commit(self):
        data = self.output()
        data[0]["verificationResult"]["signature"]["certificate"]["buildSignerDigest"] = "1" * 40
        with self.assertRaisesRegex(ValueError, "signer workflow revision"):
            self.verify(self.runner(output=data))

    def test_statement_binds_exact_manifest_bytes(self):
        with self.assertRaisesRegex(ValueError, "exact release manifest"):
            self.verify(self.runner(output=self.output("0" * 64)))

    def test_predicate_workflow_identity_and_type_are_checked(self):
        for field in ("path", "repository", "ref"):
            data = self.output()
            data[0]["verificationResult"]["statement"]["predicate"]["buildDefinition"]["externalParameters"]["workflow"][field] = "different"
            with self.assertRaisesRegex(ValueError, "workflow/source"):
                self.verify(self.runner(output=data))
        data = self.output()
        data[0]["verificationResult"]["statement"]["predicateType"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "statement type"):
            self.verify(self.runner(output=data))

    def test_verified_timestamp_and_certificate_are_required(self):
        for field in ("signature", "verifiedTimestamps", "statement"):
            data = self.output()
            del data[0]["verificationResult"][field]
            with self.assertRaises(ValueError):
                self.verify(self.runner(output=data))
        data = self.output()
        data[0]["verificationResult"]["verifiedTimestamps"] = []
        with self.assertRaisesRegex(ValueError, "timestamp"):
            self.verify(self.runner(output=data))

    def test_manifest_wrong_repository_digest_protocol_or_major_never_invokes_cli(self):
        original = copy.deepcopy(self.release)
        bad = {"repository": "attacker/share", "upstream_repository": "other/cryptgeon",
               "control_commit": "1" * 40, "upstream_tag": "v3.0.0", "source_commit": "../x",
               "upstream_commit": "-option", "image": "ghcr.io/attacker/share:latest",
               "branding_sha256": "1" * 64, "security_contract_sha256": "2" * 64,
               "file_format_version": 1, "schema_version": True}
        for key, value in bad.items():
            self.release = dict(original, **{key: value})
            self.write()
            with self.assertRaises(ValueError):
                self.verify()
        self.assertEqual(self.calls, [])

    def test_duplicate_json_fields_and_unexpected_keys_are_rejected(self):
        self.manifest.write_text('{"format":"one","format":"two"}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.verify()
        self.release["unapproved"] = "extra"
        self.write()
        with self.assertRaisesRegex(ValueError, "schema"):
            self.verify()
        self.assertEqual(self.calls, [])

    def test_unpinned_policy_identity_is_rejected_before_cli(self):
        for key, bad in (("repository_id", "REPLACE"), ("allowed_control_commit", "main"),
                         ("allowed_major", True), ("signer_workflow", "other/workflow")):
            original = self.policy[key]
            self.policy[key] = bad
            with self.assertRaises(ValueError):
                self.verify()
            self.policy[key] = original
        self.assertEqual(self.calls, [])

    def test_symlinks_nonregular_and_oversize_inputs_are_rejected(self):
        link = self.root / "manifest-link"
        link.symlink_to(self.manifest)
        for path in (link, self.root):
            with self.assertRaises((ValueError, OSError)):
                provenance.verify_release(path, self.bundle, self.policy, runner=self.runner())
        self.bundle.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "bounded"):
            self.verify()
        self.assertEqual(self.calls, [])

    def test_empty_or_excessive_verifier_output_is_rejected(self):
        for output in (b"", b"x" * (4 * 1024 * 1024 + 1)):
            with self.assertRaisesRegex(ValueError, "bounded verifier"):
                self.verify(self.runner(output=output))

    def test_private_snapshots_prevent_original_input_replacement_race(self):
        data = self.output()
        expected = self.manifest.read_bytes()
        def race(argv):
            self.manifest.write_text("changed after snapshot")
            self.bundle.write_text("changed after snapshot")
            self.assertEqual(Path(argv[3]).read_bytes(), expected)
            self.assertNotEqual(Path(argv[argv.index("--bundle") + 1]), self.bundle)
        self.assertEqual(self.verify(self.runner(output=data, during=race)), self.release)


if __name__ == "__main__":
    unittest.main()
