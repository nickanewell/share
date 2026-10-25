#!/usr/bin/env python3
"""Verify a bounded, signed release manifest before any Docker operation.

This is a policy wrapper around GitHub CLI's real Sigstore verification, not a
signature implementation. A successful CI status, image label or self-described
JSON statement is never sufficient. The caller must protect the installed code,
host policy and input directory; candidate code must not run on the host.

Only the local manifest is verified, using its downloaded bundle. This avoids
both a persistent GitHub token and OCI verification's registry-auth requirement.
The verified manifest cryptographically binds the exact image digest. The fixed
Ubuntu verifier binary /usr/bin/gh must be installed/reviewed before activation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


REPOSITORY = "nickanewell/share"
UPSTREAM = "cupcakearmy/cryptgeon"
SIGNER = REPOSITORY + "/.github/workflows/automatic-release.yml"
REF = "refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
GH = "/usr/bin/gh"
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TAG = re.compile(r"v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z")
FIELDS = frozenset({
    "format", "schema_version", "repository", "control_commit", "source_commit",
    "upstream_repository", "upstream_tag", "upstream_commit", "image",
    "branding_sha256", "security_contract_sha256", "file_format_version",
})


def strict_json(data):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj

    def invalid_constant(_):
        raise ValueError("Non-finite JSON number")

    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Invalid bounded JSON") from error


def bounded_read(path, limit):
    """Read once through a no-follow descriptor; reject aliased input paths."""
    path = Path(path).absolute()
    if path != path.resolve(strict=True):
        raise ValueError("Input paths must be canonical real paths, without symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Expected a bounded regular input file")
        result = stream.read(limit + 1)
    if not result or len(result) > limit:
        raise ValueError("Expected a nonempty bounded input file")
    return result


def validate_policy(policy):
    # The promoter validates the complete host policy, ownership and permissions.
    # This verifier checks its identity subset rather than accepting new issuers,
    # arbitrary executable paths or publisher repositories through configuration.
    if not isinstance(policy, dict):
        raise ValueError("Host policy must be an object")
    fixed = {"repository": REPOSITORY, "signer_workflow": SIGNER,
             "allowed_major": 2, "file_format_version": 2}
    for key, expected in fixed.items():
        if policy.get(key) != expected or type(policy.get(key)) is not type(expected):
            raise ValueError("Unsupported host policy identity: " + key)
    for key, pattern in (("allowed_control_commit", SHA1), ("branding_sha256", SHA256),
                         ("security_contract_sha256", SHA256)):
        if not isinstance(policy.get(key), str) or not pattern.fullmatch(policy[key]):
            raise ValueError("Host policy must pin " + key)
    if not isinstance(policy.get("repository_id"), str) or not re.fullmatch(r"[1-9][0-9]{0,19}", policy["repository_id"]):
        raise ValueError("Host policy must pin the verified GitHub repository ID")


def validate_release(release, policy):
    validate_policy(policy)
    if not isinstance(release, dict) or set(release) != FIELDS:
        raise ValueError("Unexpected release manifest schema")
    for key, value in {"format": "rival-it-share-release", "schema_version": 1,
                       "repository": REPOSITORY, "upstream_repository": UPSTREAM,
                       "file_format_version": 2}.items():
        if release[key] != value or type(release[key]) is not type(value):
            raise ValueError("Unsupported release identity: " + key)
    for key in ("control_commit", "source_commit", "upstream_commit"):
        if not isinstance(release[key], str) or not SHA1.fullmatch(release[key]):
            raise ValueError("Release commit must be a complete lowercase SHA")
    if release["control_commit"] != policy["allowed_control_commit"]:
        raise ValueError("Release control commit is not approved")
    for key in ("branding_sha256", "security_contract_sha256"):
        if not isinstance(release[key], str) or not SHA256.fullmatch(release[key]) or release[key] != policy[key]:
            raise ValueError("Release does not match the approved " + key)
    tag = TAG.fullmatch(release["upstream_tag"]) if isinstance(release["upstream_tag"], str) else None
    if not tag or int(tag[1]) != policy["allowed_major"]:
        raise ValueError("Only stable releases within the approved major are accepted")
    if not isinstance(release["image"], str) or not re.fullmatch(
        r"ghcr\.io/nickanewell/share@sha256:[0-9a-f]{64}", release["image"]
    ):
        raise ValueError("Release must pin the approved image repository by digest")
    return release


def validate_verification_output(data, digest, policy):
    """Inspect only output emitted after gh's cryptographic policy succeeds.

    The certificate fields below are GitHub OIDC-derived, unlike the workflow-
    supplied predicate. Fields are flat because Sigstore certificate.Summary
    embeds its Extensions. Unknown/missing output shapes fail closed.
    """
    verified = strict_json(data)
    if not isinstance(verified, list) or len(verified) != 1:
        raise ValueError("Expected exactly one verified attestation")
    try:
        result = verified[0]["verificationResult"]
        certificate = result["signature"]["certificate"]
        statement = result["statement"]
        timestamps = result["verifiedTimestamps"]
        identity = "https://github.com/" + SIGNER + "@" + REF
        expected = {
            "subjectAlternativeName": identity,
            "issuer": ISSUER,
            "buildSignerURI": identity,
            "buildConfigURI": identity,
            "buildConfigDigest": policy["allowed_control_commit"],
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": "https://github.com/" + REPOSITORY,
            "sourceRepositoryDigest": policy["allowed_control_commit"],
            "sourceRepositoryRef": REF,
            "sourceRepositoryIdentifier": policy["repository_id"],
        }
        if not isinstance(certificate, dict) or any(certificate.get(k) != v for k, v in expected.items()):
            raise ValueError("Verified publisher certificate does not match host policy")
        if certificate.get("buildSignerDigest", "") not in ("", policy["allowed_control_commit"]):
            raise ValueError("Unexpected signer workflow revision")
        if not isinstance(timestamps, list) or not timestamps or any(
            not isinstance(t, dict) or not isinstance(t.get("timestamp"), str) for t in timestamps
        ):
            raise ValueError("Verified observer timestamp is required")
        if statement["_type"] != "https://in-toto.io/Statement/v1" or statement["predicateType"] != PREDICATE:
            raise ValueError("Unexpected verified statement type")
        subjects = statement["subject"]
        if not isinstance(subjects, list) or len(subjects) != 1 or subjects[0].get("digest") != {"sha256": digest}:
            raise ValueError("Verified statement does not bind this exact release manifest")
        definition = statement["predicate"]["buildDefinition"]
        workflow = definition["externalParameters"]["workflow"]
        if definition["buildType"] != BUILD_TYPE or workflow != {
            "repository": "https://github.com/" + REPOSITORY,
            "path": ".github/workflows/automatic-release.yml", "ref": REF,
        }:
            raise ValueError("Unexpected provenance workflow/source identity")
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise ValueError("Unsupported verified provenance output shape") from error


def verify_release(manifest_path, bundle_path, policy, runner=subprocess.run):
    """Return the release only after real verification; no Docker or deployment."""
    validate_policy(policy)
    manifest = bounded_read(manifest_path, 16 * 1024)
    bundle = bounded_read(bundle_path, 2 * 1024 * 1024)
    release = validate_release(strict_json(manifest), policy)
    digest = hashlib.sha256(manifest).hexdigest()
    # gh reopens paths. Private snapshots bind its input to the bytes validated
    # here and keep an unprivileged downloader from racing the original files.
    with tempfile.TemporaryDirectory(prefix="rival-share-provenance-") as temporary:
        root = Path(temporary).resolve()
        subject = root / "release.json"
        signed = root / "release.sigstore.jsonl"
        for path, data in ((subject, manifest), (signed, bundle)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        config = root / "gh-empty"
        config.mkdir(mode=0o700)
        env = {"PATH": "/usr/bin:/bin", "HOME": str(config), "GH_CONFIG_DIR": str(config),
               "XDG_CONFIG_HOME": str(config), "XDG_CACHE_HOME": str(config),
               "TMPDIR": str(root), "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1",
               "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1", "LC_ALL": "C"}
        argv = [GH, "attestation", "verify", str(subject), "--bundle", str(signed),
                "--repo", REPOSITORY, "--signer-workflow", SIGNER,
                "--source-ref", REF, "--source-digest", policy["allowed_control_commit"],
                "--cert-oidc-issuer", ISSUER, "--hostname", "github.com",
                "--deny-self-hosted-runners", "--predicate-type", PREDICATE, "--format", "json"]
        # Temporary files bound the output even if a verifier prints excessively.
        # The reviewed gh binary is trusted to enforce signatures; its stdout is
        # still parsed/bounded and no stderr (possibly auth/config text) is logged.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                result = runner(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                env=env, timeout=45, check=False)
            except (OSError, subprocess.SubprocessError) as error:
                raise ValueError("GitHub cryptographic verifier unavailable or timed out") from error
            if result.returncode != 0:
                raise ValueError("GitHub cryptographic provenance verification failed")
            stdout.seek(0)
            output = stdout.read(4 * 1024 * 1024 + 1)
            if not output or len(output) > 4 * 1024 * 1024:
                raise ValueError("Expected bounded verifier JSON output")
        validate_verification_output(output, digest, policy)
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = strict_json(bounded_read(args.policy, 32 * 1024))
        release = verify_release(args.manifest, args.bundle, policy)
        print(json.dumps(release, sort_keys=True))
    except (ValueError, OSError) as error:
        parser.exit(1, "Release verification stopped: " + str(error) + "\n")


if __name__ == "__main__":
    main()
