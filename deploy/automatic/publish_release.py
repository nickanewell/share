#!/usr/bin/env python3
"""Validate (default), or explicitly publish a gated Share release from Actions.

Never runs a candidate command/container. Local temporary Git object imports
validate the source bundle even in plan mode; plan never contacts Docker, logs
in, pushes Git, or writes GitHub/registry state. Publishing is split around the
workflow's official attestation action. Failed/uncertain publication is not
retried, overwritten or rolled back by deleting remotely published material.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request


HERE = Path(__file__).resolve().parent
REPOSITORY = "nickanewell/share"
REMOTE = "https://github.com/" + REPOSITORY + ".git"
BRANCH = "refs/heads/automation/release-v2"
CANDIDATE = "refs/heads/automation-candidate"
IMAGE = "ghcr.io/nickanewell/share"
CHECKS = ("javascript-security", "frontend-sync", "frontend-check", "rust-security",
          "staging-health-format", "browser-chrome-firefox-webkit")
SOURCE_FIELDS = {"format", "schema_version", "repository", "control_commit", "source_commit",
                 "upstream_repository", "upstream_tag", "upstream_commit", "branding_sha256",
                 "security_contract_sha256", "file_format_version", "release_parent"}
GATE_FIELDS = {"format", "schema_version", "source_commit", "image", "image_id", "passed", "checks"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TAG = re.compile(r"v2\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z")
LIMITS = {"release-input.json": 16 * 1024, "gates.json": 16 * 1024,
          "source.bundle": 64 * 1024 * 1024, "image.tar": 512 * 1024 * 1024}
MAX_LOG = 16 * 1024 * 1024


class PublishError(ValueError):
    pass


def sibling(name):
    spec = importlib.util.spec_from_file_location("rival_publish_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PublishError("Duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(PublishError("Invalid JSON constant")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PublishError("Malformed bounded publication JSON") from error


def canonical(path, directory=False):
    path = Path(path).absolute()
    if path != path.resolve(strict=True):
        raise PublishError("Publication inputs must use canonical paths without symlinks")
    mode = path.lstat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise PublishError("Expected a real directory" if directory else "Expected a regular file")
    return path


def snapshot(source, target, limit):
    source = canonical(source)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise PublishError("Publication input exceeds its size/type limit")
        total = 0
        with open(target, "xb") as output:
            os.chmod(target, 0o600)
            while chunk := stream.read(min(65536, limit + 1 - total)):
                total += len(chunk)
                if total > limit:
                    raise PublishError("Publication input exceeds its size limit")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if total != info.st_size:
            raise PublishError("Publication input changed during capture")


def base_env(home):
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
            "XDG_CONFIG_HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C"}


def command(argv, *, env, runner=subprocess.run, data=None, timeout=45, check=True):
    def limit_log():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            completed = runner(argv, input=data, stdout=out, stderr=err, env=env,
                               timeout=timeout, check=False, preexec_fn=limit_log)
        except (OSError, subprocess.SubprocessError) as error:
            raise PublishError("Publication command failed or timed out; inspect its outcome before retrying") from error
        out.seek(0)
        output = out.read(MAX_LOG + 1)
    if len(output) >= MAX_LOG:
        raise PublishError("Publication command exceeded its output limit")
    if check and completed.returncode:
        # Never relay subprocess stderr: Git/registry authentication failures may
        # include credential/configuration details. No command is automatically retried.
        raise PublishError("Publication command failed; partial external state may need review")
    return output, completed.returncode


def git(root, *args, env, runner=subprocess.run, check=True):
    return command(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                    "-c", "credential.helper=", "-c", "protocol.ext.allow=never",
                    "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true",
                    "-c", "http.followRedirects=false", "-c", "submodule.recurse=false",
                    "-C", str(root), *args], env=env, runner=runner, check=check)


def context(source, environ):
    required = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": source["control_commit"],
                "RIVAL_ALLOW_PUBLISH": "true"}
    if any(environ.get(key) != value for key, value in required.items()):
        raise PublishError("Publishing requires the explicitly enabled trusted main-branch Actions context")
    token = environ.get("GITHUB_TOKEN")
    if not isinstance(token, str) or not token.strip() or "\n" in token or "\r" in token:
        raise PublishError("An ephemeral publisher-job GITHUB_TOKEN is required")
    return token


def validate_records(source, gates, control, env, runner):
    if not isinstance(source, dict) or set(source) != SOURCE_FIELDS:
        raise PublishError("Unexpected source manifest schema")
    for key, expected in {"format": "rival-it-share-source", "schema_version": 1,
                          "repository": REPOSITORY, "upstream_repository": "cupcakearmy/cryptgeon",
                          "file_format_version": 2}.items():
        if source[key] != expected or type(source[key]) is not type(expected):
            raise PublishError("Unsupported source identity")
    for key in ("control_commit", "source_commit", "upstream_commit"):
        if not isinstance(source[key], str) or not SHA.fullmatch(source[key]):
            raise PublishError("Complete source/control/upstream commits must be pinned")
    if source["release_parent"] is not None and (not isinstance(source["release_parent"], str) or not SHA.fullmatch(source["release_parent"])):
        raise PublishError("Release parent must be a complete commit or null")
    if not isinstance(source["upstream_tag"], str) or not TAG.fullmatch(source["upstream_tag"]):
        raise PublishError("Only stable major-2 releases may be published")
    control_sha = git(control, "rev-parse", "--verify", "HEAD", env=env, runner=runner)[0].decode().strip()
    if source["control_commit"] != control_sha:
        raise PublishError("The reviewed control checkout must be clean and match the pinned commit")
    trusted = sibling("prepare_release")
    # The trusted helper recognizes verified LFS materialization without running
    # repository/global clean filters. Plain `git status` would misclassify it.
    trusted.require_clean(control)
    for key, expected in {
        "branding_sha256": hashlib.sha256((control / "deploy/automatic/brand-manifest.json").read_bytes()).hexdigest(),
        "security_contract_sha256": trusted.contract_digest(control),
    }.items():
        if not isinstance(source[key], str) or not SHA256.fullmatch(source[key]) or source[key] != expected:
            raise PublishError("Candidate changed a trusted branding/security contract")
    if not isinstance(gates, dict) or set(gates) != GATE_FIELDS:
        raise PublishError("Unexpected gate result schema")
    expected = {"format": "rival-it-share-gates", "schema_version": 1, "source_commit": source["source_commit"],
                "image": "rival-it-share:gate-" + source["source_commit"], "passed": True, "checks": list(CHECKS)}
    if any(gates.get(key) != value or type(gates.get(key)) is not type(value) for key, value in expected.items()):
        raise PublishError("Every maintained gate must pass for this exact candidate")
    if not isinstance(gates["image_id"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", gates["image_id"]):
        raise PublishError("Gate must identify the exact tested image ID")
    return trusted


def validate_bundle(control, bundle, source, trusted, work, env, runner):
    heads = command(["git", "bundle", "list-heads", str(bundle)], env=env, runner=runner)[0].decode().splitlines()
    if heads != [source["source_commit"] + " " + CANDIDATE]:
        raise PublishError("Source bundle must contain exactly the approved candidate ref")
    bare = work / "source.git"
    command(["git", "init", "--bare", str(bare)], env=env, runner=runner)
    git(bare, "fetch", "--no-tags", "--no-write-fetch-head", str(control), source["control_commit"], env=env, runner=runner)
    git(bare, "bundle", "verify", str(bundle), env=env, runner=runner)
    git(bare, "fetch", "--no-tags", "--no-write-fetch-head", str(bundle), CANDIDATE + ":" + CANDIDATE, env=env, runner=runner)
    parents = git(bare, "rev-list", "--parents", "-n1", source["source_commit"], env=env, runner=runner)[0].decode().split()
    expected = [source["source_commit"], source["control_commit"]]
    if source["release_parent"] and source["release_parent"] != source["control_commit"]:
        expected.append(source["release_parent"])
    if parents != expected:
        raise PublishError("Candidate ancestry does not match its recorded control/release parents")
    if source["release_parent"]:
        git(bare, "merge-base", "--is-ancestor", source["release_parent"], source["source_commit"], env=env, runner=runner)
    # Compare immutable Git objects; no candidate checkout, filters or scripts run.
    paths = getattr(trusted, "CONTRACT_PATHS")
    for path in paths:
        a = git(bare, "ls-tree", "-rz", source["control_commit"], "--", path, env=env, runner=runner)[0]
        b = git(bare, "ls-tree", "-rz", source["source_commit"], "--", path, env=env, runner=runner)[0]
        if a != b:
            raise PublishError("Bundled candidate changed a maintained contract: " + path)
    manifest = strict_json((control / "deploy/automatic/brand-manifest.json").read_bytes())
    for path, expected_hash in manifest["assets"].items():
        data = git(bare, "show", source["source_commit"] + ":" + path, env=env, runner=runner)[0]
        if hashlib.sha256(data).hexdigest() != expected_hash:
            raise PublishError("Bundled candidate changed approved artwork")
    return bare


def validate_image_archive(path, gates, source):
    """Accept one Docker-save image, never extract archive paths to the host.

    OCI-index archives are deliberately rejected until that export form is
    separately validated; a later real Linux export must pass this preflight.
    """
    with tarfile.open(path, "r:") as archive:
        entries = {}
        total = 0
        for member in archive:
            name = member.name
            if len(entries) >= 20000 or name in entries or not name or str(PurePosixPath(name)) != name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
                raise PublishError("Ambiguous or unsafe image archive path")
            if not (member.isfile() or member.isdir()) or member.size > LIMITS["image.tar"]:
                raise PublishError("Image archive contains an unsupported entry")
            total += member.size
            if total > LIMITS["image.tar"]:
                raise PublishError("Image archive exceeds its uncompressed size limit")
            entries[name] = member
        if "index.json" in entries or "oci-layout" in entries:
            raise PublishError("OCI-index image exports require separate validation; no image was loaded")
        def read(name, maximum):
            item = entries.get(name)
            if item is None or not item.isfile() or item.size > maximum:
                raise PublishError("Image archive metadata is missing or oversized")
            return archive.extractfile(item).read(maximum + 1)
        manifest = strict_json(read("manifest.json", 1024 * 1024))
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
            raise PublishError("Expected one image in the Docker archive")
        entry = manifest[0]
        if entry.get("RepoTags") != [gates["image"]] or not isinstance(entry.get("Config"), str):
            raise PublishError("Image archive must contain only the gated local image tag")
        if "repositories" in entries:
            repositories = strict_json(read("repositories", 1024 * 1024))
            wanted_tag = "gate-" + source["source_commit"]
            if (not isinstance(repositories, dict) or set(repositories) != {"rival-it-share"}
                    or not isinstance(repositories["rival-it-share"], dict)
                    or set(repositories["rival-it-share"]) != {wanted_tag}
                    or not isinstance(repositories["rival-it-share"][wanted_tag], str)
                    or not SHA256.fullmatch(repositories["rival-it-share"][wanted_tag])):
                raise PublishError("Legacy archive repository metadata contains an unexpected tag")
        config_data = read(entry["Config"], 8 * 1024 * 1024)
        if "sha256:" + hashlib.sha256(config_data).hexdigest() != gates["image_id"]:
            raise PublishError("Image archive config does not match the tested image ID")
        config = strict_json(config_data)
        if not isinstance(config, dict) or not isinstance(config.get("config"), dict):
            raise PublishError("Image archive config must contain an image configuration object")
        labels = config["config"].get("Labels")
        if not isinstance(labels, dict):
            raise PublishError("Image archive labels must identify the tested source")
        if labels.get("org.opencontainers.image.revision") != source["source_commit"] or labels.get("org.opencontainers.image.source") != "https://github.com/" + REPOSITORY:
            raise PublishError("Image archive source/revision labels do not match the gated source")
        layers = entry.get("Layers")
        if not isinstance(layers, list) or not 0 < len(layers) <= 128 or any(not isinstance(name, str) or name not in entries or not entries[name].isfile() for name in layers):
            raise PublishError("Image archive layers are missing or malformed")


@contextlib.contextmanager
def validated(control, artifacts, runner=subprocess.run):
    control, artifacts = canonical(control, True), canonical(artifacts, True)
    with tempfile.TemporaryDirectory(prefix="rival-publisher-") as temporary:
        work = Path(temporary).resolve()
        for name, limit in LIMITS.items():
            snapshot(artifacts / name, work / name, limit)
        source = strict_json((work / "release-input.json").read_bytes())
        gates = strict_json((work / "gates.json").read_bytes())
        env = base_env(work)
        trusted = validate_records(source, gates, control, env, runner)
        bare = validate_bundle(control, work / "source.bundle", source, trusted, work, env, runner)
        validate_image_archive(work / "image.tar", gates, source)
        yield source, gates, bare, work, env


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise PublishError("Authenticated GitHub redirects are not accepted")


class GitHub:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, data=None, *, upload=False, missing=False):
        host = "uploads.github.com" if upload else "api.github.com"
        prefix = "/repos/" + REPOSITORY + "/"
        suffix = path[len(prefix):] if path.startswith(prefix) else ""
        if upload:
            allowed = method == "POST" and re.fullmatch(
                r"releases/[1-9][0-9]*/assets\?name=(release\.json|release\.sigstore\.jsonl|source\.bundle)", suffix)
        else:
            allowed = (method == "GET" and re.fullmatch(
                r"releases/tags/rival-auto-v2\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", suffix)
                or method == "POST" and suffix == "releases"
                or method == "PATCH" and re.fullmatch(r"releases/[1-9][0-9]*", suffix))
        if not allowed:
            raise PublishError("Unapproved authenticated API destination")
        body = data if upload else (json.dumps(data).encode() if data is not None else None)
        request = urllib.request.Request("https://" + host + path, data=body, method=method, headers={
            "Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "RivalITSharePublisher/1",
            "Content-Type": "application/octet-stream" if upload else "application/json"})
        try:
            with self.opener.open(request, timeout=30) as response:
                result = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise PublishError("GitHub publication request failed with HTTP " + str(error.code)) from None
        except (OSError, urllib.error.URLError):
            raise PublishError("GitHub publication outcome may be uncertain; inspect before retrying") from None
        if len(result) > 1024 * 1024:
            raise PublishError("GitHub publication response exceeded its size limit")
        return strict_json(result)


def remote_head(root, ref, env, runner):
    output = git(root, "ls-remote", "--refs", REMOTE, ref, env=env, runner=runner)[0].decode().splitlines()
    if not output:
        return None
    if len(output) != 1 or output[0].split()[-1] != ref or not SHA.fullmatch(output[0].split()[0]):
        raise PublishError("Unexpected remote ref identity")
    return output[0].split()[0]


def preflight_remote(source, bare, env, runner, api, *, branch_published=False):
    upstream = "https://github.com/cupcakearmy/cryptgeon.git"
    refs = ["refs/tags/" + source["upstream_tag"], "refs/tags/" + source["upstream_tag"] + "^{}"]
    lines = git(bare, "ls-remote", upstream, *refs, env=env, runner=runner)[0].decode().splitlines()
    resolved = {}
    for line in lines:
        pieces = line.split()
        if len(pieces) != 2 or pieces[1] not in refs or pieces[1] in resolved or not SHA.fullmatch(pieces[0]):
            raise PublishError("Unexpected upstream tag identity")
        resolved[pieces[1]] = pieces[0]
    if resolved.get(refs[1], resolved.get(refs[0])) != source["upstream_commit"]:
        raise PublishError("Upstream stable tag moved or disappeared")
    expected = source["source_commit"] if branch_published else source["release_parent"]
    if remote_head(bare, BRANCH, env, runner) != expected:
        raise PublishError("Release branch changed; no publication was attempted")
    tag = "rival-auto-" + source["upstream_tag"]
    if api.request("GET", "/repos/" + REPOSITORY + "/releases/tags/" + tag, missing=True) is not None:
        raise PublishError("Release already exists, including drafts; never overwrite or retry it automatically")
    if remote_head(bare, "refs/tags/" + tag, env, runner) is not None:
        raise PublishError("Release tag already exists; manual review required")


def write_json(path, value):
    with open(path, "x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def prepare(control, artifacts, output, *, publish=False, environ=None, runner=subprocess.run, api_factory=GitHub):
    environ = os.environ if environ is None else environ
    with validated(control, artifacts, runner) as (source, gates, bare, work, env):
        output = Path(output).absolute()
        if output.parent != output.parent.resolve(strict=True) or output.exists() or output.is_symlink():
            raise PublishError("Preparation output must be a fresh canonical directory")
        if not publish:
            return {"mode": "plan", "source_commit": source["source_commit"], "checks": gates["checks"],
                    "result": "validated offline; no Docker, login or external writes"}
        token = context(source, environ)
        api = api_factory(token)
        preflight_remote(source, bare, env, runner, api)
        output.mkdir(mode=0o700)
        write_json(output / "publication-attempt.json", {"source_commit": source["source_commit"], "state": "prepare started"})
        docker_config = work / "docker-config"
        docker_config.mkdir(mode=0o700)
        # A nonempty auth map prevents Docker's platform helper autodetection.
        # Login may write credentials ONLY into this private ephemeral file.
        write_json(docker_config / "config.json", {"auths": {"ghcr.io": {}}, "credsStore": "", "credHelpers": {}})
        docker_env = dict(env, DOCKER_CONFIG=str(docker_config))
        command(["docker", "load", "--input", str(work / "image.tar")], env=docker_env, runner=runner, timeout=180)
        image = strict_json(command(["docker", "image", "inspect", gates["image"], "--format", "{{json .}}"], env=docker_env, runner=runner)[0])
        if image.get("Id") != gates["image_id"] or image.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != source["source_commit"]:
            raise PublishError("Loaded image identity does not match the tested candidate; nothing pushed")
        remote_image = IMAGE + ":candidate-" + source["source_commit"]
        command(["docker", "tag", gates["image"], remote_image], env=docker_env, runner=runner)
        command(["docker", "login", "ghcr.io", "--username", "nickanewell", "--password-stdin"],
                env=docker_env, runner=runner, data=(token + "\n").encode())
        pushed = command(["docker", "push", remote_image], env=docker_env, runner=runner, timeout=300)[0].decode()
        matches = re.findall(r"(?m)^candidate-" + source["source_commit"] + r": digest: (sha256:[0-9a-f]{64}) size: [0-9]+$", pushed)
        if len(matches) != 1:
            raise PublishError("Image push digest is uncertain; inspect registry state before retrying")
        # Fixed askpass code contains no token; only this Git subprocess receives
        # the ephemeral token in its environment. No credential helper is used.
        askpass = work / "git-askpass"
        askpass.write_text('#!/bin/sh\ncase "$1" in\n *Username*) printf "%s\\n" "x-access-token";;\n *Password*) printf "%s\\n" "$GITHUB_TOKEN";;\n *) exit 1;;\nesac\n')
        askpass.chmod(0o700)
        git_env = dict(env, GIT_ASKPASS=str(askpass), GITHUB_TOKEN=token)
        if remote_head(bare, BRANCH, git_env, runner) != source["release_parent"]:
            raise PublishError("Release branch changed after image push; image exists, source/ref was not replaced")
        lease = "--force-with-lease=" + BRANCH + ":" + (source["release_parent"] or "")
        # This is an exact compare-and-swap lease, not permission to rewrite
        # history: validate_bundle proved descendant ancestry (or create-only).
        git(bare, "push", lease, REMOTE, source["source_commit"] + ":" + BRANCH, env=git_env, runner=runner)
        if remote_head(bare, BRANCH, git_env, runner) != source["source_commit"]:
            raise PublishError("Source push outcome is uncertain; inspect branch before retrying")
        release = {key: value for key, value in source.items() if key != "release_parent"}
        release["format"] = "rival-it-share-release"
        release["image"] = IMAGE + "@" + matches[0]
        write_json(output / "release.json", release)
        return {"mode": "prepared", "source_commit": source["source_commit"], "image": release["image"],
                "result": "image/source published; unsigned manifest ready for trusted workflow attestation"}


def release(control, artifacts, output, bundle, *, publish=False, environ=None, runner=subprocess.run,
            api_factory=GitHub, verifier=None):
    environ = os.environ if environ is None else environ
    with validated(control, artifacts, runner) as (source, gates, bare, work, env):
        output = canonical(output, True)
        snapshot(output / "release.json", work / "release.json", 16 * 1024)
        snapshot(bundle, work / "release.sigstore.jsonl", 2 * 1024 * 1024)
        manifest_data = (work / "release.json").read_bytes()
        manifest = strict_json(manifest_data)
        expected = {k: v for k, v in source.items() if k != "release_parent"}
        expected["format"] = "rival-it-share-release"
        expected["image"] = manifest.get("image") if isinstance(manifest, dict) else None
        if manifest != expected or not isinstance(expected["image"], str) or not re.fullmatch(r"ghcr\.io/nickanewell/share@sha256:[0-9a-f]{64}", expected["image"]):
            raise PublishError("Release manifest does not match the validated source and gate")
        if not publish:
            return {"mode": "plan", "source_commit": source["source_commit"],
                    "result": "files validated; signature not verified and nothing published"}
        token = context(source, environ)
        repo_id = environ.get("GITHUB_REPOSITORY_ID", "")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", repo_id):
            raise PublishError("Trusted Actions repository ID is required")
        module = sibling("provenance")
        policy = {"repository": REPOSITORY, "repository_id": repo_id,
                  "signer_workflow": module.SIGNER, "allowed_control_commit": source["control_commit"],
                  "branding_sha256": source["branding_sha256"], "security_contract_sha256": source["security_contract_sha256"],
                  "allowed_major": 2, "file_format_version": 2}
        verified = (verifier or module.verify_release)(work / "release.json", work / "release.sigstore.jsonl", policy, runner=runner)
        if verified != manifest:
            raise PublishError("Signature verifier did not return this exact release manifest")
        api = api_factory(token)
        preflight_remote(source, bare, env, runner, api, branch_published=True)
        if (output / "release-attempt.json").exists():
            raise PublishError("A release attempt was already recorded; inspect its outcome before retrying")
        write_json(output / "release-attempt.json", {"source_commit": source["source_commit"], "state": "release started"})
        tag = "rival-auto-" + source["upstream_tag"]
        draft = api.request("POST", "/repos/" + REPOSITORY + "/releases", {
            "tag_name": tag, "target_commitish": source["source_commit"], "name": "Rival IT Share " + source["upstream_tag"],
            "body": "Automatically tested branded release. Source: " + source["source_commit"] + ". Image: " + manifest["image"],
            "draft": True, "prerelease": False, "make_latest": "false"})
        identifier = draft.get("id") if isinstance(draft, dict) else None
        if type(identifier) is not int or identifier <= 0 or draft.get("draft") is not True:
            raise PublishError("Draft creation outcome is uncertain; inspect GitHub before retrying")
        for name in ("release.json", "release.sigstore.jsonl", "source.bundle"):
            data = (work / name).read_bytes()
            asset = api.request("POST", f"/repos/{REPOSITORY}/releases/{identifier}/assets?name={name}", data, upload=True)
            if not isinstance(asset, dict) or asset.get("name") != name or asset.get("size") != len(data) or asset.get("state") != "uploaded":
                raise PublishError("Asset upload failed or is uncertain; release remains draft")
        published = api.request("PATCH", f"/repos/{REPOSITORY}/releases/{identifier}", {"draft": False, "make_latest": "false"})
        if not isinstance(published, dict) or published.get("draft") is not False or published.get("tag_name") != tag:
            raise PublishError("Final publication outcome is uncertain; inspect GitHub before retrying")
        return {"mode": "published", "tag": tag, "image": manifest["image"],
                "url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "release"))
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--publish", action="store_true")
    group.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.control, args.artifacts, args.output, publish=args.publish)
        else:
            if args.bundle is None:
                parser.error("release requires --bundle")
            result = release(args.control, args.artifacts, args.output, args.bundle, publish=args.publish)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, "Release publication stopped: " + str(error) + "\n")


if __name__ == "__main__":
    main()
