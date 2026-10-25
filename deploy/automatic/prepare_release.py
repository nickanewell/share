#!/usr/bin/env python3
"""Prepare a disposable stable-release source bundle. Never publishes or deploys.

Execute this helper from the reviewed control checkout, never from upstream.
Build/test execution belongs in the isolated gate. A parent release commit is
history only: no file is inherited from its tree. Inputs/artifacts are not a
sandbox against a hostile concurrent local writer.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess


REPOSITORY = "nickanewell/share"
UPSTREAM = "cupcakearmy/cryptgeon"
SHA = re.compile(r"[0-9a-f]{40}\Z")
LFS = re.compile(rb"version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]{1,12})\n?\Z")
MAX_FILE = 64 * 1024 * 1024
SECURITY_PATHS = (
    "packages/backend/src/lock.rs", "packages/backend/src/note/routes.rs",
    "packages/backend/src/note/model.rs", "packages/backend/src/status/mod.rs",
    "packages/cli/src/shared/files.ts", "packages/cli/src/shared/adapters.ts",
    "packages/cli/src/shared/api.ts", "packages/cli/src/actions/upload.ts",
    "packages/cli/src/actions/download.ts", "packages/cli/src/utils/download-files.ts",
    "packages/frontend/src/routes/note/[id]/+page.svelte",
    "packages/frontend/src/lib/ui/NoteResult.svelte",
    "packages/frontend/src/lib/ui/FileUpload.svelte",
    "packages/backend/src/main.rs", "packages/backend/src/note/mod.rs",
    "packages/cli/src/cli.ts", "packages/cli/src/shared/shared.ts",
    "packages/frontend/src/lib/ui/ShowNote.svelte",
    "packages/frontend/src/lib/views/Create.svelte",
)
CONTRACT_PATHS = (
    "Dockerfile", ".dockerignore", ".gitattributes", ".lfsconfig", ".github",
    ".upstream-sync.json", "playwright.config.ts", "test", "scripts", "deploy/automatic",
) + SECURITY_PATHS
REQUIRED_CONTRACTS = (
    "Dockerfile", ".dockerignore", "playwright.config.ts", ".upstream-sync.json",
    "test/security/cli-download.test.mjs", "test/security/file-metadata.test.mjs",
    "test/web/file/security.spec.js", "deploy/automatic/brand-manifest.json",
) + SECURITY_PATHS
EXCLUDED = (".github", "deploy", "scripts", "docs", "Dockerfile", ".dockerignore",
            ".gitattributes", ".lfsconfig", ".upstream-sync.json", "playwright.config.ts", "test")


def _environment(extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k not in {"GH_TOKEN", "GITHUB_TOKEN"}}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/usr/bin/false", GIT_LFS_SKIP_SMUDGE="1")
    env.update(extra or {})
    return env


def git(root, *args, data=None, check=True, local=False, extra_env=None):
    command = ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgsign=false",
               "-c", "credential.helper=", "-c", "protocol.ext.allow=never",
               "-c", "protocol.file.allow=" + ("always" if local else "never"),
               "-c", "protocol.ssh.allow=never", "-c", "submodule.recurse=false",
               "-c", "filter.lfs.process=", "-c", "filter.lfs.clean=",
               "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false",
               "-C", str(root), *args]
    result = subprocess.run(command, input=data, capture_output=True, env=_environment(extra_env), timeout=90)
    if check and result.returncode:
        raise ValueError("Git preparation stopped: " + result.stderr.decode(errors="replace").strip())
    return result


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _safe_path(value):
    if (not value or str(PurePosixPath(value)) != value or PurePosixPath(value).is_absolute()
            or ".." in PurePosixPath(value).parts or "\\" in value or ":" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(part.casefold() == ".git" for part in PurePosixPath(value).parts)):
        raise ValueError("Unsafe repository path")
    return PurePosixPath(value).parts


def _read_file(root, path):
    current = Path(root)
    for part in _safe_path(path)[:-1]:
        current = current / part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("Repository ancestors must be real directories")
    fd = os.open(current / PurePosixPath(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise ValueError("Expected a bounded regular repository file")
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError("Repository file exceeds the preparation limit")
    return data


def _index(root):
    entries = {}
    for record in git(root, "ls-files", "--stage", "-z").stdout.split(b"\0"):
        if not record:
            continue
        header, path = record.split(b"\t", 1)
        mode, oid, stage = header.decode().split()
        path = path.decode("utf-8", errors="strict")
        _safe_path(path)
        if mode not in ("100644", "100755") or stage != "0" or path in entries:
            raise ValueError("Symlinks, submodules and unresolved index entries are forbidden")
        entries[path] = (mode, oid)
    return entries


def _blob(root, oid):
    size = int(git(root, "cat-file", "-s", oid).stdout)
    if size > MAX_FILE:
        raise ValueError("Repository blob exceeds the preparation limit")
    return git(root, "cat-file", "blob", oid).stdout


def _matches_blob(root, path, blob):
    data = _read_file(root, path)
    pointer = LFS.fullmatch(blob)
    if data == blob:
        return
    if pointer and len(data) == int(pointer[2]) and hashlib.sha256(data).hexdigest().encode() == pointer[1]:
        return
    raise ValueError("Working tree differs from its tracked blob: " + path)


def require_clean(root):
    """Check without invoking Git clean/smudge filters from the working tree."""
    if git(root, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "HEAD").stdout:
        raise ValueError("A clean control index is required")
    if git(root, "ls-files", "--others", "--exclude-standard", "-z").stdout:
        raise ValueError("A clean control working tree is required")
    for path, (_, oid) in _index(root).items():
        _matches_blob(root, path, _blob(root, oid))


def _contract_entries(root):
    entries = _index(root)
    if any(path not in entries for path in REQUIRED_CONTRACTS):
        raise ValueError("A required trusted security contract is missing")
    selected = {}
    for path, (mode, oid) in sorted(entries.items()):
        if any(path == prefix or path.startswith(prefix + "/") for prefix in CONTRACT_PATHS):
            blob = _blob(root, oid)
            _matches_blob(root, path, blob)
            selected[path] = (mode, blob)
    return selected


def contract_digest(control):
    """Hash canonical tracked contract bytes; normalize verified LFS materialization."""
    digest = hashlib.sha256(b"rival-it-security-contract-v1\0")
    for path, (mode, blob) in _contract_entries(control).items():
        for value in (path.encode(), mode.encode(), blob):
            digest.update(len(value).to_bytes(8, "big")); digest.update(value)
    return digest.hexdigest()


def assert_contract(control, candidate):
    if _contract_entries(control) != _contract_entries(candidate):
        raise ValueError("Candidate changed a trusted build/security contract or security implementation")


def _scan_upstream(root, baseline, target):
    for record in git(root, "ls-tree", "-r", "-z", target).stdout.split(b"\0"):
        if not record:
            continue
        head, name = record.split(b"\t", 1)
        mode, kind, _ = head.decode().split()
        _safe_path(name.decode("utf-8", errors="strict"))
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError("Upstream symlinks and submodules require manual review")
    changed = git(root, "diff", "--name-only", "--no-renames", "-z", baseline, target).stdout.split(b"\0")
    for raw in changed:
        if not raw:
            continue
        parts = _safe_path(raw.decode("utf-8", errors="strict"))
        if (parts[-1] in {".npmrc", ".pnpmfile.cjs", ".gitconfig", ".gitmodules", ".lfsconfig"}
                or ".cargo" in parts and parts[-1] in {"config", "config.toml"}):
            raise ValueError("Upstream executable/tool configuration requires manual review")


def _prepare(control, candidate, tag, expected_upstream_sha, release_parent, upstream_source, release_source, local):
    control, candidate = Path(control).absolute(), Path(candidate).absolute()
    overlay = _load(Path(__file__).with_name("brand_overlay.py"), "trusted_brand_overlay")
    overlay.check_directories(control)
    overlay.check_directories(candidate.parent)
    if control == candidate or control in candidate.parents or candidate in control.parents:
        raise ValueError("Candidate must be separate from the trusted control checkout")
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("A fresh candidate path is required")
    artifacts = [candidate.parent / "source.bundle", candidate.parent / "release-input.json"]
    if any(p.exists() or p.is_symlink() for p in artifacts):
        raise ValueError("Fresh exclusive artifact paths are required")
    if not SHA.fullmatch(expected_upstream_sha) or release_parent is not None and not SHA.fullmatch(release_parent):
        raise ValueError("Full lowercase expected commit identities are required")
    require_clean(control)
    updater = _load(control / "scripts/upstream_update.py", "trusted_upstream_update")
    config = updater.read_config(control)
    if config["major"] != 2 or updater.version(tag)[0] != 2 or updater.version(tag) <= updater.version(config["current_tag"]):
        raise ValueError("Only a newer stable major-2 release is eligible")
    control_sha = git(control, "rev-parse", "HEAD^{commit}").stdout.decode().strip()
    # Cloning this exact local trusted path copies objects, never hooks/config.
    git(candidate.parent, "clone", "--no-hardlinks", "--no-checkout", str(control), str(candidate), local=True)
    git(candidate, "switch", "--detach", control_sha)
    for release_tag, destination in ((config["current_tag"], "baseline"), (tag, "target")):
        git(candidate, "fetch", "--no-tags", "--no-recurse-submodules", upstream_source,
            "refs/tags/" + release_tag + ":refs/preparation/" + destination, local=local)
    baseline = git(candidate, "rev-parse", "refs/preparation/baseline^{commit}").stdout.decode().strip()
    target = git(candidate, "rev-parse", "refs/preparation/target^{commit}").stdout.decode().strip()
    if baseline != config["current_commit"] or target != expected_upstream_sha:
        raise ValueError("An upstream tag moved or differs from its expected pinned identity")
    git(candidate, "merge-base", "--is-ancestor", baseline, target)
    _scan_upstream(candidate, baseline, target)
    manifest = overlay.load_manifest(control / "deploy/automatic/brand-manifest.json")
    assets = tuple(manifest["assets"])
    config["protected_paths"] = [path for path in config["protected_paths"]
                                 if not any(path == asset or asset.startswith(path.rstrip("/") + "/") for asset in assets)]
    updater.EXCLUDED = tuple(dict.fromkeys((*updater.EXCLUDED, *EXCLUDED, *assets)))
    updater.git = lambda root, *args, data=None, check=True: git(root, *args, data=data, check=check)
    updater.apply_delta(candidate, baseline, target, config)
    overlay.apply_overlay(control, candidate, manifest)
    assert_contract(control, candidate)
    git(candidate, "add", "--", *assets)
    parents = [control_sha]
    if release_parent:
        git(candidate, "fetch", "--no-tags", "--no-recurse-submodules", release_source,
            "refs/heads/automation/release-v2:refs/preparation/release-parent", local=local)
        observed = git(candidate, "rev-parse", "refs/preparation/release-parent^{commit}").stdout.decode().strip()
        if observed != release_parent:
            raise ValueError("The guarded release branch changed")
        if release_parent != control_sha:
            parents.append(release_parent)
    tree = git(candidate, "write-tree").stdout.decode().strip()
    timestamp = git(candidate, "show", "-s", "--format=%ct", target).stdout.decode().strip()
    if not re.fullmatch(r"[0-9]{1,12}", timestamp):
        raise ValueError("Unsupported upstream commit timestamp")
    author = dict(GIT_AUTHOR_NAME="Rival IT automation", GIT_COMMITTER_NAME="Rival IT automation",
                  GIT_AUTHOR_EMAIL="automation@example.invalid", GIT_COMMITTER_EMAIL="automation@example.invalid",
                  GIT_AUTHOR_DATE=timestamp + " +0000", GIT_COMMITTER_DATE=timestamp + " +0000")
    args = ["commit-tree", tree]
    for parent in parents:
        args += ["-p", parent]
    source_sha = git(candidate, *args, data=(f"Prepare Cryptgeon {tag} ({target}) with reviewed Rival IT controls\n").encode(), extra_env=author).stdout.decode().strip()
    git(candidate, "update-ref", "refs/heads/automation-candidate", source_sha)
    git(candidate, "switch", "automation-candidate")
    require_clean(candidate)
    metadata = dict(format="rival-it-share-source", schema_version=1, repository=REPOSITORY,
                    control_commit=control_sha, source_commit=source_sha, upstream_repository=UPSTREAM,
                    upstream_tag=tag, upstream_commit=target,
                    branding_sha256=hashlib.sha256(_read_file(control, "deploy/automatic/brand-manifest.json")).hexdigest(),
                    security_contract_sha256=contract_digest(control), file_format_version=2, release_parent=release_parent)
    # Keep generated artifacts out of the source/build context and use exclusive
    # destination creation; a failed run must be discarded, never overwritten.
    internal = candidate / ".git/prepared-source.bundle"
    git(candidate, "bundle", "create", str(internal), "refs/heads/automation-candidate")
    expected_head = (source_sha + " refs/heads/automation-candidate").encode()
    if git(candidate, "bundle", "list-heads", str(internal)).stdout.strip() != expected_head:
        raise ValueError("Unexpected bundle refs")
    with open(internal, "rb") as source, open(artifacts[0], "xb") as destination:
        shutil.copyfileobj(source, destination)
    with open(artifacts[1], "x", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2); stream.write("\n")
    return metadata


def prepare_online(control, candidate, tag, expected_upstream_sha, release_parent=None):
    return _prepare(control, candidate, tag, expected_upstream_sha, release_parent,
                    "https://github.com/" + UPSTREAM + ".git", "https://github.com/" + REPOSITORY + ".git", False)


def prepare_from_refs(control, candidate, tag, expected_upstream_sha, upstream_source, release_parent=None, release_source=None):
    """Offline fixture entry point: local repositories only; never a URL override."""
    upstream_source = Path(upstream_source).resolve(strict=True)
    release_source = Path(release_source or control).resolve(strict=True)
    return _prepare(control, candidate, tag, expected_upstream_sha, release_parent,
                    str(upstream_source), str(release_source), True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-upstream-commit", required=True)
    parser.add_argument("--release-parent")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare_online(args.control, args.candidate, args.tag,
                                       args.expected_upstream_commit, args.release_parent), indent=2))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, "Automatic source preparation stopped: " + str(error) + "\n")


if __name__ == "__main__":
    main()
