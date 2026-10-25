#!/usr/bin/env python3
"""Restore pinned artwork into a disposable checkout; never deploys or edits code.

The source/manifest must come from a trusted, pinned fork checkout. Roots must
not overlap and the candidate must have no concurrent writer. All inputs and
existing destinations are checked before any directory or asset is written.
Use canonical root/manifest paths: symlink ancestors are rejected, including OS
aliases such as macOS /tmp. Descriptor-relative traversal rejects symlinks. This is not
a sandbox against another process renaming directories during the operation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat


ASSETS = frozenset({
    "packages/frontend/static/favicon.png",
    "packages/frontend/static/logo-light.svg",
    "packages/frontend/static/logo-dark.svg",
    "packages/frontend/static/branding/rival-it-master-lockup.png",
    "packages/frontend/static/branding/rival-it-master-mark.png",
})
MAX_ASSET_BYTES = 5 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest) != {"format", "version", "assets"}:
        raise ValueError("Unexpected branding manifest schema")
    if manifest["format"] != "rival-it-brand-overlay" or type(manifest["version"]) is not int or manifest["version"] != 1:
        raise ValueError("Unsupported branding manifest format/version")
    assets = manifest["assets"]
    if not isinstance(assets, dict) or set(assets) != ASSETS:
        raise ValueError("Manifest must contain only the five approved artwork paths")
    for path, digest in assets.items():
        if str(PurePosixPath(path)) != path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise ValueError("Artwork paths must be canonical and repository-relative")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Artwork hashes must be lowercase SHA256")
    return assets


def load_manifest(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate manifest key")
            result[key] = value
        return result
    check_directories(Path(path).absolute().parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Branding manifest must be a regular file")
        data = stream.read(8193)
    if len(data) > 8192:
        raise ValueError("Branding manifest is too large")
    manifest = json.loads(data, object_pairs_hook=unique)
    validate_manifest(manifest)
    return manifest


def check_directories(path):
    for component in (*reversed(path.parents), path):
        if not stat.S_ISDIR(component.lstat().st_mode):
            raise ValueError("Roots and ancestors must be real directories")


def parent_fd(root, parts, create=False):
    fd = os.dup(root)
    try:
        for part in parts:
            try:
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                os.mkdir(part, mode=0o755, dir_fd=fd)
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def check_destination(fd, name):
    try:
        mode = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise ValueError("Destination artwork must be a regular file")


def apply_overlay(source, target, manifest):
    assets = validate_manifest(manifest)
    source, target = Path(source).absolute(), Path(target).absolute()
    check_directories(source)
    check_directories(target)
    # Do not resolve a root symlink away before the no-follow open below.
    real_source, real_target = source.resolve(strict=True), target.resolve(strict=True)
    if real_source == real_target or real_source in real_target.parents or real_target in real_source.parents:
        raise ValueError("Trusted source and disposable candidate roots must not overlap")
    src = os.open(source, DIR_FLAGS)
    try:
        dst = os.open(target, DIR_FLAGS)
        try:
            prepared = []
            for path, digest in sorted(assets.items()):
                parts = PurePosixPath(path).parts
                parent = parent_fd(src, parts[:-1])
                if parent is None:
                    raise ValueError("A trusted artwork input is missing")
                try:
                    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    with os.fdopen(fd, "rb") as stream:
                        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                            raise ValueError("Trusted artwork must be a regular file")
                        data = stream.read(MAX_ASSET_BYTES + 1)
                finally:
                    os.close(parent)
                if len(data) > MAX_ASSET_BYTES or hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError("Trusted artwork hash/size check failed: " + path)
                parent = parent_fd(dst, parts[:-1])
                if parent is not None:
                    try:
                        check_destination(parent, parts[-1])
                    finally:
                        os.close(parent)
                prepared.append((parts, digest, data))

            # Only validated bytes are used after the complete preflight.
            for parts, digest, data in prepared:
                parent = parent_fd(dst, parts[:-1], create=True)
                temporary = ".rival-brand-" + secrets.token_hex(12)
                try:
                    check_destination(parent, parts[-1])
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(data)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
                    finally:
                        try:
                            os.unlink(temporary, dir_fd=parent)
                        except FileNotFoundError:
                            pass
                finally:
                    os.close(parent)
            return [{"path": "/".join(parts), "sha256": digest} for parts, digest, _ in prepared]
        finally:
            os.close(dst)
    finally:
        os.close(src)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="trusted pinned fork checkout")
    parser.add_argument("target", type=Path, help="disposable candidate checkout; no concurrent writers")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("brand-manifest.json"))
    args = parser.parse_args()
    try:
        print(json.dumps(apply_overlay(args.source, args.target, load_manifest(args.manifest)), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, "Branding overlay stopped: " + str(error) + "\n")


if __name__ == "__main__":
    main()
