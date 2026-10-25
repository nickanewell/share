#!/usr/bin/env python3
"""Discover a public signed release; only an explicitly enabled promoter may apply it.

No GitHub token, registry credential, shell, candidate script or Docker operation
is used here. Downloads are untrusted until the separate promoter authenticates
the local manifest and binds it to the expected upstream release.
"""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request


REPOSITORY = "nickanewell/share"
API = "https://api.github.com/repos/" + REPOSITORY + "/releases"
TAG = re.compile(r"rival-auto-v(2)\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z")
ASSET_LIMITS = {"release.json": 32 * 1024, "release.sigstore.jsonl": 4 * 1024 * 1024}
REDIRECT_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
INSTALL_ROOT = Path("/usr/local/lib/rival-share-update")
INSTALLED_MODULES = ("controller.py", "promote.py", "provenance.py")


class ControllerError(ValueError):
    pass


def validate_bootstrap(script, *, isolated, lstat=os.lstat):
    """Standard-library-only check, before importing any installed updater code.

    Python -I is essential: script code cannot undo a malicious sitecustomize
    that the interpreter already imported from an inherited PYTHONPATH.
    """
    if not isolated:
        raise ControllerError("Applying updates requires the isolated Python interpreter (-I)")
    if Path(script) != INSTALL_ROOT / "controller.py":
        raise ControllerError("Applying updates requires the reviewed fixed installation path")
    checked = set()
    for filename in INSTALLED_MODULES:
        module = INSTALL_ROOT / filename
        for path in [*reversed(module.parents), module]:
            if path in checked:
                continue
            checked.add(path)
            info = lstat(path)
            if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                raise ControllerError("Untrusted updater code ownership/mode or symlink")
            expected = stat.S_ISREG if path == module else stat.S_ISDIR
            if not expected(info.st_mode):
                raise ControllerError("Unexpected updater code file type")


def import_promoter(apply):
    # Keep importlib local so the only modules imported before this validation
    # are standard library modules loaded by Python's isolated interpreter.
    if apply:
        validate_bootstrap(Path(__file__), isolated=bool(sys.flags.isolated))
        directory = INSTALL_ROOT
    else:
        directory = Path(__file__).resolve().parent
    import importlib.util
    # -I excludes the script directory. Only the checked installation is added
    # for the promoter's later sibling import of provenance, never the cwd.
    if apply:
        sys.path.insert(0, str(directory))
    path = directory / "promote.py"
    specification = importlib.util.spec_from_file_location("rival_share_trusted_promoter", path)
    if specification is None or specification.loader is None:
        raise ControllerError("Trusted promoter module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ControllerError("Duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(ControllerError("Invalid JSON constant")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ControllerError("Malformed release JSON") from error


def valid_https(url, hosts):
    try:
        parsed = urllib.parse.urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname in hosts and parsed.port in (None, 443)
                and not parsed.username and not parsed.password and not parsed.fragment)
    except (TypeError, ValueError):
        return False


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 1

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # API repository renames/transfers need deliberate review, not redirects.
        if urllib.parse.urlsplit(req.full_url).hostname == "api.github.com":
            raise ControllerError("API redirects are not accepted")
        if not valid_https(newurl, REDIRECT_HOSTS):
            raise ControllerError("Release asset redirected outside approved HTTPS hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_bytes(url, maximum):
    if not valid_https(url, REDIRECT_HOSTS | {"api.github.com"}):
        raise ControllerError("Unapproved download destination")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SafeRedirect())
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json" if url.startswith(API + "?") else "application/octet-stream",
        "User-Agent": "RivalITShareUpdater/1",
    })
    try:
        with opener.open(request, timeout=25) as response:
            if response.status != 200:
                raise ControllerError("Expected HTTP 200 for release data")
            data = response.read(maximum + 1)
    except urllib.error.HTTPError as error:
        raise ControllerError("Release request failed with HTTP " + str(error.code)) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ControllerError("Release network request failed") from None
    if len(data) > maximum:
        raise ControllerError("Release data exceeds its size limit")
    return data


def release_record(release):
    """Validate eligible metadata, but never treat it as authenticated provenance."""
    if not isinstance(release, dict):
        raise ControllerError("Expected release objects")
    tag = release.get("tag_name")
    match = TAG.fullmatch(tag) if isinstance(tag, str) else None
    if not match or release.get("draft") is not False or release.get("prerelease") is not False:
        return None
    identifier = release.get("id")
    if type(identifier) is not int or identifier <= 0:
        raise ControllerError("Release ID must be a positive integer")
    if not isinstance(release.get("published_at"), str) or not TIMESTAMP.fullmatch(release["published_at"]):
        raise ControllerError("Published release timestamp is missing or malformed")
    if release.get("html_url") != f"https://github.com/{REPOSITORY}/releases/tag/{tag}":
        raise ControllerError("Release identity does not match the approved repository")
    entries = release.get("assets")
    if not isinstance(entries, list) or len(entries) > 100:
        raise ControllerError("Expected a bounded asset list")
    assets = {}
    for asset in entries:
        if not isinstance(asset, dict):
            raise ControllerError("Expected asset objects")
        name = asset.get("name")
        if name not in ASSET_LIMITS:
            continue  # Other assets are neither fetched nor interpreted.
        if name in assets:
            raise ControllerError("Ambiguous duplicate release asset")
        expected = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        if asset.get("browser_download_url") != expected:
            raise ControllerError("Release asset URL does not match its repository/tag/name")
        if type(asset.get("size")) is not int or not 0 < asset["size"] <= ASSET_LIMITS[name]:
            raise ControllerError("Release asset size is missing or exceeds its limit")
        assets[name] = expected
    if set(assets) != set(ASSET_LIMITS):
        raise ControllerError("Required signed release assets are missing")
    return {"tag": tag, "upstream_tag": "v" + ".".join(match.groups()),
            "version": tuple(map(int, match.groups())), "id": identifier, "assets": assets}


def discover(fetch=fetch_bytes):
    records = {}
    for page in range(1, 11):
        data = fetch(API + f"?per_page=100&page={page}", 2 * 1024 * 1024)
        if len(data) > 2 * 1024 * 1024:
            raise ControllerError("Release metadata exceeds its size limit")
        batch = strict_json(data)
        if not isinstance(batch, list) or len(batch) > 100:
            raise ControllerError("Expected at most 100 releases per page")
        for release in batch:
            record = release_record(release)
            if record is None:
                continue
            previous = records.get(record["version"])
            if previous is not None and previous != record:
                raise ControllerError("Ambiguous duplicate release version")
            records[record["version"]] = record
        if len(batch) < 100:
            return records[max(records)] if records else None
    raise ControllerError("Release page limit reached; manual review required")


def checked_directory(fd, expected_uid):
    current = os.fstat(fd)
    if not stat.S_ISDIR(current.st_mode) or current.st_uid != expected_uid or current.st_mode & 0o022:
        raise ControllerError("Incoming state must be a trusted private directory")


def save_inputs(state_dir, identifier, manifest, bundle, expected_uid=0):
    """Write bounded untrusted inputs only below a previously preflighted state dir."""
    if type(identifier) is not int or identifier <= 0:
        raise ControllerError("Release ID must be a positive integer")
    if (not isinstance(manifest, bytes) or not isinstance(bundle, bytes) or not manifest or not bundle
            or len(manifest) > ASSET_LIMITS["release.json"] or len(bundle) > ASSET_LIMITS["release.sigstore.jsonl"]):
        raise ControllerError("Release input exceeds its size limit")
    parent = os.open(state_dir, DIR_FLAGS)
    try:
        checked_directory(parent, expected_uid)
        try:
            os.mkdir("incoming", 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        incoming = os.open("incoming", DIR_FLAGS, dir_fd=parent)
        try:
            checked_directory(incoming, expected_uid)
            name = f"release-{identifier}-" + secrets.token_hex(12)
            os.mkdir(name, 0o700, dir_fd=incoming)
            destination = os.open(name, DIR_FLAGS, dir_fd=incoming)
            try:
                checked_directory(destination, expected_uid)
                for filename, data in (("release.json", manifest), ("release.sigstore.jsonl", bundle)):
                    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=destination)
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                os.fsync(destination)
            finally:
                os.close(destination)
            os.fsync(incoming)
        finally:
            os.close(incoming)
    finally:
        os.close(parent)
    directory = Path(state_dir) / "incoming" / name
    return directory / "release.json", directory / "release.sigstore.jsonl"


def run(policy_path, apply=False, fetch=fetch_bytes, promoter=None, save=save_inputs):
    if promoter is None:
        promoter = import_promoter(apply)
    policy = promoter.load_policy(policy_path, apply=apply)
    # load_policy(apply=True) checks enabled/root/config/state before any downloads or writes.
    selection = discover(fetch)
    if selection is None:
        return {"mode": "apply" if apply else "plan", "result": "no eligible release"}
    if not apply:
        return {"mode": "plan", "candidate_release": selection["tag"], "authenticated": False,
                "result": "discovery only; nothing downloaded or executed"}
    manifest = fetch(selection["assets"]["release.json"], ASSET_LIMITS["release.json"])
    bundle = fetch(selection["assets"]["release.sigstore.jsonl"], ASSET_LIMITS["release.sigstore.jsonl"])
    if (not isinstance(manifest, bytes) or not isinstance(bundle, bytes)
            or len(manifest) > ASSET_LIMITS["release.json"] or len(bundle) > ASSET_LIMITS["release.sigstore.jsonl"]):
        raise ControllerError("Release input exceeds its size limit")
    # Basic parsing bounds disk use/fails early; promoter performs cryptographic validation.
    if not isinstance(strict_json(manifest), dict) or not bundle:
        raise ControllerError("Malformed signed release inputs")
    paths = save(policy["state_dir"], selection["id"], manifest, bundle)
    return promoter.promote_release(paths[0], paths[1], policy, apply=True,
                                    expected_upstream_tag=selection["upstream_tag"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("/etc/rival-share/update-policy.json"))
    parser.add_argument("--apply", action="store_true", help="requires an enabled, root-owned reviewed host policy")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.policy, apply=args.apply), sort_keys=True))
    except Exception as error:
        # Exception details/redirect query strings must not expose signed URLs or private config.
        parser.exit(1, "Update controller stopped (" + type(error).__name__ + "); no fallback was attempted.\n")


if __name__ == "__main__":
    main()
