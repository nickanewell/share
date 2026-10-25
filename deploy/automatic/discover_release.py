#!/usr/bin/env python3
"""Read-only discovery for the trusted automatic-release workflow."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

from provenance import SHA1, TAG, strict_json

UPSTREAM = "cupcakearmy/cryptgeon"
REPOSITORY = "nickanewell/share"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("API redirects require review")


def api(path):
    if not re.fullmatch(r"/repos/(?:cupcakearmy/cryptgeon/releases\?per_page=100&page=[1-9][0-9]?|nickanewell/share/releases/tags/rival-auto-v[0-9]+\.[0-9]+\.[0-9]+)", path):
        raise ValueError("Unexpected discovery endpoint")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "rival-share-release-discovery",
               "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request("https://api.github.com" + path, headers=headers), timeout=25) as response:
            data = response.read(2 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404 and path.startswith("/repos/" + REPOSITORY + "/releases/tags/"):
            return None
        raise ValueError("Release discovery API failed") from None
    if not data or len(data) > 2 * 1024 * 1024:
        raise ValueError("Release discovery response exceeds its limit")
    return strict_json(data)


def remote_refs(repository, refs):
    if repository not in (UPSTREAM, REPOSITORY):
        raise ValueError("Unexpected repository")
    result = subprocess.run(["git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
                             "ls-remote", "https://github.com/" + repository + ".git", *refs],
                            capture_output=True, text=True, timeout=60, check=True,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent",
                                 "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
    if len(result.stdout) > 4096:
        raise ValueError("Unexpected remote ref response")
    found = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not SHA1.fullmatch(parts[0]) or parts[1] not in refs or parts[1] in found:
            raise ValueError("Unexpected remote ref identity")
        found[parts[1]] = parts[0]
    return found


def numbers(tag):
    match = TAG.fullmatch(tag) if isinstance(tag, str) else None
    if not match:
        raise ValueError("Expected a stable semantic release tag")
    return tuple(map(int, match.groups()))


def discover(control, fetch=api, refs=remote_refs):
    config = strict_json((Path(control) / ".upstream-sync.json").read_bytes())
    if config.get("repository") != UPSTREAM or config.get("major") != 2 or type(config.get("major")) is not int:
        raise ValueError("Unsupported upstream policy")
    current = numbers(config["current_tag"])
    if current[0] != 2 or not SHA1.fullmatch(config.get("current_commit", "")):
        raise ValueError("Invalid pinned upstream baseline")
    releases = []
    for page in range(1, 11):
        batch = fetch(f"/repos/{UPSTREAM}/releases?per_page=100&page={page}")
        if not isinstance(batch, list) or len(batch) > 100:
            raise ValueError("Expected a bounded release list")
        releases.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError("Release pagination exceeded its limit")
    stable = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False or not release.get("published_at"):
            continue
        try:
            stable.append((numbers(release.get("tag_name")), release["tag_name"]))
        except ValueError:
            continue
    newer = [item for item in stable if item[0][0] == 2 and item[0] > current]
    majors = [item for item in stable if item[0][0] > 2]
    result = {"available": False, "tag": "", "upstream_commit": "", "release_parent": "",
              "major_available": max(majors)[1] if majors else "", "reason": "no-newer-compatible-release"}
    if not newer:
        return result
    tag = max(newer)[1]
    direct = "refs/tags/" + tag
    found = refs(UPSTREAM, [direct, direct + "^{}"])
    target = found.get(direct + "^{}", found.get(direct))
    if not target or not SHA1.fullmatch(target):
        raise ValueError("Selected upstream tag has no pinned Git identity")
    existing = fetch(f"/repos/{REPOSITORY}/releases/tags/rival-auto-{tag}")
    if existing is not None:
        if not isinstance(existing, dict) or existing.get("tag_name") != "rival-auto-" + tag or existing.get("draft") is not False or existing.get("prerelease") is not False:
            raise ValueError("An existing partial or unexpected release requires review")
        expected_names = {"release.json", "release.sigstore.jsonl", "source.bundle"}
        assets = existing.get("assets")
        if not isinstance(assets, list) or {a.get("name") for a in assets if isinstance(a, dict)} != expected_names:
            raise ValueError("An existing incomplete release requires review")
        # This is duplicate-publication prevention, not a trust assertion.
        # The VM independently verifies the signed manifest before any promotion.
        result.update(tag=tag, upstream_commit=target, reason="already-published-vm-verifies-independently")
        return result
    branch = "refs/heads/automation/release-v2"
    parent = refs(REPOSITORY, [branch]).get(branch, "")
    if parent and not SHA1.fullmatch(parent):
        raise ValueError("Unexpected release branch head")
    result.update(available=True, tag=tag, upstream_commit=target, release_parent=parent, reason="new-compatible-release")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        result = discover(args.control)
        print(json.dumps(result, sort_keys=True))
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as stream:
                for key in ("available", "tag", "upstream_commit", "release_parent", "major_available"):
                    value = str(result[key]).lower() if isinstance(result[key], bool) else result[key]
                    if "\n" in value or "\r" in value:
                        raise ValueError("Invalid workflow output")
                    stream.write(key + "=" + value + "\n")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, "Discovery stopped: " + str(error) + "\n")


if __name__ == "__main__":
    main()
