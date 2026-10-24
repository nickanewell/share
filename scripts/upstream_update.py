#!/usr/bin/env python3
"""Discover stable upstream releases and prepare a local, reviewable update.

This script never pushes, opens PRs, publishes images/packages, or deploys.
The workflow performs the two explicit proposal writes after this script exits.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request


UPSTREAM = "cupcakearmy/cryptgeon"
TAG = re.compile(r"v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z")
EXCLUDED = (
    ".github",
    ".upstream-sync.json",
    "scripts/upstream_update.py",
    "scripts/test_upstream_update.py",
    "docs/upstream-maintenance.md",
)


def version(tag):
    match = TAG.fullmatch(tag) if isinstance(tag, str) else None
    if not match:
        raise ValueError("Expected a stable tag such as v2.9.3")
    return tuple(map(int, match.groups()))


def read_config(root):
    config = json.loads((root / ".upstream-sync.json").read_text())
    if config["repository"] != UPSTREAM:
        raise ValueError("Only the reviewed Cryptgeon upstream is allowed")
    if version(config["current_tag"])[0] != config["major"]:
        raise ValueError("Baseline major does not match the allowed major")
    if not re.fullmatch(r"[0-9a-f]{40}", config["current_commit"]):
        raise ValueError("Baseline must pin an upstream commit")
    for path in config["protected_paths"]:
        if not isinstance(path, str) or path.startswith(("/", ":")) or ".." in Path(path).parts:
            raise ValueError("Protected paths must be repository-relative")
    return config


def select_release(releases, config):
    current = version(config["current_tag"])
    candidates = []
    for release in releases:
        if release.get("draft") or release.get("prerelease") or not release.get("published_at"):
            continue
        try:
            item = version(release.get("tag_name"))
        except ValueError:
            continue
        candidates.append((item, release["tag_name"]))
    same_major = [item for item in candidates if item[0][0] == config["major"] and item[0] > current]
    new_major = [item for item in candidates if item[0][0] > config["major"]]
    return {
        "available": bool(same_major),
        "tag": max(same_major)[1] if same_major else "",
        "branch": "automation/upstream-" + max(same_major)[1] if same_major else "",
        "major_available": max(new_major)[1] if new_major else "",
    }


def fetch_releases():
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    releases = []
    for page in range(1, 11):
        url = f"https://api.github.com/repos/{UPSTREAM}/releases?per_page=100&page={page}"
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=25) as response:
            data = response.read(2_097_153)
        if len(data) > 2_097_152:
            raise RuntimeError("Release response exceeds the expected size")
        batch = json.loads(data)
        if not isinstance(batch, list):
            raise RuntimeError("Expected a release list")
        releases.extend(batch)
        if len(batch) < 100:
            return releases
    raise RuntimeError("Too many release pages; review the updater before continuing")


def git(root, *args, data=None, check=True):
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C", str(root), *args],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace").strip() or f"git {args[0]} failed")
    return result


def protected(path, roots):
    return any(path == root.rstrip("/") or path.startswith(root.rstrip("/") + "/") for root in roots)


def apply_delta(root, baseline, target, config):
    """Apply a reviewed-tag delta without upstream workflows or branding changes.

    Three-way application preserves fork-only patches. Conflicts stop without a
    commit; the failed CI checkout is disposable and no remote write takes place.
    """
    if git(root, "status", "--porcelain").stdout:
        raise RuntimeError("A clean working tree is required")
    git(root, "merge-base", "--is-ancestor", baseline, target)
    changed = git(root, "diff", "--name-only", "--no-renames", baseline, target).stdout.decode().splitlines()
    touched_branding = [path for path in changed if protected(path, config["protected_paths"])]
    if touched_branding:
        raise RuntimeError("Upstream touched protected branding; review manually: " + ", ".join(touched_branding))
    pathspec = ["--", ".", *(":(exclude)" + path for path in EXCLUDED)]
    patch = git(root, "diff", "--binary", "--full-index", "--no-ext-diff", baseline, target, *pathspec).stdout
    if patch:
        git(root, "apply", "--3way", "--index", "--whitespace=nowarn", "-", data=patch)
    if git(root, "diff", "--cached", "--name-only", "--", ".github").stdout:
        raise RuntimeError("Refusing an automated workflow change")


def prepare(root, config, tag, body_file):
    if version(tag)[0] != config["major"] or version(tag) <= version(config["current_tag"]):
        raise ValueError("Only a newer stable release within the configured major is allowed")
    if git(root, "status", "--porcelain").stdout:
        raise RuntimeError("A clean working tree is required")
    for release_tag in (config["current_tag"], tag):
        git(root, "fetch", "--no-tags", "--force", f"https://github.com/{UPSTREAM}.git",
            f"refs/tags/{release_tag}:refs/upstream-sync/{release_tag}")
    baseline = f"refs/upstream-sync/{config['current_tag']}^{{commit}}"
    target = f"refs/upstream-sync/{tag}^{{commit}}"
    baseline_sha = git(root, "rev-parse", baseline).stdout.decode().strip()
    target_sha = git(root, "rev-parse", target).stdout.decode().strip()
    if baseline_sha != config["current_commit"]:
        raise RuntimeError("The recorded upstream baseline tag moved; manual review is required")
    branch = "automation/upstream-" + tag
    git(root, "switch", "-c", branch)
    apply_delta(root, baseline, target, config)
    previous = config["current_tag"]
    config.update(current_tag=tag, current_commit=target_sha)
    (root / ".upstream-sync.json").write_text(json.dumps(config, indent=2) + "\n")
    git(root, "add", ".upstream-sync.json")
    git(root, "-c", "user.name=github-actions[bot]", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "-m", f"Update Cryptgeon to {tag}")
    skipped = git(root, "diff", "--name-only", baseline, target, "--", ".github").stdout.decode().strip()
    body_file.write_text(
        f"Bring the fork from upstream **{previous}** to **{tag}** while retaining Rival IT branding and local patches.\n\n"
        f"- Release: https://github.com/{UPSTREAM}/releases/tag/{tag}\n"
        f"- Upstream commit: `{target_sha}`\n"
        f"- Upstream delta: https://github.com/{UPSTREAM}/compare/{previous}...{tag}\n\n"
        "The update uses three-way application of the upstream delta. Branding changes and conflicts require manual handling. "
        "Upstream workflow changes are excluded so publishing cannot revert to upstream destinations.\n\n"
        "Upstream workflow changes to review separately:\n\n"
        + ("```text\n" + skipped + "\n```\n\n" if skipped else "None.\n\n")
        + "Review before merging:\n\n"
        "- [ ] Approve the PR workflows to run if GitHub requests approval; verify all required CI checks on this PR head.\n"
        "- [ ] Review configuration/API/codec changes and confirm the Rival IT logo, favicon and title.\n"
        "- [ ] Review excluded workflow changes and independently audit runtime/dependency advisories.\n"
        "- [ ] Keep deployment manual and identify the Nick-owned image digest/build commit before deploying.\n\n"
        "This automation does not publish packages/images, merge PRs, or deploy.\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("discover", "prepare"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--releases", type=Path, help="Local release JSON for a read-only discovery check")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--body-file", type=Path, default=Path("/tmp/upstream-update-body.md"))
    args = parser.parse_args()
    root = args.root.resolve()
    config = read_config(root)
    if args.command == "discover":
        releases = json.loads(args.releases.read_text()) if args.releases else fetch_releases()
        selected = select_release(releases, config)
        print(json.dumps(selected))
        if args.github_output:
            with args.github_output.open("a") as output:
                for key, value in selected.items():
                    output.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
        if selected["major_available"]:
            print("A new upstream major requires manual migration: " + selected["major_available"], file=sys.stderr)
    else:
        if not args.tag:
            parser.error("prepare requires --tag")
        prepare(root, config, args.tag, args.body_file)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print("Upstream update stopped: " + str(error), file=sys.stderr)
        sys.exit(1)
