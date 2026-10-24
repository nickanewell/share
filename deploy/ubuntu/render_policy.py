#!/usr/bin/env python3
"""Render reviewable Ubuntu maintenance files. Never installs or enables them."""

import argparse
import json
import re
from pathlib import Path


PACKAGES = {
    "docker-ce": 29,
    "docker-ce-cli": 29,
    "containerd.io": 2,
    "docker-compose-plugin": 5,
    "docker-buildx-plugin": 0,
    "docker-ce-rootless-extras": 29,
}
REQUIRED = {"docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"}
VERSION = re.compile(r"(?P<epoch>[0-9]+:)?(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)(?:[-+~.][A-Za-z0-9.+~:-]+)?\Z")


def family(package, version):
    if package not in PACKAGES or not isinstance(version, str):
        raise ValueError("Unknown package or invalid version")
    match = VERSION.fullmatch(version)
    if not match or int(match["major"]) != PACKAGES[package] or re.search(r"[.~+-](?:rc|alpha|beta)[0-9]", version, re.I):
        raise ValueError(f"{package}: version is outside the observed approved major")
    prefix = (match["epoch"] or "") + match["major"] + "."
    # A zero-major Buildx minor can introduce breaking changes; retain its minor.
    if int(match["major"]) == 0:
        prefix += match["minor"] + "."
    return prefix + "*"


def render(versions):
    if not isinstance(versions, dict) or not REQUIRED <= versions.keys():
        raise ValueError("Supply the full installed versions of the four required Docker packages")
    if versions.keys() - PACKAGES.keys():
        raise ValueError("Unexpected package in inventory")
    preferences = "# Generated proposal: retain the recorded Docker package families.\n"
    for package, version in sorted(versions.items()):
        preferences += f"\nPackage: {package}\nPin: version {family(package, version)}\nPin-Priority: 500\n"
    # Specific allowed-family records precede the catch-all rejection records.
    # Priority 500 never requests a downgrade; any major/epoch change needs review.
    preferences += "\nPackage: " + " ".join(PACKAGES) + "\nPin: version *\nPin-Priority: -1\n"
    missing = sorted(PACKAGES.keys() - versions.keys())
    blacklist = "".join(f'    "^{package}$";\n' for package in missing)
    policy = '''// Generated proposal: Ubuntu 24.04 only. Review live origin metadata first.
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Allowed-Origins {
    "Ubuntu:noble";
    "Ubuntu:noble-security";
    "UbuntuESMApps:noble-apps-security";
    "UbuntuESM:noble-infra-security";
    "Docker:noble";
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "now";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Package-Blacklist {
''' + blacklist + "};\n"
    timer = lambda calendar: f"""[Timer]
OnCalendar=
OnCalendar={calendar} America/New_York
RandomizedDelaySec=0
AccuracySec=1min
Persistent=false
"""
    return {
        "etc/apt/apt.conf.d/99rival-share-maintenance": policy,
        "etc/apt/apt.conf.d/99rival-share-periodic": 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
        "etc/apt/preferences.d/rival-share-docker.pref": preferences,
        "etc/systemd/system/apt-daily.timer.d/rival-share.conf": timer("*-*-* 02:15:00"),
        "etc/systemd/system/apt-daily-upgrade.timer.d/rival-share.conf": timer("Sun *-*-* 03:00:00"),
        "etc/systemd/system/rival-share-security-check.timer": """[Unit]
Description=Check Ubuntu and approved Docker security updates without installing

[Timer]
OnCalendar=*-*-* 02:30:00 America/New_York
RandomizedDelaySec=0
AccuracySec=1min
Persistent=false

[Install]
WantedBy=timers.target
""",
        "etc/systemd/system/rival-share-security-check.service": """[Unit]
Description=Simulate approved unattended upgrades after nightly package discovery
Wants=apt-daily.service
After=apt-daily.service network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/unattended-upgrade --dry-run
TimeoutStartSec=20min
Nice=10
""",
    }


def write_proposal(output, files):
    output.mkdir(parents=True, exist_ok=False)
    for relative, content in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def review_output(path):
    output = path.resolve()
    system_config = Path("/etc").resolve()
    if output == system_config or system_config in output.parents:
        raise ValueError("Render to a local review directory, not /etc")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="JSON object of exact dpkg installed package versions; no secrets")
    parser.add_argument("--output-dir", type=Path, required=True, help="new local review directory; never /etc")
    parser.add_argument("--docker-origin-verified", action="store_true", help="operator has verified signed download.docker.com stable origin Docker/noble")
    args = parser.parse_args()
    if not args.docker_origin_verified:
        parser.error("Inspect signed Docker APT source/origin first; no policy was generated")
    try:
        output = review_output(args.output_dir)
        files = render(json.loads(args.inventory.read_text(encoding="utf-8")))
        write_proposal(output, files)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"Rendered {len(files)} proposal files under {output}; nothing installed or enabled")


if __name__ == "__main__":
    main()
