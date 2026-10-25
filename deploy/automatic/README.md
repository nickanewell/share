# Automatic stable app updates: implementation awaiting activation review

These are local implementation files, not an installed or enabled updater.
Production currently runs the tested branded Cryptgeon 2.9.3 build from bf589781.
The previous draft-PR-only workflow remains inactive and is insufficient for
unattended deployment. No persistent credential is required by this design.

## Smallest deployment path

1. A scheduled workflow loaded from the reviewed `main` branch discovers published
   stable releases of `cupcakearmy/cryptgeon`. Accept newer major-2 releases only;
   resolve and record the exact upstream commit. A moved baseline tag, downgrade,
   unexpected repository, prerelease or unsupported major stops the update.
2. Prepare the upstream delta in a disposable checkout using the trusted updater
   from `main`, not scripts from the candidate. Preserve the fork's security
   patches by three-way application. Never force-resolve conflicts. Exclude
   upstream workflows, deployment/updater policy, regression contracts and local
   branding assets. Overlay the approved assets from the reviewed fork and check
   their hashes. Branding integration code must merge cleanly; copying an entire
   old layout over a changed upstream layout could discard a security fix.
3. On ephemeral GitHub-hosted runners, build and test candidate code in isolated
   containers without publishing credentials, server configuration, VM access or
   a mounted host Docker socket. Use the reviewed build recipe and regression
   harness. Run JS/Rust security units, frontend checks/build, browser tests and
   independent legacy/new text/file, capability and one-view compatibility checks.
   Candidate code must not be able to replace the checks that authorize release.
4. A separate publisher job, which does not execute candidate scripts, publishes
   the exact tested image to `ghcr.io/nickanewell/share`. Record source on the
   dedicated `automation/release-v2` branch with a guarded fast-forward update;
   never overwrite an unexpected remote branch. Keep `main` as the reviewed
   control plane rather than bypassing its review rules. Record fork/upstream
   commits, image digest, overlay identity and successful gate results. Generate
   GitHub build provenance for the published digest.
5. A root-owned Ubuntu timer makes outbound-only reads and anonymous public-image
   pulls. Treat a candidate tag as a discovery hint, resolve its immutable digest,
   verify provenance against this repository's exact publisher workflow/ref, and
   validate the release identity and monotonic version. Fail closed if provenance
   cannot be verified without unexpected credentials; never substitute a PAT.
6. Stage the exact image against a separate private RAM-only cache, preserving
   production-equivalent limits. Pass health and independent synthetic encrypted
   share checks and verify branding. Preserve the previous compatible image and
   raw private Compose configuration, then change only the app image by digest
   and recreate only `share-app`. Verify local/public health and sharing afterward.
   On failure, restore the previous new-format-compatible image/config and stop.
   Do not repeatedly retry a failed release or modify the live cache/tunnel.

Attestation proves the publisher's identity, not that arbitrary upstream software
is harmless. Upstream build/install scripts are trusted only inside the isolated
candidate job; they never receive privileged publisher or deployment authority.

## Approval and access boundary

The implementation and first controlled promotion must pass before enabling a
timer or schedule. Approval must name these changes explicitly:

- Publish the prepared code and review/merge the trusted automation into `main`.
- Permit only the publisher job's ephemeral `GITHUB_TOKEN` permissions:
  `contents: write` for the dedicated release-source branch, `packages: write`
  for `ghcr.io/nickanewell/share`, and `id-token: write` plus
  `attestations: write` for provenance. Other jobs remain read-only/no secrets.
  No workflow-write, administrator, SSH, environment-secret or personal-token
  permission is needed. Keep repository defaults restricted.
- Make that image package public and link it to `nickanewell/share`; builds must
  contain only public source/assets, never the production Compose/environment.
  Public visibility enables anonymous VM pulls. Inspect existing package access
  and repository rules first; do not assume their current settings.
- Install the reviewed provenance verifier and root-owned controller/policy,
  create its protected state/backup directories and enable its systemd timer.
  Access to the Docker daemon is root-equivalent. Grant it to this fixed service,
  not a new remotely accessible user or a container with the Docker socket.
- Approve its schedule and app-only restart/rollback authority. No inbound SSH,
  Cloudflare API token, registry login or persistent GitHub credential is needed.

Suggested cadence: nightly discovery/build; automatic promotion in an agreed
window, skipping Sunday 03:00 Eastern while the Windows host reboots. Moving guest
OS maintenance to Saturday 03:00 America/New_York avoids that known overlap.
Serialize guest package/image work and defer a needed guest reboot until its
maintenance run finishes; verify recovery after boot. Host reboot duration and
Hyper-V guest shutdown/start behavior remain unverified.

## What is automatic, and what stops

Compatible same-major stable releases can go through this path without a PR
approval or deployment click once activation is specifically approved. Major v3,
protocol/schema migrations, conflicts, changed protected control code, failed
security/branding/compatibility checks, unverified provenance, an unexpected
remote head or failed health gate keep the last working app and require review.
The custom file format remains version 2 and its old-reader non-consumption guard
must survive both promotion and rollback. Run one active production backend.

This does not promise that upstream will keep releasing v2 patches or that an
update is vulnerability-free. Runtime/dependency/toolchain security refreshes and
Redis/Cloudflared updates need their own policies. Notifications need an approved
monitoring destination; local logs alone are not an external alert.

## Implemented components

| File | Responsibility |
| --- | --- |
| `discover_release.py` | Bounded, read-only release discovery, exact Git tag identity and duplicate-publication prevention |
| `prepare_release.py` | Fresh source preparation, three-way upstream application, pinned security/control files, verified artwork, standalone Git bundle |
| `brand_overlay.py`, `brand-manifest.json` | Restore exactly five approved artwork files; reject tampering, path escapes and symlinks |
| `gate.py`, `gate-browser.Dockerfile`, `gate.config.cjs` | Isolated Docker build, maintained unit/type/browser contracts, exact image identity and owned-resource cleanup |
| `publish_release.py` | Context-gated ephemeral publication, source fast-forward lease, signed-manifest validation, complete-assets-before-public release |
| `provenance.py` | Real GitHub CLI Sigstore verification plus repository ID, main workflow/ref/control SHA and manifest-digest checks |
| `controller.py` | Bounded public discovery/downloads; validates installed code ownership before imports under Python `-I` |
| `promote.py` | Protected configuration, private candidate cache/probe, image-only promotion, bounded health checks, compatible rollback and failure quarantine |
| `rival-share-update.service`, `.timer` | Inactive root-service/timer templates; app window Saturday 05:00 Eastern |

The workflow is `.github/workflows/automatic-release.yml`. Its schedule runs
nightly at **06:23 UTC**. All scheduled work is skipped until repository variable
`ENABLE_AUTOMATIC_RELEASES=true`. A manual `validate_current=true` run builds/tests
the current reviewed source and validates the real Docker-save archive even if no
new upstream release exists. This path cannot publish, even when `publish=true`
is also selected. A same-repository pull request touching the updater also runs
this read-only Linux validation before merge; it cannot reach the publisher.
Manual dispatch becomes available once the workflow is on the default branch.
A normal manual default `publish=false` run prepares/tests a
newly available release without registry, source-branch or release publication. Publishing also
requires the variable plus an explicit `publish=true` manual run or a scheduled
run. Only the final publisher job receives write/signing authority.

Critical security implementation and wiring files are pinned byte-for-byte.
Upstream changes to those files stop automation even if a textual merge could
succeed. This conservative boundary protects the fork's bounded locks, confined
CLI writes, authenticated file codec, upload capability guard and legacy-reader
non-consumption gate. Updating that maintained contract requires code review and
a newly approved control SHA/contract hash on the VM.

The publisher exposes stable `rival-auto-v2.X.Y` releases with exactly
`release.json`, `release.sigstore.jsonl` and `source.bundle`. GitHub's attestation
signs the manifest binding the tested image digest and source identities. A
partial draft, remote-head race, failed signature or ambiguous archive stops
without deleting or replacing prior remote material. Public tags are discovery
hints; they never authorize deployment themselves.

## Local verification and actual limits

Run the offline suite from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/automatic -p 'test_*.py' -v
```

The tests use disposable Git repositories, mocked Docker/HTTP/CLI boundaries and
the fixed Node probe with mock HTTP plus real AES-GCM/HKDF. They do not create
tokens, contact production, publish, install a service or change host settings.
The integrated suite passed **117 tests in 276.894 seconds**. Workflow syntax was
checked with official checksum-verified `actionlint` 1.7.12, including the separate
non-publishing current-source validation path added afterward.
After the final anonymous-Docker configuration guard, all **25 promoter tests**
passed again. Its private configuration contains only an empty `ghcr.io` auth
entry to prevent automatic saved-helper discovery; foreign configuration stops
execution before Docker and is never overwritten.

The first non-publishing GitHub/Linux run passed **119 updater tests** and all six
container gates, including **93 browser tests with 6 existing skips**. Its final
archive check stopped on Docker's OCI export format. The importer now validates
one platform-pinned OCI image as well as a classic Docker-save image, checking
the manifest/config/layer identities without extracting paths onto the host.
Multi-image indexes and attestation-only objects remain unsupported and fail closed.
Require a successful current-commit Linux run, including its real archive check,
before activation; consult the draft PR checks for the current result.

This Mac has no Docker or `gh`. **GHCR publication/anonymous pulls, a genuine
attestation bundle and the systemd sandbox still need controlled integration
validation.** They are mandatory activation gates and are not established by
the offline tests or container gate alone.
GitHub must also permit the ephemeral token's guarded source-branch push; a denial
stops rather than causing a fallback to a broader PAT.

Before enabling either schedule, run the controlled `validate_current=true`
pipeline path and then a release dry run when a compatible upstream release is
available; inspect their
artifacts, approve a controlled publication, verify the genuine signed manifest
without a saved credential, and validate staging/rollback on Linux with production
promotion disabled. Review all results before enabling unattended promotion.

## Exact VM activation prerequisites

Do not install directly from a candidate checkout. Review/pin the trusted control
commit, then install only `controller.py`, `promote.py` and `provenance.py` under
root-owned, non-group-writable `/usr/local/lib/rival-share-update`. The unit invokes
`/usr/bin/python3 -I`; installed code and every ancestor are checked before local
imports. Review/install the official `/usr/bin/gh` verifier separately.

The current live `/home/rival/share/docker-compose.yml` is user-writable and uses
a local image alias. Activation must explicitly approve migrating the authoritative
configuration to private root-owned **`/etc/rival-share/compose.json`**, with
**`/etc/rival-share/update-policy.json`** and root-private
**`/var/lib/rival-share-update`** state/backups. Preserve the old file and all
existing backups. Normalize settings privately, preserve named volumes/absolute
paths, account for literal dollar escaping, and compare effective configurations
without printing secrets. Pin the old app to its actual running immutable image
ID and verify it matches the compatible reader before enabling rollback. No app
mounts, Redis host ports, extra services or unreviewed Compose includes are accepted.

`host-policy.example.json` is deliberately **disabled and unusable** until its
placeholder control SHA, contract hash and verified numeric repository ID are
replaced. Pin the actual reviewed main commit, approved artwork/contract hashes,
publisher identity, existing URL and the fixed configuration/state paths.

The separate app window is **Saturday 05:00 America/New_York**, after proposed
guest OS work at Saturday 03:00 and before the known Windows-host Sunday 03:00
window. Applying defers before Docker operations if a guest reboot is pending or
APT services are active/transitional/failed. A two-hour gap is not proof that OS
maintenance completed. Unplanned reboots or uncertain command outcomes preserve
pending state for operator inspection rather than blindly retrying or overwriting
another operator's work. No new OS policy or external alert integration is enabled
by these files.
