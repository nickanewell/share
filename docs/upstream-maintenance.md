# Maintaining the Cryptgeon fork

This fork follows stable Cryptgeon v2 releases while retaining Rival IT branding
and reviewed local fixes. It does not automatically deploy or publish packages.

## What the proposed updater does

`.github/workflows/upstream-update.yml` is opt-in. Its scheduled jobs are skipped
unless the repository variable `ENABLE_UPSTREAM_UPDATES` equals `true`. A manual
run can explicitly opt in with `propose: true`. The checked-in configuration is
`.upstream-sync.json`; the initial baseline is v2.9.3 at
`40f35595337a6008afd41cd834b8eb4e8644f956`.

Once enabled, the workflow checks published releases from
`cupcakearmy/cryptgeon` on Monday mornings UTC. It ignores drafts, prereleases and
non-semantic tags. It selects the highest newer release within configured major
version 2. New major releases are reported for a separate migration review.

For an eligible release it creates a **new branch and draft PR**, carrying the
upstream delta from the recorded stable baseline using `git apply --3way`.
This preserves fork-only changes instead of resetting the fork to upstream.
The recorded upstream commit is checked so a moved baseline tag stops the run.

- Upstream changes to protected branding files stop the run before application.
  Update `protected_paths` if approved logo assets move. This list includes the
  existing logo/favicon/title/header/theme/about/layout files and the future
  `packages/frontend/static/branding` directory.
- Conflicts with local fixes stop the run without committing or pushing. Resolve
  the relevant upstream release manually, retain the fixes, test, and update the
  baseline tag/commit in `.upstream-sync.json` after integration.
- Upstream `.github` changes are excluded. Review those separately so CI updates
  are considered without restoring upstream publishing targets or removing the
  opt-in guard. The PR body lists excluded workflow paths.
- Existing proposal branches are never rewritten. A create-only Git lease also
  rejects a racing branch creation between the existence check and push. Review or
  remove an abandoned branch manually. If a push succeeded but PR creation failed,
  inspect that branch and create its PR manually; the next run leaves it alone.
- No upstream build scripts run in the privileged proposal job. Build and test
  execution belongs in the read-only PR CI job, with no registry/deploy secrets.

The helper itself never pushes, creates PRs or deploys. A local discovery-only
check is:

```sh
python3 scripts/upstream_update.py discover
python3 scripts/test_upstream_update.py
```

The `prepare` command changes the local checkout and makes a local commit. Run it
only in a disposable, clean clone based on the intended fork default branch:

```sh
python3 scripts/upstream_update.py prepare --tag v2.X.Y --body-file /tmp/update-pr.md
```

## Activation requires a separate approved GitHub change

No activation is performed by adding these files locally. After reviewing and
merging the maintenance branch:

1. Confirm the fork's publishing workflow is disabled and no workflow publishes
   to the upstream `cryptgeon` npm package or `cupcakearmy/cryptgeon` image.
2. Enable Actions for this fork if needed. Allow GitHub Actions to create pull
   requests in repository settings. The updater uses only the short-lived
   `GITHUB_TOKEN`; do not add a PAT, App key or deployment credential.
3. Set `ENABLE_UPSTREAM_UPDATES=true`, or use a manual run with `propose=true` for
   a one-time proposal. The workflow is restricted to `nickanewell/share`; if the
   repository is renamed, review that guard deliberately.
4. Protect the default branch: require human review and the Test workflow's checks.
   This workflow neither configures branch protection nor auto-merges.
5. When an update PR appears, approve workflows to run if GitHub shows that prompt.
   Verify checks on the exact PR head, including build, type checks and browser
   integration tests. A draft PR alone is not evidence those checks passed.
6. Review the diff, configuration and data compatibility, then merge only after
   successful checks. Deployment remains a separate human-reviewed operation using
   the fork's own image/build, not the upstream image that omits Rival IT branding.

Discovery has `contents: read`. Only the proposal job has `contents: write` and
`pull-requests: write`; no `actions: write`, package, environment or identity-token
permissions are requested. According to current GitHub documentation,
`GITHUB_TOKEN`-opened/updated PRs create PR workflow runs in an approval-required
state. No credential expansion is needed for that review step. If repository or
organization policy blocks those workflows, stop and resolve the policy through
the normal administrator review instead of bypassing it with a personal token.

Disable future scheduled proposals by removing/setting the repository variable to
`false`. The workflow does not change the live app in either state.

## Maintenance outside upstream syncing

Stable upstream updates do not guarantee that all security findings are fixed.
This fork now carries approved [security backports](security-hardening.md), with
legacy-file reading and authenticated new files. Preserve them during updates;
the upstream version number alone does not attest equivalent behavior.
Cryptgeon v2.9.3 retains the reviewed unbounded per-note lock map, CLI filename
traversal and plaintext file metadata. Keep any local fixes until an upstream
release is verified to replace them safely. The v3 prerelease changes the codec
and API and does not migrate v2 notes, so it is not an automatic patch upgrade.

Runtime/container patches, dependency advisories, lockfile refreshes, GitHub action
pins, proxy headers, deployment settings and image scanning require separate
maintenance. Independently review Node/Rust/Alpine support and JS/Rust advisories;
the updater does not auto-refresh them. Preserve the existing Redis/Valkey data and
configuration decisions during deployment review and identify the deployed image
digest plus source commit for reproducibility.

Official references:

- [Cryptgeon releases](https://github.com/cupcakearmy/cryptgeon/releases)
- [GitHub release API](https://docs.github.com/en/rest/releases/releases#list-releases)
- [Workflow triggering and approval behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow)
- [GitHub token permissions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication)
