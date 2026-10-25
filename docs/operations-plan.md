# Proposed low-maintenance operations plan

**For review only. Nothing below has been enabled or deployed.** Keep the existing
Ubuntu VM and Docker Compose; this service does not need an orchestrator cluster.
Preserve the public URL, branded image, one active production app process and
one-time password-sharing workflow.

## Observed foundation

Read-only console checks found Ubuntu 24.04.5 LTS, Docker Engine Community 29.3.0,
Compose 5.1.0, about 8 GiB RAM and no swap. Unattended upgrades and both APT timers
are enabled; the reboot-required flag dates from October 13. Successful package
updates, allowed origins and automatic reboot policy have not been verified.

Production is a locally built app 2.9.1 on Alpine 3.19.9 plus Redis 7.4.5, with
unlimited container/cache memory, disabled Redis save/AOF, and an anonymous disk
volume at `/data`. Cloudflared is active; app port 8000 is bound to all VM
interfaces, Redis has no published port. Exact tunnel routing/firewall and
rollback backups remain unverified. The untracked Compose `.yml` overrides `.yaml`.

## First controlled maintenance cycle

1. Review the live Compose override/config, image identity and ingress route.
   Preserve the existing cache while replacing only the app; do not blindly
   switch it to the repository's Valkey template. Rehearse on a separate staging
   cache containing synthetic data. Record the old/new image digests and commits.
2. Deploy the tested security branch with the file-compatibility procedure in
   [security-hardening.md](security-hardening.md). Old text/legacy shares remain
   readable. New files require the new reader; the new backend protects one-view
   files from older readers with HTTP 426 before consumption.
3. Patch the actual Redis 7.4.5 instance to tested **7.4.11**, or a newer verified
   patched 7.4 release. The [official 7.4 release notes](https://raw.githubusercontent.com/redis/redis/7.4/00-RELEASENOTES)
   include several security fixes; critical CVE-2025-49844 was first fixed in
   7.4.6. Switching to Valkey is a separate migration decision. Cache restarts lose
   volatile shares and need an explicitly accepted continuity plan.
4. Update/rehearse Docker within the approved supported version family. Docker
   [29.9.2 release notes](https://docs.docker.com/engine/release-notes/29/)
   list newer security fixes than the observed 29.3.0. Upgrade cloudflared through
   its actual package/container installation method; its service being active
   does not establish its version or update policy.
5. Set tested RAM budgets and request limits. With about 8 GiB total, a starting
   staging experiment could use a 512 MiB Redis maxmemory budget, a larger Redis
   container ceiling for overhead, and a 1 GiB app ceiling. These are proposed
   starting points, not production sizing guarantees. Test file concurrency,
   eviction behavior and office NAT clients before activation. Keep Redis private;
   consider localhost-only app binding after confirming tunnel origin routing.

## Automation defaults

| Layer | Proposed policy |
| --- | --- |
| Ubuntu | Security-origin updates daily in an agreed quiet installation window; controlled required reboots, followed by app/cache/tunnel checks and alerts. Keep release upgrades manual. |
| Docker packages | Use Docker's signed APT repository; explicitly allow the approved origin/version family after staging. Engine, CLI, containerd and Compose are host packages, not container images. |
| App/base images | Stable upstream/dependency detection → proposal → security/type/build/Linux/container tests → branded image build/scan → isolated staging → immutable-digest promotion. Start with human promotion; permit narrow routine auto-promotion only after successful rehearsals. |
| Redis/Valkey | Independently scheduled, tested stateful maintenance. Do not replace a floating `latest` image blindly. Separate urgent Redis patching from engine-family migration. |
| Cloudflared | Maintain through its installation method and verify external reachability after restart. |

Ubuntu 24.04+ package updates can restart services through needrestart **during
installation**, before any reboot. Schedule installation as well as rebooting.
[Ubuntu automatic-update guidance](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)
Docker's stable repository does not itself prevent a major upgrade; version-family
policy must be deliberate. [Docker Ubuntu package guidance](https://docs.docker.com/engine/install/ubuntu/)

Engine updates do not refresh containers. Pinned image digests need periodic
refresh/rebuild/recreation; reproducibility and updates must both be handled.
[Docker build guidance](https://docs.docker.com/build/building/best-practices/)
Live restore may help supported daemon patch updates, but is not a guarantee for
minor/major upgrades, host reboots or cache replacement.
[Live-restore limits](https://docs.docker.com/engine/daemon/live-restore/)

The updater already prepared in this branch is opt-in and creates draft PRs; it
does not deploy. A future deploy controller should retain the last good compatible
digest, stop/replace only the single app against the production cache, check local
backend/cache health and public tunnel reachability, and explicitly restore the
previous compatible digest on failure. Compose health waiting alone is not
automatic rollback. Do not run old/new app replicas concurrently against the same
production cache until atomic multi-process note consumption is designed.

## Recovery, visibility and least privilege

- Back up encrypted configuration, Compose definitions, recovery credentials and
  image/digest manifests off the VM; test rebuilding the service. Keep secrets
  outside Git/images and restrict backup access. Do not silently back up note
  payloads or enable persistence: RAM-only retention is a separate privacy choice.
  Review Hyper-V saved state/snapshots because they may retain VM memory.
- Alert on failed updates, prolonged pending reboots, low disk/RAM, OOM/restarts,
  app/cache health, tunnel outage and rollback failures. Use health/status metrics;
  avoid logging passwords, note contents or keys. Choose the owner/alert destination
  before enabling notifications.
- Run app containers as a non-root user where tested, drop unnecessary capabilities,
  avoid privileged mode/host mounts, and keep Docker administration confined to a
  narrowly controlled host service. Use read-only test CI credentials; never give
  untrusted PR jobs production secrets or a Docker socket.
- Keep production config distinct from source/build contexts. Use a Nick-owned
  image destination; record source commit, tests and image digest. A small on-VM
  controller can pull a reviewed digest without exposing an unauthenticated Docker
  API or granting broad inbound CI access. Any credential/permission setup needs
  separate approval.

## Decisions needed before activation

Approve: the first deployment/cache patch; installation/reboot window and timezone;
whether cache/VM maintenance may invalidate outstanding shares; Redis patch versus
later Valkey migration; memory/request budgets; image registry and narrowly scoped
deployment identity; backup retention/restore drill and alert destination; and the
exact update classes allowed automatic promotion. Initially keep Ubuntu release,
Docker major, cache-engine, encryption/retention and upstream major changes manual.

Cache/VM reboots lose unopened RAM-only shares. Retaining those shares across
reboots requires an explicit change to the original retention design.

Cloudflare maintenance reference:
[update cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/update-cloudflared/).
