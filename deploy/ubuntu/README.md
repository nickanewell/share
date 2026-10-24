# Ubuntu maintenance policy proposal

These files **render a local proposal only**. Nothing installs a package, writes
to `/etc`, changes permissions, enables a timer, restarts a service or reboots the
VM. The live package inventory and signed APT source still need inspection.

The approved direction is nightly security checks and a Sunday **03:00
America/New_York** maintenance window, accepting interruption and loss of
temporary shares. The concrete settings below need review before activation.

## Exact host policy

- Refresh package indexes nightly at **02:15 Eastern** using `apt-daily.timer`.
- Simulate eligible updates nightly at **02:30 Eastern**; this check installs
  nothing. APT indexes and ordinary update logs are written locally.
- Install allowed updates on **Sunday at 03:00 Eastern** using Ubuntu's existing
  `apt-daily-upgrade.service` and `unattended-upgrades`.
- Permit Ubuntu Noble release/security pockets and existing ESM security pockets;
  permit Docker's verified signed Noble stable origin. Keep Ubuntu release
  upgrades and proposed/backports/general Ubuntu updates outside this policy.
- Constrain Docker Engine/CLI to major **29**, containerd to major **2**, and
  Compose to major **5**. For an installed zero-major Buildx, retain its current
  minor. Preserve the installed Debian epoch. Unknown optional Docker packages
  are blocked until inventoried. A dependency requiring another family stops
  that update rather than silently crossing the boundary.
- Reboot **after the Sunday upgrade run completes, if Ubuntu requests it**,
  including when users are logged in. This is not an exact 03:00 reboot promise.
  Needrestart may restart affected services during package installation.
  The automatic-reboot setting applies to any unattended-upgrades invocation:
  an operator manually installing with it outside Sunday could also reboot.
  Inspect other callers before activation; the timer is the window control.
- Do not automatically remove packages or unused kernels. Do not change the VM's
  timezone: explicit IANA timer zones track Eastern daylight saving time.
- Disable randomized timer delay and missed-run catch-up for these timers, so
  booting a previously stopped VM does not unexpectedly start a missed maintenance
  installation. A VM unavailable during the window needs an operator follow-up.

This host policy does **not** update container images, app source or Cloudflared.
The installed Cloudflared source/version remains unknown and needs its own
approved package policy. Docker installation alone does not refresh containers.

## Inventory and render

Read installed versions without exposing environment values or tunnel tokens:

```sh
dpkg-query -W -f='${binary:Package} ${Version}\n' \
  docker-ce docker-ce-cli containerd.io docker-compose-plugin \
  docker-buildx-plugin docker-ce-rootless-extras
apt-cache policy docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin
```

Confirm the installed source is the signed official
`https://download.docker.com/linux/ubuntu` Noble stable repository, and its signed
Release metadata actually identifies origin `Docker`/archive `noble`. Do not add a
new trust key, repository, allow unauthenticated packages, or substitute a
different source as part of rendering. Capture the exact versions in a JSON
object keyed by package name; omit only packages that are genuinely uninstalled.
The four principal packages are required.

```sh
python3 deploy/ubuntu/render_policy.py /tmp/docker-installed-versions.json \
  --docker-origin-verified --output-dir /tmp/share-maintenance-proposal
python3 deploy/ubuntu/test_policy.py
```

Render to a fresh local directory. The program refuses `/etc` and refuses to
replace an existing proposal directory. Inventory strings cannot inject APT
configuration. The sample versions used by tests are fixtures, not deployment
evidence.

## Before enabling

1. Review `apt-config dump`, existing preferences, timer drop-ins and APT/dpkg
   health. Preserve existing configuration/drop-ins and the live untracked
   `/home/rival/share/docker-compose.yml` in a restricted rollback directory.
   Never print secrets. Keep the current app/cache images and old Compose;
   do not run image/volume/system prune or delete backups.
2. Review the generated diff. Installing these root-owned files and enabling
   `rival-share-security-check.timer` are persistent security-sensitive changes:
   obtain the required action-specific approval. This renderer grants no access
   and needs no token, deploy key or new sudo rule.
3. Validate on Ubuntu before activation: `apt-config dump`, `apt-cache policy`
   for each Docker package, `unattended-upgrade --dry-run --debug`,
   `systemd-analyze verify` on the new service/timer, and
   `systemd-analyze calendar 'Sun *-*-* 03:00:00 America/New_York'`. Check dates
   across daylight saving changes. Confirm only approved origins/families appear
   and no removal/downgrade is proposed. These APT checks need live sources; they
   have **not** run on the Mac.
4. After installation, daemon-reload and restart the two existing APT timers;
   enable/start only the new check timer. Inspect `systemctl list-timers`,
   `apt-daily-upgrade` and unattended-upgrades logs. Check for other cron/timer
   callers that could install outside the window. Do not disable APT signature
   verification, AppArmor, TLS validation or firewall rules.
5. Verify Docker, the single app, Redis and Cloudflared recover after the first
   agreed maintenance/reboot. Both local and public `/api/live` must return 200;
   this endpoint checks cache reachability without reading a note.

Reverting this policy means restoring the preserved APT configuration/preferences
and timer drop-ins, disabling only the newly introduced check timer, then
daemon-reload/restarting the APT timers. It does not downgrade already installed
packages. Host package rollback needs its own tested recovery plan.

## App/cache promotion and monitoring boundaries

Keep upstream sync as stable v2 release → draft PR → CI. Publish/review the branded
image, run Linux/Docker and compatibility tests on an isolated cache, then promote
an immutable reviewed image identity. Retain the last good **new-format-compatible**
reader/backend; rolling back to stock 2.9.1 after v2 file creation removes the
older-reader consumption guard. Exclude v3/protocol/retention changes from routine
automatic promotion.

For Redis, independently track the official **7.4** security line, initially patch
the observed 7.4.5 to tested 7.4.11 (or a newer verified 7.4 patch). Before each
promotion, record the old/new image digest, stage a RAM-only private cache, verify
version/PING plus synthetic app round trips, and replace only that Compose
service with explicit health/rollback checks. Keep its existing configuration;
do not silently migrate to Valkey, add persistence, or expose port 6379. No
floating `latest`/blind image replacement controller is included here.

Unattended-upgrades and systemd journal supply **local logs**, not an external
alert. Select Nick's existing RMM/monitoring destination and approve its exact
integration before claiming notifications are active. Monitor update failures,
pending reboot age, app/cache/tunnel health, disk/RAM and container OOM/restarts.
Back up encrypted deployment configuration and recovery material off the VM and
test a restore; do not silently back up transient note payloads.

## Official references

- [Ubuntu automatic updates and service/reboot behavior](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)
- [Ubuntu unattended-upgrade dry-run](https://manpages.ubuntu.com/manpages/noble/man8/unattended-upgrade.8.html)
- [APT preference ordering and downgrade rules](https://manpages.ubuntu.com/manpages/noble/man5/apt_preferences.5.html)
- [systemd IANA calendar zones](https://www.freedesktop.org/software/systemd/man/latest/systemd.time.html)
- [systemd timers and missed-run policy](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html)
- [Official Docker Ubuntu package source/upgrades](https://docs.docker.com/engine/install/ubuntu/)
- [Redis 7.4 release notes](https://raw.githubusercontent.com/redis/redis/7.4/00-RELEASENOTES)
