# Local security backports and rollout review

These changes follow the approved security review on 2026-10-24. They are local
backports on Cryptgeon 2.9.3, not claims about an upstream release or a deployed
fix. No production service has been changed.

## Fixes

### Bounded note locking

`packages/backend/src/lock.rs` replaces the unbounded per-ID HashMap with 1,024
mutex shards, randomized per shared state. Arbitrary missing-note IDs no longer
retain owned IDs/locks. Same-note requests and shard collisions serialize through
the complete existing Redis read/decrement/delete operation. Unrelated shards can
make progress. This avoids unsafe lock removal while other requests are waiting.

Locks remain per application process. Multiple application replicas still need a
separate atomic Redis consumption design before claiming exact global view counts.
This change does not bound Redis note storage, request throughput or container RAM.

### Confined CLI downloads

`packages/cli/src/utils/download-files.ts` validates the complete selection before
writing. Only portable basenames are allowed: traversal, separators, absolute
paths, Windows drive/ADS/device names, control characters and ambiguous dot/space
endings are rejected with an error. The browser can still display legacy names.

The CLI captures its download directory before asynchronous work. Synchronous,
relative filesystem operations are anchored to the kernel's current directory,
checking its device/inode before opening each file. Atomic exclusive creation
(`wx`, mode 0600) rejects existing files and live/dangling symlinks. Collisions use
numbered suffixes, preserving extensions. Duplicate selections use indices.
Failed writes close descriptors and remove only the newly created inode.

The directory must be trusted. This is not a sandbox against hostile code already
running inside the CLI process or another local actor controlling the directory.
Whole-bundle publication is not atomic; a later disk error may leave earlier
successfully downloaded files. Existing files are never intentionally overwritten.

### Authenticated file metadata

New file shares encrypt one complete manifest and raw-byte bundle, binding names,
MIME types, actual byte lengths, ordering and contents with AES-GCM. The outer
object has exactly `format: "cryptgeon-files"`, `version: 2`, and `ciphertext`.

The AES key is domain-separated from the original note key using standard
HKDF-SHA256: salt UTF-8 `cryptgeon-files`, info UTF-8 `cryptgeon-files/v2`, output
256 bits. This prevents a hostile server from wrapping a new ciphertext in an
old file array and successfully decrypting it under the legacy raw key.

The authenticated plaintext is a four-byte big-endian manifest length, UTF-8 JSON
manifest, then concatenated file bytes. The manifest repeats the format/version
and lists each name/type/actual size. No nested Base64 means roughly the same
single-Base64 overhead as the old codec. Exact schemas, canonical AES framing and
Base64, IV/tag lengths, UTF-8, safe sizes and complete byte partitioning are checked.
Frame/manifest limits are 512 MiB/16 MiB, independently of the server request cap.

New versioned objects never fall back to legacy after a validation/authentication
failure. The reader still accepts historical encrypted file arrays and old
16/24/32-byte AES keys. It recomputes actual lengths and returns
`metadataAuthenticated: false`; the browser and CLI visibly warn that filenames
and types are unverified. Old metadata cannot become authenticated retroactively.
The public array-returning `decrypt()` remains available; callers needing the
security status should use `decryptWithInfo()`.

The backend advertises `file_format_version: 2`. Updated browser/CLI file uploads
refuse servers lacking that capability, before creating a share. This avoids
accidentally sending new files to an older bundled reader. It is compatibility
negotiation, not attestation of a server's code. Existing text/password link
formats, public URL and backend opaque note storage are unchanged.

The updated backend also requires a single `X-Cryptgeon-File-Format: 2` read
capability for v2 envelopes. It returns HTTP 426 **before consuming any views** to
older/ambiguous readers; old text and legacy file reads still work without it.
This preserves a new one-view file when an old browser/CLI tries to open it.
Object-shaped parse failures are conservatively preserved too, including
duplicate JSON fields that JavaScript accepts using their last values.

Ciphertext length, note kind and password-derivation parameters remain visible.
As with the existing web app, encryption cannot protect against a server that
serves malicious JavaScript to the browser.

## Continuity and rollback before any external rollout

1. Preserve the existing public URL and password-sharing client workflow. Existing
   text links continue to work in both directions; no forced reset or migration.
2. Upgrade/refresh receiving browser tabs and CLI clients before sharing new v2
   files. **Old readers cannot open v2 files.** The updated backend refuses their
   consume request without decrementing views. Old upstream 2.x CLI packages do
   not contain these fork backports. There is no silent downgrade to
   unauthenticated new file writes.
3. Keep the existing cache service and its volatile state during an app-only
   rollout. Do not blindly apply the repository's Valkey template to a running
   Redis deployment or use Compose down/volume removal as an update procedure.
   View-limited notes can lack a time expiry; waiting six hours does not guarantee
   every old note has drained. No live note inventory/content was inspected.
4. Identify/review the actual live Compose file, overrides, environment settings,
   image ID and source commit before building/deploying. The VM inspection found
   a `.yml` override taking precedence over the tracked `.yaml`; a source update
   alone does not establish what runs. Preserve a reviewed rollback image/config.
5. Once v2 files exist, an old pre-v2 frontend/backend is not a compatible rollback.
   Retain the new reader in the rollback build, or explicitly coordinate expiry,
   consumption/resending and client communication. An old backend lacks the
   non-consumption capability guard. A destructive cache restart
   loses volatile shares; changing persistence would require a separate privacy
   and operational decision.
6. Confirm ingress/origin routing and TLS, health, headers and single-replica
   topology. Keep publication, workflow activation and deployment separate and
   approved. No remote merge/push or deployment was performed here.

## Verified server follow-ups, not performed

Read-only VM/container inspection confirmed app 2.9.1 on **Alpine 3.19.9** and
**Redis 7.4.5**. Alpine's normal 3.19 support has ended. Redis 7.4.5 matches
[CVE-2025-49844](https://github.com/redis/redis/security/advisories/GHSA-4789-qfc9-5f9q),
which permits RCE for a client with Redis access/Lua permission. Its first 7.4 fix
is 7.4.6; [current official 7.4 release notes](https://raw.githubusercontent.com/redis/redis/7.4/00-RELEASENOTES)
list **7.4.11**, with additional security fixes. Plan a patched Redis update or
deliberate Valkey migration separately. Redis had no published host port; no public
reachability, exploitation or compromise was established.

Both containers had no Docker memory limit; Redis had `maxmemory=0` and
`noeviction`. Agree and test cache/container memory budgets and eviction policy.
Redis `save` was empty and AOF disabled, but its `/data` used an anonymous disk
volume rather than tmpfs. Do not equate disabled normal persistence with proof
that no data could ever reach disk. Review swap, snapshots/crash dumps and storage
policy without silently changing them. Exact ingress/TLS routing and usable
rollback/snapshots remain unverified; cloudflared was active.

## Validation

- Build and frontend type check pass (zero type errors/warnings).
- **32 JavaScript security tests**: 14 CLI confinement/race/failure tests and 18
  codec tests, including independent WebCrypto fixtures, 20 randomized rounds,
  wrong keys, tampering, key-domain downgrade attempts, malformed authenticated
  frames, padding bits, allocation bounds, legacy keys/files and Node fallback.
- **9 Rust tests**: 100,000 unique IDs with bounded storage, repeated same-note
  contention across clones, colliding IDs, and unrelated-shard progress.
  Reader capability tests cover missing/duplicate/unknown headers, equivalent
  JSON header encodings, legacy reads and a borrowed 10 MiB ciphertext field.
- **18 Chromium cases**, **4 actual encrypted CLI/API round trips**, and **1,205
  loopback API requests** pass. Covers real PNG/PDF/1 MiB binary bytes, legacy
  warning, tamper rejection, capability guards, unchanged text, one-minute expiry,
  server body limits and exact view counts under concurrent consumers.
- After the non-consumption safeguard, all **9 tracked browser security cases**,
  four CLI round trips and 1,205 loopback API requests passed again. The portable
  cases are committed under `test/web/file/security.spec.js` for future CI.
  A final focused rerun also passed canonical/duplicate format/duplicate version
  envelopes against five missing/invalid reader capabilities each, followed by
  successful updated-reader downloads.
- Seven updater safety tests still pass. The read-only PR CI now runs the security
  suite; the updater's three-way merge must retain these backports or stop on
  conflicts. A future upstream version is not proof that these fixes are obsolete.

Tests used isolated native macOS Node 24/Rust 1.99.1, Chromium and RAM-only Valkey.
Test services were stopped afterward. No production note reads/writes or exploit
tests occurred. Docker/Linux execution, Firefox/WebKit, Windows filesystem behavior
and multiple app processes remain untested. Existing ESM-entry/peer-range issues
and dependency low-severity notices from the first maintenance review remain.

Crypto references: [WebCrypto HKDF](https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams),
[Node 18 WebCrypto](https://github.com/nodejs/node/blob/v18.x/doc/api/webcrypto.md).
