# Rival IT Share maintenance review — 2026-10-24

This local branch integrates stable Cryptgeon **v2.9.3** into the branded fork,
refreshes compatible dependencies, and prepares review-based upstream updates.
Nothing was pushed, enabled on GitHub, published, or deployed.

## Live deployment observations

The bounded passive check used ordinary HTTPS GETs and the available **Google
Chrome extension browser**. No notes were created, uploaded, read, enumerated or
probed. Requests covered the homepage, its linked JavaScript assets,
`/api/status`, `/api/live`, `/_app/version.json`, the public About page and the
HTTP root redirect.

- `https://share.rivalit.ai/` returned 200 through Cloudflare and rendered Rival IT
  branding. HTTP redirected to HTTPS with 301. `/api/live` returned 200.
- `/api/status` and About reported **2.9.1**. Public configuration exposed a
  10,000,000-byte limit, 25 maximum views, 360-minute maximum expiration, and
  enabled files/advanced settings. Theme overrides were empty.
- The homepage had no observed Content-Security-Policy, Strict-Transport-Security,
  X-Frame-Options, X-Content-Type-Options or Referrer-Policy response headers.
  Review proxy/browser hardening before rollout; absence alone is not proof of
  exploitation. CSP needs testing with Svelte's inline bootstrap.
- Shared asset `/_app/immutable/chunks/C046oX_z.js` exactly matched the reviewed
  original build, SHA-256
  `067df63ab2c0314074cb82b06bfaa56a9340df3686ce394288539cd8f31351c5`.
  This confirms the legacy browser file envelope, including plaintext metadata.
- The live SvelteKit build ID was `1792639847270`; that is not an app semantic
  version. Asset Last-Modified was 2026-10-22, which does not establish deployment
  time or a source revision.

The status version and matching browser asset do **not** attest the backend
commit, Cargo/JavaScript lockfile, image digest, Alpine version, cache version,
replica count, firewall/rate limits, TLS origin configuration or persistence
settings. Obtain those from the deployment operator/image inventory. Public
GitHub showed no deployment or workflow-run records during the review.

## Local changes and migration notes

- Merged upstream v2.9.3 (`40f35595337a6008afd41cd834b8eb4e8644f956`), preserving
  Rival IT title, About content, theme assets and layout. The fork originally had
  one branding commit beyond upstream base `482795dd…`.
- Applied the verified new Canva-rendered Rival IT lockup and symbol. Original
  PNGs are retained under `packages/frontend/static/branding/`. Logo SVG wrappers
  crop only canvas padding and use the source pixels as a luminance mask for
  black/white theme variants; the mark is not redrawn. The favicon is byte-for-byte
  the supplied black-on-white symbol.
- Upstream moves to Node 24, pnpm 11, Rust edition 2024/MSRV 1.95, Axum 0.8,
  Redis client 1.x, TypeScript 6 and Vite 8. Local pins are Node **24.22.1**, pnpm
  **11.5.0**, Rust **1.99.1** and Alpine **3.24.3**. Docker bases/actions are pinned
  to verified digests/commits; Cargo builds use `--locked`.
- Refreshed JavaScript packages within their compatible upstream ranges and
  upgraded the locale-only ZIP dependency to **adm-zip 0.6.1** for its security
  fixes. The one-week upstream dependency release-age policy remains in place.
  Patched Rust lockfile Tokio to **1.54.1** and anyhow to **1.0.104**.
- Fixed two upstream file-preview type errors with an owned ArrayBuffer byte
  copy, preserving byte offsets/lengths. Removed the existing download type-ignore.
- Upstream Compose changes Redis to **Valkey 7**, retaining service name `redis`
  and the `REDIS` connection setting. This has not been applied to production.
  Review the deployed cache/persistence configuration; do not silently replace or
  discard live data. RAM-only deployments can lose existing notes on restart.
- Production Compose now builds this checkout as `rival-it-share:local`;
  it does not substitute the upstream image, which lacks Rival IT branding.
  Deployment remains manual and needs a deliberate image identity/rollback plan.
- Replaced inherited publishing with a manual information-only workflow. No
  registry credentials or publish destinations remain in active workflows.
- Added an **opt-in**, same-major stable upstream draft-PR proposal workflow.
  See [activation, permissions and conflict handling](upstream-maintenance.md).
  It does not merge or deploy. No repository variable/settings were changed.

## Validation

Local toolchains/caches, browser binaries and test services were isolated. Native
tests used macOS arm64, Node 24.22.1, pnpm 11.5.0 and Rust/Cargo 1.99.1.

- `pnpm install --frozen-lockfile --ignore-scripts` passed, followed by compatible
  updates and a final frozen-lockfile consistency check.
- `pnpm --filter @cryptgeon/web exec svelte-kit sync`, `pnpm run build` and
  `pnpm --filter @cryptgeon/web check` passed; final type check: 0 errors/warnings.
- `cargo check --locked` and `cargo test --locked --all-targets` passed with
  temporary target/cache directories. Rust test count: **0**. Clippy before the
  two lockfile patches passed with routine style/unused-CSP warnings.
- **7 updater safety tests** passed: stable selection, input validation,
  branding preservation, workflow exclusion, conflict/dirty-tree stops, and a
  create-only branch lease that rejects racing existing branches. Workflow YAML
  parsed and read-only permission/inert-publishing invariants passed.
- **11 Chromium UI integration cases** passed against only
  `http://127.0.0.1:18080`, plus **4 actual crypto/API roundtrips** with fragment
  keys/passwords, exact byte comparison and one-view deletion. Used actual local
  Rust backend and RAM-only Valkey 7.2.14, with network guards excluding production.
  Generated valid PNG/PDF and a 1 MiB binary supplemented repository fixtures,
  which are Git LFS pointer files in this checkout.
- Validated ArrayBuffer offset/ownership behavior and adm-zip's real locale-script
  API with disposable fixtures. Verified logo/favicon in dark and light pages.
- `pnpm peers check` reports the pre-existing `precompile-intl-runtime 0.8.5`
  peer range for Svelte 3/4 against Svelte 5.57.2. Build, type checks and the
  exercised English UI pass; this does not validate every locale/runtime path.
- Final npm audit: **5 low**, **0 moderate/high/critical**. Remaining low entries
  are cookie, esbuild, Babel core and two SvelteKit 2 features not used by this
  static app. The corresponding SvelteKit fixes require a separate major-3
  migration. No claim of zero vulnerabilities is made.
- Compared locked Rust packages with current official RustSec ranges. Only
  `dotenv 0.15`'s unmaintained notice remains; no published patched version.

Initial type checking of untouched upstream found two BlobPart errors; fixed and
rechecked. An initial integration harness importing the package's ESM `index.js`
failed on bundled inquirer's dynamic `tty` require before any requests; the same
failure was reproduced on the original 2.9.1 build. The actual CommonJS CLI and
browser paths passed. This pre-existing ESM library-entry limitation is not fixed
here. Initial sandbox DNS/local-bind/tool-runtime restrictions were resolved with
isolated tooling and authorized local/read-only access.

Not tested: Docker build/image scan, Linux runtime, GitHub-hosted CI execution,
Firefox/WebKit, production note behavior or deployment/rollback. Docker is absent
on this host. Local integration does not prove production compatibility.

## Security work still separate from an upstream stable sync

Stable **2.9.3 retains** the source findings: unbounded per-note lock map
(`packages/backend/src/note/routes.rs`), CLI output path traversal
(`packages/cli/src/actions/download.ts`), and plaintext/unauthenticated file
metadata (`packages/cli/src/shared/adapters.ts`). They were not silently repaired
or exercised against production in this maintenance task.

V3 prereleases remove the specific lock map and encrypt file metadata, but change
the API/codec and do not migrate v2 notes. The CLI traversal pattern remains in
the inspected v3 tags. Plan targeted fixes or a deliberate future migration;
upstream synchronization is not complete security remediation.

Sources: [stable release](https://github.com/cupcakearmy/cryptgeon/releases/tag/v2.9.3),
[stable backend](https://github.com/cupcakearmy/cryptgeon/blob/v2.9.3/packages/backend/src/note/routes.rs),
[stable CLI](https://github.com/cupcakearmy/cryptgeon/blob/v2.9.3/packages/cli/src/actions/download.ts),
[stable file envelope](https://github.com/cupcakearmy/cryptgeon/blob/v2.9.3/packages/cli/src/shared/adapters.ts),
[Alpine support](https://alpinelinux.org/releases/),
[OWASP headers](https://owasp.org/projects/secure-headers-project),
[RustSec](https://rustsec.org/advisories/).
