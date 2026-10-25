# Isolated Linux release validation

These files do not deploy production or configure automatic updates. The gate is
prepared but **has not been run on Linux/Docker**; VM access must be recovered first.
Run on an authorized Linux amd64 Docker host from a clean, committed checkout with
the pinned Node/pnpm and Rust toolchains available. Never reuse the production
Compose file/project or production Redis. Reserve loopback port 13000 first.

Fetch the real Git LFS test fixtures (`git lfs pull`) before the full suite. The
browser CI checkout now requests LFS. Pointer files alone are not valid fixtures.

```sh
test -z "$(git status --porcelain)"
export SOURCE_REVISION="$(git rev-parse HEAD)"
pnpm install --frozen-lockfile
python3 scripts/test_upstream_update.py
cargo +1.99.1 test --locked --manifest-path packages/backend/Cargo.toml
pnpm run test:security
pnpm --filter @cryptgeon/web exec svelte-kit sync
pnpm --filter @cryptgeon/web check
pnpm run build
pnpm exec playwright install --with-deps
docker compose --project-name rival-share-staging -f deploy/compose.staging.yaml config --quiet
docker compose --project-name rival-share-staging -f deploy/compose.staging.yaml build --pull app
docker compose --project-name rival-share-staging -f deploy/compose.staging.yaml up --detach --wait --wait-timeout 90
curl --fail --silent http://127.0.0.1:13000/api/status/
docker compose --project-name rival-share-staging -f deploy/compose.staging.yaml exec -T redis redis-server --version
docker image inspect "rival-it-share:staging-$SOURCE_REVISION" --format '{{.Id}} {{json .Config.Labels}}'
pnpm exec playwright test --config=deploy/playwright.staging.config.ts --project=chrome test/web/file/security.spec.js
pnpm exec playwright test --config=deploy/playwright.staging.config.ts
docker compose --project-name rival-share-staging -f deploy/compose.staging.yaml down
```

Check every exit status and stop promotion on failure. Run the final `down` after
failed tests too; it targets only this isolated project and clears synthetic RAM
shares. There are no Redis host ports, disk volumes or production mounts. Keep the
successful app image by ID for promotion, and preserve the current production image
and configuration separately before any rollout. Record commit, image ID/digest,
labels and test outcomes. A local image ID is not a registry digest/attestation.

The Redis multi-platform index digest was read from Docker Hub's official
[`library/redis` tag metadata](https://hub.docker.com/v2/repositories/library/redis/tags/7.4.11-alpine)
on 2026-10-24. Its linux/amd64 child is
`sha256:8be847644e195abc4c10c8d9936cfa45332eccc6b714fa7b186ff43f1f4d5579`.
Pins need deliberate refresh and retesting; they do not update themselves.
