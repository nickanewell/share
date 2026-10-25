# FRONTEND
FROM node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS client
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

WORKDIR /tmp
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm run build


# BACKEND
FROM rust:1.99.1-alpine3.24@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS backend
WORKDIR /tmp
RUN apk add --no-cache libc-dev openssl-dev alpine-sdk
COPY ./packages/backend ./
RUN RUSTFLAGS="-Ctarget-feature=-crt-static" cargo build --release --locked


# RUNNER
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/nickanewell/share" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
WORKDIR /app
RUN apk add --no-cache curl libgcc
COPY --from=backend /tmp/target/release/cryptgeon .
COPY --from=client /tmp/packages/frontend/build ./frontend
ENV FRONTEND_PATH="./frontend"
ENV REDIS="redis://redis/"
EXPOSE 8000
ENTRYPOINT [ "/app/cryptgeon" ]
