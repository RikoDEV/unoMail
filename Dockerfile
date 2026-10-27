# syntax=docker/dockerfile:1
# unoMail: mail server, web client, admin panel, Rspamd and ClamAV in one container.

# --- Web UI -------------------------------------------------------------------------------
FROM node:25-alpine AS web
WORKDIR /build
# Node 25+ no longer ships corepack; npm installs the pinned pnpm on any version.
RUN npm install -g pnpm@11.1.2
COPY web/package.json web/pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

# --- Server -------------------------------------------------------------------------------
FROM rust:1-alpine AS server
RUN apk add --no-cache build-base
WORKDIR /build
COPY server/Cargo.toml server/Cargo.lock ./
# Build dependencies in their own layer so source changes do not recompile them.
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked && rm -rf src
COPY server/ ./
# A release image is built with its tag (v1.2.3); a local build reports the crate version.
ARG UNOMAIL_VERSION
RUN touch src/main.rs src/lib.rs && UNOMAIL_VERSION="${UNOMAIL_VERSION#v}" cargo build --release --locked

# --- Runtime ------------------------------------------------------------------------------
FROM alpine:3.24
RUN apk add --no-cache ca-certificates clamav clamav-daemon clamav-libunrar curl git libcap redis rspamd s6-overlay tzdata \
    && addgroup -S unomail && adduser -S -H -G unomail -h /data/unomail -s /sbin/nologin unomail \
    # Rspamd talks to ClamAV over its Unix socket.
    && addgroup -S mailfilter && addgroup unomail rspamd \
    && addgroup rspamd redis \
    && addgroup unomail mailfilter && addgroup rspamd mailfilter && addgroup clamav mailfilter \
    && rm -rf /etc/rspamd/local.d/* /var/cache/apk/*

COPY --from=server /build/target/release/unomail /usr/local/bin/unomail
COPY --from=server /build/target/release/unomail-p12 /usr/local/bin/unomail-p12
COPY --from=web /build/dist /usr/share/unomail/web
COPY docker/rspamd/ /etc/rspamd/local.d/
COPY docker/clamav/ /etc/clamav/
COPY docker/s6/ /etc/s6-overlay/s6-rc.d/

# The server runs unprivileged; this capability alone lets it bind the mail and web ports.
RUN setcap cap_net_bind_service=+ep /usr/local/bin/unomail \
    && chmod +x /etc/s6-overlay/s6-rc.d/*/run /etc/s6-overlay/s6-rc.d/*/up.sh 2>/dev/null || true

ENV UNOMAIL_DATA_DIR=/data/unomail \
    UNOMAIL_WEB_DIR=/usr/share/unomail/web \
    UNOMAIL_RSPAMD_URL=http://127.0.0.1:11333 \
    UNOMAIL_RSPAMD_CONTROLLER_URL=http://127.0.0.1:11334 \
    UNOMAIL_RSPAMD_SOCKET=/run/rspamd/worker.sock \
    UNOMAIL_RSPAMD_CONTROLLER_SOCKET=/run/rspamd/controller.sock \
    CLAMAV_ENABLED=true \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_KEEP_ENV=1

VOLUME /data
# SMTP, HTTP (ACME + redirect), IMAP (STARTTLS), HTTPS, SMTPS, submission, IMAPS, POP3S
EXPOSE 25 80 143 443 465 587 993 995
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:80/health || exit 1
ENTRYPOINT ["/init"]
