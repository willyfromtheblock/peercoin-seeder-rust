# Multi-stage Docker build
# No apt-get anywhere: rust:1-bookworm already ships gcc, sqlite is bundled by
# libsqlite3-sys, and TLS is rustls (no openssl). Avoids depending on debian
# apt mirrors at build time.
FROM rust:1-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage - minimal image, no package installs needed
FROM debian:bookworm-slim

# CA certs copied from the builder instead of apt (rustls uses them if TLS is hit)
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /app/target/release/peercoin-seeder-rust /usr/local/bin/

# WORKDIR creates the data dir without needing a shell/mkdir layer
WORKDIR /data

EXPOSE 53/udp

# Note: Running as root is required for binding to port 53 (privileged port)
CMD ["peercoin-seeder-rust"]
