# Multi-stage Docker build for cross-compilation
FROM rust:1-bookworm AS builder

# Install dependencies for SQLite
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build release binary
RUN cargo build --release

# Runtime stage - minimal image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder stage
COPY --from=builder /app/target/release/peercoin-seeder-rust /usr/local/bin/

# Create data directory
RUN mkdir -p /data

# Note: Running as root is required for binding to port 53 (privileged port)
WORKDIR /data

EXPOSE 53/udp

CMD ["peercoin-seeder-rust"]
