# Builder stage
FROM rust:alpine AS builder

# Install build dependencies
# build-base: for gcc/compilation
# openssl-dev: for networking features
# perl: required by ring/openssl builds
RUN apk add --no-cache build-base openssl-dev perl

WORKDIR /app

# Copy the entire workspace
# We copy everything because it's a workspace and inter-crate dependencies might be complex
COPY . .

# Build the hickory-dns binary
# We explicitly enable features for a full-featured server
# release profile is used for optimization
RUN cargo build --release --bin hickory-dns --features sqlite,resolver,recursor,blocklist,pipeline,remote-blocklist,dnssec-ring,https-ring,tls-ring,quic-ring,prometheus-metrics,metrics

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
# ca-certificates: for TLS validation
# openssl: library support
RUN apk add --no-cache ca-certificates openssl wget tzdata

ENV TZ=Asia/Dhaka

# Create a non-root user for security (optional but recommended, though user didn't explicitly ask, good practice)
# But for simplicity and standard port usage (53 requires root or capabilities), we'll stick to root or user can configure.
# For now, let's keep it simple as requested, running as root to bind port 53 easily.

WORKDIR /usr/local/bin

# Copy the binary from builder
COPY --from=builder /app/target/release/hickory-dns .

# Create a directory for config
RUN mkdir -p /config

# Expose pipeline defaults: HAProxy backend (PROXY v2) and DoH admin
EXPOSE 5301/tcp 443/tcp 9000/tcp

# Set volume for persistence/config if needed
VOLUME ["/config"]

# Entrypoint
ENTRYPOINT ["./hickory-dns"]
CMD ["--help"]
