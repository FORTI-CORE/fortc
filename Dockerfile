# Multi-stage build for optimal image size
FROM rust:1.75-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Runtime stage - minimal image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m -u 1000 fortc && \
    mkdir -p /home/fortc/scans && \
    chown -R fortc:fortc /home/fortc

# Copy the binary from builder
COPY --from=builder /app/target/release/fortc /usr/local/bin/fortc

# Set permissions
RUN chmod +x /usr/local/bin/fortc

# Switch to non-root user
USER fortc
WORKDIR /home/fortc

# Create volume for scan results
VOLUME ["/home/fortc/scans"]

# Set environment variables
ENV RUST_LOG=info

# Default command shows help
ENTRYPOINT ["fortc"]
CMD ["--help"]
