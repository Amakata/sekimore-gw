# syntax=docker/dockerfile:1.7

# ---- sekimore-relay (Rust) ----
# 各アーキで native にビルドした静的 musl バイナリ。glibc 世代に依存しないので
# devcontainer base イメージへ COPY --from してもそのまま動く。
# （buildx の arm64 は QEMU で遅い。cargo-zigbuild による cross は将来の最適化: relay/README.md）
FROM rust:1.89-slim-bookworm AS relay-builder
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add "$(uname -m)-unknown-linux-musl"
WORKDIR /build
COPY relay/Cargo.toml relay/Cargo.lock relay/rust-toolchain.toml ./
COPY relay/src ./src
# テストの fixture は Rust のユニットテストが include_str! するだけなので不要（--release はテストを含まない）
RUN cargo build --release --locked --target "$(uname -m)-unknown-linux-musl" \
    && install -m 0755 "target/$(uname -m)-unknown-linux-musl/release/sekimore-relay" /sekimore-relay

# ---- gateway ----
FROM python:3.13-slim

# System package installation
# openssh-client: relay が上流 git へ出るときの ssh / ssh-add / ssh-keyscan / ssh-keygen
RUN apt-get update && apt-get install -y \
    iptables \
    ipset \
    iproute2 \
    dnsutils \
    procps \
    squid \
    ulogd2 \
    docker.io \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy project configuration and source code
COPY pyproject.toml .
COPY README.md .
COPY src/ ./src/
COPY config/ulogd.conf /etc/ulogd.conf
COPY entrypoint.sh /app/entrypoint.sh
COPY scripts/start-relay.sh /app/scripts/start-relay.sh

# Install dependencies using uv
RUN uv pip install --system .

# sekimore-relay binary (starts only when config.yml has a git-relay handler)
COPY --from=relay-builder /sekimore-relay /usr/local/bin/sekimore-relay

# Create data directories (relay state lives under /data/relay on the gateway-data volume)
RUN mkdir -p /data /data/relay /etc/sekimore /var/spool/squid /var/log/squid /var/log/ulog \
    && chmod 700 /data/relay

# Grant execution permission to entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/scripts/start-relay.sh

# Initialize Squid cache directories
RUN squid -z || true

# Privileged mode required (for iptables, ipset operations)
# Specify cap_add: NET_ADMIN in docker-compose.yml
# For host-side iptables manipulation, privileged: true is required

# Expose Web UI port. 22 (git relay) / 8420 (relay API) / 443 (relay passthrough) are
# documentation only: agents reach them over internal-net; do not publish them to the host.
EXPOSE 8080 22 8420 443

# Entrypoint (ulogd2 + relay + Web UI + Main app)
CMD ["/app/entrypoint.sh"]
