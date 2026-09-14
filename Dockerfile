# syntax=docker/dockerfile:1.7

# ---- sekimore-relay (Rust) ----
# ビルドはランナーの CPU (BUILDPLATFORM) で native に走らせ、TARGETARCH 向けの静的 musl バイナリを
# cargo-zigbuild でクロスコンパイルする。arm64 を QEMU で回すと 40 分超かかるため。
# 静的 musl なので glibc 世代に依存せず、devcontainer base イメージへ COPY --from してもそのまま動く。
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:0.20.1 AS relay-builder
ARG TARGETARCH
WORKDIR /build
# rust-toolchain.toml の版を先に入れておく (ソース変更で無効化されないレイヤ)
COPY relay/rust-toolchain.toml ./
RUN CHANNEL="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" \
    && rustup toolchain install "$CHANNEL" --profile minimal --component rustfmt --component clippy \
    && rustup target add --toolchain "$CHANNEL" x86_64-unknown-linux-musl aarch64-unknown-linux-musl
COPY relay/Cargo.toml relay/Cargo.lock ./
COPY relay/src ./src
RUN case "$TARGETARCH" in \
      amd64) T=x86_64-unknown-linux-musl ;; \
      arm64) T=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac \
    && cargo zigbuild --release --locked --target "$T" \
    && install -m 0755 "target/$T/release/sekimore-relay" /sekimore-relay

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
# agent-setup.sh is shipped in the image so that sgw-devcontainer-base can COPY --from it
# (same tag as the relay binary => the two always match)
COPY agent-setup.sh /usr/local/share/sekimore/agent-setup.sh

# Install dependencies using uv
RUN uv pip install --system .

# sekimore-relay binary (starts only when config.yml has a git-relay handler)
COPY --from=relay-builder /sekimore-relay /usr/local/bin/sekimore-relay

# Create data directories (relay state lives under /data/relay on the gateway-data volume)
RUN mkdir -p /data /data/relay /etc/sekimore /var/spool/squid /var/log/squid /var/log/ulog \
    && chmod 700 /data/relay

# Grant execution permission to entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/scripts/start-relay.sh /usr/local/share/sekimore/agent-setup.sh

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
