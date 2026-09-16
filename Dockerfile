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
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl > /tmp/t ;; \
      arm64) echo aarch64-unknown-linux-musl > /tmp/t ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac
# 依存だけ先にコンパイルする層 (Cargo.toml/lock だけで、src はダミー)。src 変更でこの層は無効化されない
COPY relay/Cargo.toml relay/Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs \
    && cargo zigbuild --release --locked --target "$(cat /tmp/t)" || true \
    && rm -rf src
# 本ソースをコピーして本ビルド (依存は上でキャッシュ済み)。ダミーの成果物は消して確実に本体を再ビルド
COPY relay/src ./src
# sekimore guide (AI エージェント向けの使い方) はバイナリに埋め込む (include_str!)
COPY relay/share ./share
RUN T="$(cat /tmp/t)" \
    && rm -f "target/$T/release/deps/sekimore_relay"* "target/$T/release/sekimore-relay" 2>/dev/null || true; \
    cargo zigbuild --release --locked --target "$T" \
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
