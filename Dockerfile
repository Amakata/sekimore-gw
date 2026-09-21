# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# ---- sekimore-relay (Rust) ----
# Build natively on the runner's CPU (BUILDPLATFORM) and cross-compile a static musl binary for
# TARGETARCH with cargo-zigbuild, because building arm64 under QEMU takes over 40 minutes.
# Being static musl, it does not depend on the glibc generation and works as-is when COPY --from'd
# into the devcontainer base image.
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:0.20.1@sha256:af1bc2b869c5d76c1300f7a4685c2f1793d068e6e895c9f5c399b517b31a731e AS relay-builder
ARG TARGETARCH
WORKDIR /build
# Install the toolchain version from rust-toolchain.toml first (a layer source changes do not invalidate)
COPY relay/rust-toolchain.toml ./
RUN CHANNEL="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" \
    && rustup toolchain install "$CHANNEL" --profile minimal --component rustfmt --component clippy \
    && rustup target add --toolchain "$CHANNEL" x86_64-unknown-linux-musl aarch64-unknown-linux-musl
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl > /tmp/t ;; \
      arm64) echo aarch64-unknown-linux-musl > /tmp/t ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac
# Layer that compiles only the dependencies (just Cargo.toml/lock, with a dummy src); src changes do not invalidate it
COPY relay/Cargo.toml relay/Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs \
    && cargo zigbuild --release --locked --target "$(cat /tmp/t)" || true \
    && rm -rf src
# Copy the real sources and do the real build (dependencies are cached above); drop the dummy artifacts so the binary is definitely rebuilt
COPY relay/src ./src
# The sekimore guide (usage notes for AI agents) and the CLI locale dictionaries are embedded
# in the binary via include_str!, so both have to be here before the build
COPY relay/share ./share
COPY relay/locales ./locales
RUN T="$(cat /tmp/t)" \
    && rm -f "target/$T/release/deps/sekimore_relay"* "target/$T/release/sekimore-relay" 2>/dev/null || true; \
    cargo zigbuild --release --locked --target "$T" \
    && install -m 0755 "target/$T/release/sekimore-relay" /sekimore-relay

# ---- gateway ----
FROM python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0

# The Debian archive as of one moment, so a rebuild of this commit installs what the last one did.
#
# The base image is pinned by digest, but everything installed on top of it was not: `apt-get
# update` takes whatever Debian is serving that day. Two releases apart, this layer moved by 1,275
# bytes and every consumer re-pulled 160 MB of identical content. Naming versions alone does not
# fix it — the ~100 transitive dependencies would still float, and a named version disappears from
# the archive within weeks of being superseded. The snapshot is what makes both hold.
#
# **Bumping this is how security updates arrive.** Nothing reaches this image between bumps. Do it
# on a schedule, not when something breaks; `test_supply_chain_pins.py` fails once it is stale.
ARG DEBIAN_SNAPSHOT=20260920T000000Z

# System package installation
# openssh-client: ssh / ssh-add / ssh-keyscan / ssh-keygen, used when the relay reaches out to the upstream git
# bind9-dnsutils: what `dnsutils` resolved to — the latter is a virtual name trixie has no package for
RUN set -eu \
    # Fail here rather than inside apt if the base image ever stops shipping the keyring: the
    # snapshot is still signature-verified, and a missing key must not degrade to trusting less.
    && test -f /usr/share/keyrings/debian-archive-keyring.gpg \
    && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list \
    && printf '%s\n' \
        'Types: deb' \
        "URIs: https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" \
        'Suites: trixie' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        > /etc/apt/sources.list.d/snapshot.sources \
    && apt-get update \
    && apt-get install -y \
        iptables=1.8.11-2 \
        ipset=7.22-1+b1 \
        iproute2=6.15.0-1 \
        bind9-dnsutils=1:9.20.26-1~deb13u1 \
        procps=2:4.0.4-9 \
        squid=6.13-2+deb13u3 \
        ulogd2=2.0.8-3 \
        docker.io=26.1.5+dfsg1-9+deb13u1 \
        openssh-client=1:10.0p1-7+deb13u4 \
    && rm -rf /var/lib/apt/lists/* \
    # Everything below records *that a build happened*, not anything the gateway reads. Left in,
    # they are the whole reason an unchanged 160 MB layer gets a new digest every release and
    # every deployment re-pulls it (#97). Measured: these were the only files whose contents
    # differed between 0.2.21 and 0.2.22 — metadata was already identical, so BuildKit's
    # timestamp normalisation had done its half.
    #
    # machine-id must be *empty*, not absent: systemd and dbus treat an empty one as
    # "first boot, generate at runtime", while a missing one is an error.
    && : > /etc/machine-id \
    && : > /var/lib/dbus/machine-id \
    && rm -f /var/log/alternatives.log /var/log/dpkg.log \
             /var/log/apt/history.log /var/log/apt/term.log \
             /var/cache/ldconfig/aux-cache

# Working directory
WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Dependencies first, from the manifest alone. The source arrives after, so editing it does not
# rebuild site-packages — the same shape the relay-builder stage above uses for cargo. A stand-in
# package is enough for `uv pip install .` to resolve and install everything but the project.
COPY pyproject.toml .
COPY README.md .
RUN mkdir -p src/sekimore_placeholder \
    && touch src/sekimore_placeholder/__init__.py \
    && uv pip install --system . \
    && rm -rf src \
    # In this layer, not a later one. A .pyc carries the source's mtime inside its header, so
    # every build writes a different byte and the layer moves (#97); `unchecked-hash` puts the
    # source's hash there instead. Recompiling the whole tree from the *last* layer instead would
    # copy every dependency's bytecode into it — 10 MB, measured, on top of the copy already here.
    && python -m compileall -q --invalidation-mode unchecked-hash /usr/local/lib/python3.13

# The project itself, and everything that changes with it
COPY src/ ./src/
COPY config/ulogd.conf /etc/ulogd.conf
COPY entrypoint.sh /app/entrypoint.sh
COPY scripts/start-relay.sh /app/scripts/start-relay.sh
# agent-setup.sh is shipped in the image so that sgw-devcontainer-base can COPY --from it
# (same tag as the relay binary => the two always match)
COPY agent-setup.sh /usr/local/share/sekimore/agent-setup.sh
# The gw:* mise tasks, for the same reason: the operator's interface belongs to the gateway, not
# to a copy in every project's mise.toml. A project reads one out of the image (or COPY --from's
# it) and includes it, so the tasks and the relay that serves them always come from one release.
# Two languages, as with agent-guide.{en,ja}.md: the descriptions are what `mise tasks` prints on
# the operator's terminal. The task set is the same in both, and a test holds them to that.
COPY share/gateway.mise.en.toml /usr/local/share/sekimore/gateway.mise.en.toml
COPY share/gateway.mise.ja.toml /usr/local/share/sekimore/gateway.mise.ja.toml
RUN uv pip install --system --no-deps . \
    # Only what this install added. The dependencies were compiled in their own layer above, and
    # redoing them here would put a second copy of every .pyc in this one.
    && find /usr/local/lib/python3.13/site-packages -maxdepth 1 -name 'sekimore*' \
        -exec python -m compileall -q --invalidation-mode unchecked-hash {} + \
    && python -m compileall -q --invalidation-mode unchecked-hash /app/src

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
