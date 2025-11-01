FROM python:3.13-slim

# System package installation
RUN apt-get update && apt-get install -y \
    iptables \
    ipset \
    iproute2 \
    dnsutils \
    procps \
    squid \
    ulogd2 \
    docker.io \
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

# Install dependencies using uv
RUN uv pip install --system .

# Create data directories
RUN mkdir -p /data /etc/sekimore /var/spool/squid /var/log/squid /var/log/ulog

# Grant execution permission to entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Initialize Squid cache directories
RUN squid -z || true

# Privileged mode required (for iptables, ipset operations)
# Specify cap_add: NET_ADMIN in docker-compose.yml
# For host-side iptables manipulation, privileged: true is required

# Expose Web UI port
EXPOSE 8080

# Entrypoint (ulogd2 + Web UI + Main app)
CMD ["/app/entrypoint.sh"]
