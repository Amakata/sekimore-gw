#!/bin/bash
# Runs sekimore-relay serve. Called in the background from entrypoint.sh.
#
#   serve always starts: the Web UI first, and the relay when config.yml declares a git-relay
#   handler. With no relay, or an invalid relay configuration, serve runs the Web UI alone and
#   logs why; a relay that fails to start leaves the Web UI running. DNS and the firewall never
#   depend on it.
#
#   serve is started again if it ever exits — a panic aborts it (panic = "abort"). After a restart
#   the secret store is locked again until someone runs `sgw unlock`.
BIN=${SEKIMORE_RELAY_BIN:-/usr/local/bin/sekimore-relay}
CFG=${SEKIMORE_CONFIG_PATH:-/etc/sekimore/config.yml}

if [ ! -x "$BIN" ]; then
    echo "[relay] binary $BIN missing, skipping"
    exit 0
fi

while true; do
    "$BIN" --config "$CFG" serve
    rc=$?
    echo "[relay] sekimore-relay serve exited (rc=$rc); starting it again in 2s" >&2
    sleep 2
done
