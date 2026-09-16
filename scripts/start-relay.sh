#!/bin/bash
# Decides whether to start sekimore-relay. Called in the background from entrypoint.sh.
#
#   needs-relay exit codes: 0 = start / 1 = not needed (no git-relay in domain_handlers) / 2 = invalid config
#   A relay failure never takes down the gateway (DNS / firewall work without the relay).
BIN=${SEKIMORE_RELAY_BIN:-/usr/local/bin/sekimore-relay}
CFG=${SEKIMORE_CONFIG_PATH:-/etc/sekimore/config.yml}

if [ ! -x "$BIN" ]; then
    echo "[relay] binary $BIN missing, skipping"
    exit 0
fi

"$BIN" --config "$CFG" needs-relay
rc=$?
case $rc in
    0)
        echo "[relay] git-relay handler configured, starting sekimore-relay"
        exec "$BIN" --config "$CFG" serve
        ;;
    1)
        echo "[relay] no git-relay handler in $CFG, not starting"
        exit 0
        ;;
    *)
        echo "[relay] ERROR: config check failed (rc=$rc); gateway continues without relay" >&2
        exit 0
        ;;
esac
