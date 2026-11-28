#!/bin/bash
# Runs sekimore-relay gateway, the gateway's own process (0.3.0-alpha.5): the firewall and proxy log
# followers, which were tasks of the Python orchestrator before. Called in the background from
# entrypoint.sh, with the config.yml the orchestrator reads.
#
#   gateway is started again if it ever exits — a panic aborts it (panic = "abort") — with a line on
#   stderr naming the exit code. Rows logged while it is down are lost (ulogd's and Squid's own
#   files keep the lines). The delay before a restart is 2s; after a run shorter than 10s it doubles
#   up to 60s, so a gateway that cannot start (an unreadable or refused config.yml) logs two lines a
#   minute rather than one a second, and a run of 10s or more resets it to 2s.
#
#   SIGTERM / SIGINT stop the loop and the gateway with it, and nothing is started again.
BIN=${SEKIMORE_RELAY_BIN:-/usr/local/bin/sekimore-relay}
CFG=/etc/sekimore/config.yml

if [ ! -x "$BIN" ]; then
    echo "[gateway] binary $BIN missing, skipping"
    exit 0
fi

child=""
trap '[ -n "$child" ] && kill -TERM "$child" 2>/dev/null; exit 0' TERM INT

delay=2
while true; do
    started=$SECONDS
    "$BIN" -v --config "$CFG" gateway &
    child=$!
    wait "$child"
    rc=$?
    child=""
    lived=$((SECONDS - started))
    [ "$lived" -ge 10 ] && delay=2
    echo "[gateway] sekimore-relay gateway exited (rc=$rc); firewall blocks and proxy requests are not recorded until it is back; starting it again in ${delay}s" >&2
    sleep "$delay" &
    wait $!
    [ "$lived" -lt 10 ] && delay=$((delay * 2 > 60 ? 60 : delay * 2))
done
