#!/bin/bash
# sekimore-relay の起動判定。entrypoint.sh からバックグラウンドで呼ばれる。
#
#   needs-relay の終了コード: 0 = 起動する / 1 = 不要（domain_handlers に git-relay が無い） / 2 = 設定不正
#   relay の失敗で gateway を止めない（DNS / firewall は relay 無しでも機能する）。
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
