#!/bin/sh
# kitewrt guard — the one LAN-outage path the daemon cannot cover: the daemon
# itself being gone.
#
# Every other failure is handled in Python: the watchdog restarts sing-box, and
# turning the VPN off always takes the LAN direct. But if the daemon is dead or
# wedged (crash-looping past procd's respawn limit, OOM-killed, stuck), nothing
# watches the capture, and a capture with no tproxy listener behind it
# black-holes every LAN connection and all LAN DNS. The user's "turn the VPN
# off" lives in the daemon's UI, so they could not even do that.
#
# Runs as its own procd instance next to the daemon (not cron: one less
# dependency on a firmware that may not run crond). Every minute it checks the
# three facts that together mean "dark LAN, nobody home":
#
#   1. the capture hook is in mangle/PREROUTING,
#   2. nothing listens on the tproxy port,
#   3. the daemon does not answer /api/health.
#
# Three strikes in a row (≈3 min — far longer than any restart the daemon does
# itself) and it makes the capture inert by flushing its chains, then stops
# sing-box so a later respawn cannot sit on the LAN resolver address with no
# capture (the DNS half-state). The daemon's next start sweeps the rest.
#
# CHAIN / PORT must match kitewrt/divert.py — pinned by tests/test_guard.py.

CHAIN=kitewrt_tproxy
PORT_HEX=1ED7
HEALTH=http://127.0.0.1:8088/api/health
INTERVAL=${KITEWRT_GUARD_INTERVAL:-60}
STRIKES_TO_ACT=3

hooked() {
    iptables -w 5 -t mangle -S PREROUTING 2>/dev/null | grep -q -- "-j $CHAIN\$"
}

listening() {
    awk -v p=":$PORT_HEX" '$4 == "0A" && substr($2, length($2) - 4) == p { f = 1 } END { exit !f }' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

daemon_alive() {
    curl -s -m 5 -o /dev/null "$HEALTH"
}

strikes=0
while :; do
    sleep "$INTERVAL"
    if hooked && ! listening && ! daemon_alive; then
        strikes=$((strikes + 1))
        logger -t kitewrt-guard "LAN captured with no listener and no daemon (strike $strikes/$STRIKES_TO_ACT)"
    else
        strikes=0
    fi
    if [ "$strikes" -ge "$STRIKES_TO_ACT" ]; then
        logger -t kitewrt-guard "releasing the LAN: flushing $CHAIN and stopping sing-box"
        iptables -w 5 -t mangle -F "$CHAIN" 2>/dev/null
        iptables -w 5 -t mangle -F "${CHAIN}_next" 2>/dev/null
        /etc/init.d/singbox stop 2>/dev/null
        strikes=0
    fi
done
