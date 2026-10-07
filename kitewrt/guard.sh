#!/bin/sh
# kitewrt guard — the one failure the daemon cannot handle: the daemon itself
# being gone.
#
# Every other failure is handled in Python: the watchdog restarts sing-box, and
# turning the VPN off always takes the LAN direct. But if the daemon is dead or
# wedged (crash-looping past procd's respawn limit, OOM-killed, stuck), nothing
# watches the capture — and a capture with no tproxy listener behind it
# black-holes every LAN connection and all LAN DNS. The VPN switch lives in the
# daemon's UI, so the user cannot even turn it off.
#
# Runs as its own procd service, kitewrt-guard (not cron: one less
# dependency on a firmware that may not run crond). Every minute it checks the
# three facts that together mean "dark LAN, nobody home":
#
#   1. the capture hook is in mangle/PREROUTING,
#   2. nothing listens on the tproxy port,
#   3. the daemon does not answer /api/health.
#
# Three strikes in a row (~3 min — far longer than any restart the daemon does
# itself) and it acts:
#
#   * first it tries to bring both back: restart sing-box and the daemon;
#   * VPN off and still broken → release the LAN (flush the capture, stop
#     sing-box so a respawn cannot recreate the DNS half-state). The user asked
#     for a plain router.
#   * VPN on and still broken → the LAN stays dark. That is the design: with
#     the VPN on, dropping beats leaking (an earlier version of this script
#     released the LAN here, which the red-team review caught). Instead it
#     takes over :8088 with a page that says what happened and offers the one
#     control the user needs — "turn the VPN off" — and retries the daemon
#     every few minutes.
#
# Whatever happened is noted in $EVENT; the daemon shows it on the dashboard
# once it is back.
#
# CHAIN / PORT / UI_PORT must match kitewrt/divert.py and the init script —
# pinned by tests/test_guard.py.

CHAIN=kitewrt_tproxy
PORT_HEX=1ED7
UI_PORT=8088
HEALTH=http://127.0.0.1:$UI_PORT/api/health
# Overridable only so tests/test_guard.py can run this script for real.
STATE=${KITEWRT_GUARD_STATE:-/etc/kitewrt/data/state.json}
EVENT=${KITEWRT_GUARD_EVENT:-/etc/kitewrt/data/guard-event}
PAGE=${KITEWRT_GUARD_PAGE:-/tmp/kitewrt-guard-page}
PAGE_PID=${KITEWRT_GUARD_PAGE_PID:-/var/run/kitewrt-guard-page.pid}
INIT=${KITEWRT_GUARD_INIT:-/etc/init.d}
PROCNET=${KITEWRT_GUARD_PROCNET:-/proc/net}
MAX_TICKS=${KITEWRT_GUARD_MAX_TICKS:-0} # 0 = forever
INTERVAL=${KITEWRT_GUARD_INTERVAL:-60}
STRIKES_TO_ACT=3
RETRY_EVERY=5       # ticks between daemon retries while the page is up
DEAD_RETRY_EVERY=10 # ticks between retries when only the daemon is down

log() { logger -t kitewrt-guard "$*"; }

hooked() {
    iptables -w 5 -t mangle -S PREROUTING 2>/dev/null | grep -q -- "-j $CHAIN\$"
}

listening() {
    awk -v p=":$PORT_HEX" '$4 == "0A" && substr($2, length($2) - 4) == p { f = 1 } END { exit !f }' \
        "$PROCNET/tcp" "$PROCNET/tcp6" 2>/dev/null
}

daemon_alive() {
    curl -s -m 5 -o /dev/null "$HEALTH"
}

vpn_on() {
    grep -q '"vpn_on": *true' "$STATE" 2>/dev/null
}

note() {
    echo "$(date '+%F %T') $*" >>"$EVENT"
}

release() {
    iptables -w 5 -t mangle -F "$CHAIN" 2>/dev/null
    iptables -w 5 -t mangle -F "${CHAIN}_next" 2>/dev/null
    "$INIT/singbox" stop 2>/dev/null
}

recover() {
    # The page holds :8088; the daemon cannot start while it does.
    page_down
    log "restarting sing-box and the daemon"
    # Noted *before* the restart: the daemon reads this file once it is back,
    # and a line appended after that would sit there until the next crash.
    note "the daemon was not responding; the guard restarted it"
    "$INIT/singbox" restart 2>/dev/null
    "$INIT/kitewrt" restart 2>/dev/null
    n=0
    while [ $n -lt 12 ]; do
        sleep "${KITEWRT_GUARD_RECOVER_SLEEP:-5}"
        daemon_alive && return 0
        n=$((n + 1))
    done
    return 1
}

page_running() {
    [ -s "$PAGE_PID" ] && kill -0 "$(cat "$PAGE_PID")" 2>/dev/null
}

page_down() {
    page_running && kill "$(cat "$PAGE_PID")" 2>/dev/null
    rm -f "$PAGE_PID"
}

page_up() {
    page_running && return 0
    command -v uhttpd >/dev/null 2>&1 || {
        log "no uhttpd: cannot show the emergency page; the LAN stays dark until the daemon is back"
        return 1
    }
    mkdir -p "$PAGE/cgi-bin"
    cat >"$PAGE/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>kitewrt is down</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#222;background:#fafafa}
@media(prefers-color-scheme:dark){body{color:#ddd;background:#161616}}
button{font:inherit;padding:.6rem 1rem;border-radius:.4rem;border:1px solid #b33;background:#c33;color:#fff;cursor:pointer}
code{font-size:.9em}</style>
<h1>kitewrt is down</h1>
<p>The kitewrt daemon on this router stopped and could not be restarted.
The VPN is <b>on</b>, so the network is held <b>offline on purpose</b>: without the
VPN running, traffic would otherwise go out unprotected.</p>
<p>The router keeps trying to bring kitewrt back every few minutes.</p>
<form method="post" action="/cgi-bin/vpn-off">
<p><button type="submit">Turn the VPN off — use the internet without it</button></p>
</form>
<p>Turning it on again later works as usual from the kitewrt page once it is back.
Details: <code>logread -e kitewrt</code> and <code>/etc/kitewrt/data/diag/</code> on the router.</p>
HTML
    cat >"$PAGE/cgi-bin/vpn-off" <<CGI
#!/bin/sh
if [ "\$REQUEST_METHOD" != POST ]; then
    printf 'Status: 405 Method Not Allowed\\r\\nContent-Type: text/plain\\r\\n\\r\\nPOST only\\n'; exit 0
fi
# A browser sends Origin on every cross-site POST: refuse one from elsewhere.
if [ -n "\$HTTP_ORIGIN" ] && [ "\${HTTP_ORIGIN#*://}" != "\$HTTP_HOST" ]; then
    printf 'Status: 403 Forbidden\\r\\nContent-Type: text/plain\\r\\n\\r\\ncross-origin\\n'; exit 0
fi
if [ -f "$STATE" ]; then
    sed 's/"vpn_on": *true/"vpn_on": false/' "$STATE" >"$STATE.guard" &&
        chmod 600 "$STATE.guard" && mv "$STATE.guard" "$STATE"
fi
iptables -w 5 -t mangle -F "$CHAIN" 2>/dev/null
iptables -w 5 -t mangle -F "${CHAIN}_next" 2>/dev/null
"$INIT/singbox" stop >/dev/null 2>&1
echo "\$(date '+%F %T') VPN turned off from the guard page; LAN released" >>"$EVENT"
logger -t kitewrt-guard "VPN turned off from the emergency page; LAN released"
printf 'Content-Type: text/html; charset=utf-8\\r\\n\\r\\n'
printf '<!doctype html><meta charset="utf-8"><title>VPN off</title>'
printf '<p style="font:16px system-ui;max-width:36rem;margin:3rem auto">'
printf 'The VPN is off and the internet works without it. kitewrt will come back '
printf 'with the VPN off; turn it on from its page when you want it.</p>'
CGI
    chmod 755 "$PAGE/cgi-bin/vpn-off"
    # 0.0.0.0 like the daemon: the installer's firewall rule drops :8088 from
    # the WAN, so this is LAN-only.
    start-stop-daemon -S -b -m -p "$PAGE_PID" -x "$(command -v uhttpd)" -- \
        -f -p "0.0.0.0:$UI_PORT" -h "$PAGE" -x /cgi-bin -I index.html -t 30
    log "emergency page up on :$UI_PORT"
}

strikes=0
paged=0
dead=0
ticks=0
while :; do
    ticks=$((ticks + 1))
    [ "$MAX_TICKS" -gt 0 ] && [ "$ticks" -gt "$MAX_TICKS" ] && exit 0
    sleep "$INTERVAL"

    if page_running || [ "$paged" -gt 0 ]; then
        # Emergency mode (or released from the page and still retrying): keep
        # trying to get the daemon back every RETRY_EVERY ticks.
        paged=$((paged + 1))
        if [ $((paged % RETRY_EVERY)) -eq 0 ]; then
            if recover; then
                log "daemon is back"
                paged=0
                strikes=0
            elif vpn_on; then
                page_up
            else
                # Turned off from the page meanwhile: the LAN is released and
                # a page saying "the VPN is on" would be false. Keep retrying.
                paged=0
                release
            fi
        fi
        continue
    fi

    if daemon_alive; then
        strikes=0
        dead=0
        continue
    fi
    dead=$((dead + 1))
    if hooked && ! listening; then
        strikes=$((strikes + 1))
        log "LAN captured with no listener and no daemon (strike $strikes/$STRIKES_TO_ACT)"
    else
        strikes=0
        # The daemon is gone but the LAN is fine (sing-box still carries it).
        # Not urgent — but the UI is down, so try to bring it back now and
        # then. Only while the capture is hooked: a daemon that stopped
        # cleanly took its capture down with it, so no hook means someone
        # stopped kitewrt on purpose and it must stay stopped.
        if hooked && [ $((dead % DEAD_RETRY_EVERY)) -eq 0 ]; then
            recover
        fi
        continue
    fi
    [ "$strikes" -ge "$STRIKES_TO_ACT" ] || continue
    strikes=0

    if recover; then
        # The daemon is back; whatever is still wrong with sing-box is its
        # watchdog's to handle (and to show), not ours.
        log "recovered: the daemon is back"
        continue
    fi
    if listening; then
        # sing-box came back and the LAN is being carried; only the daemon is
        # missing. Holding anything offline or claiming so would be false.
        log "daemon still down, but sing-box is carrying the LAN again"
        note "daemon down; sing-box restarted by the guard and carrying the LAN"
        continue
    fi
    if ! vpn_on; then
        log "VPN is off and kitewrt cannot be brought back: releasing the LAN"
        release
        note "daemon down with the VPN off; the guard released the LAN"
        continue
    fi
    log "VPN is on and kitewrt cannot be brought back: holding the LAN offline, emergency page on :$UI_PORT"
    note "daemon down with the VPN on; the LAN was held offline"
    page_up
    paged=1
done
