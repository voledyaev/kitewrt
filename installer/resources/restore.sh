#!/bin/sh
# kitewrt self-restore after a firmware upgrade.
#
# A sysupgrade keeps /etc/kitewrt (the installer's keep.d entry) — state.json
# with the subscriptions, the rule-sets, the logs — but wipes everything else:
# python3, the daemon, sing-box, the init scripts. Measured on the Flint 2
# (GL.iNet 4.9.1 and 4.11.0): the router came back as a plain router, VPN gone,
# until someone re-ran the installer from a laptop.
#
# This puts it back by itself. The boot hook (/etc/uci-defaults/99-kitewrt-
# restore, also kept) starts this in the background on every boot; it exits at
# once unless the install is gone and the settings are not. Then it waits for
# the internet, installs python3 from the firmware's own feed, and runs the
# very installer that did the original install — kept in kit.tgz — in
# `--local` mode. Same steps, same checksums, same health check.
#
# Everything is logged to /etc/kitewrt/data/logs/restore.log (on flash, kept).

KIT=/etc/kitewrt/restore/kit.tgz
STATE=/etc/kitewrt/data/state.json
LOG=/etc/kitewrt/data/logs/restore.log
WORK=/tmp/kitewrt-restore
LOCK=/tmp/kitewrt-restore.lock

installed() { [ -d /usr/lib/kitewrt/kitewrt ] && [ -x /usr/bin/sing-box ] && [ -x /etc/init.d/kitewrt ]; }

installed && exit 0
[ -f "$STATE" ] && [ -f "$KIT" ] || exit 0
mkdir "$LOCK" 2>/dev/null || exit 0  # already running
trap 'rm -rf "$LOCK"' EXIT

mkdir -p "$(dirname "$LOG")"
exec >>"$LOG" 2>&1
say() { echo "$(date '+%F %T') $*"; logger -t kitewrt-restore "$*"; }
say "kitewrt is not installed but its settings are: restoring after a firmware upgrade"

# Up to ~2 h of attempts: the WAN may take a while (PPPoE, a modem still
# booting), and a failed attempt is retried rather than given up on.
attempt=0
while [ $attempt -lt 12 ]; do
    attempt=$((attempt + 1))
    n=0
    until ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 || ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; do
        n=$((n + 1)); [ $n -ge 60 ] && break; sleep 10
    done
    say "attempt $attempt: installing python3"
    if ! python3 -c 'import urllib.request' 2>/dev/null; then
        opkg update && opkg install python3
    fi
    if python3 -c 'import urllib.request' 2>/dev/null; then
        rm -rf "$WORK" && mkdir -p "$WORK" && tar -xzf "$KIT" -C "$WORK"
        say "attempt $attempt: running the installer locally"
        if (cd "$WORK" && python3 -m installer --local); then
            say "restored"
            rm -rf "$WORK"
            exit 0
        fi
    fi
    say "attempt $attempt failed; retrying in 10 minutes"
    sleep 600
done
say "giving up; re-run the installer from a computer (see the README)"
