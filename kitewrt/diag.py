"""Diagnostic snapshots, written when the data plane fails.

The outage this exists for left nothing behind: the router's log is a 512 KB
ring in RAM, and a firmware update (or any reboot) took it before anyone
looked. `state.json` survived, but by then it read `last_apply.ok: true` with an
empty error. The root cause was eventually reproduced on purpose — it could not
be read off the router.

So when the watchdog raises a fault, or the data plane gives up and runs the
LAN direct, the evidence is copied to `<base>/diag/` — on flash, and under
`/etc/kitewrt` so the installer's keep.d entry carries it across a sysupgrade.
Only the last few are kept; they are small, and written once per episode, not
per tick.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
import ssl
import tempfile
import time
from pathlib import Path
from typing import Any

from kitewrt.process import OutputLimitError, communicate, wait_process

logger = logging.getLogger(__name__)

KEEP = 5

# Read-only commands. Each is allowed to fail (a missing tool just leaves its
# section empty). No secrets: sing-box's config is listed, never printed.
_SCRIPT = r"""
section() { printf '\n===== %s =====\n' "$1"; }
section date; date; cat /proc/uptime
section "sing-box log"; logread -e sing-box 2>&1 | tail -n 150
section "kitewrt log"; logread -e kitewrtd 2>&1 | tail -n 150
section "procd"; logread -e procd 2>&1 | grep -i sing | tail -n 20
section "processes"; ps 2>&1 | grep -E 'sing-box|kitewrt|python' | grep -v grep
section "tproxy listener (port 7895 = 1ED7)"; grep -i ':1ED7 ' /proc/net/tcp /proc/net/tcp6
section "mangle"; iptables -w 5 -t mangle -S 2>&1 | grep -v -- '-A kitewrt_bypass'
section "nat prerouting"; iptables -w 5 -t nat -S PREROUTING 2>&1
section "ip rule"; ip rule 2>&1
section "sing-box files"; ls -la --full-time /etc/sing-box/ 2>&1 || ls -la /etc/sing-box/
section "rule-sets"; ls -la /etc/kitewrt/data/rulesets/ 2>&1
section "routes"; ip route 2>&1
section "conntrack"; cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max 2>&1
section "memory"; free 2>&1
"""


def diag_dir(base: str | Path) -> Path:
    return Path(base) / "diag"


def _host(value: Any) -> str:
    # Names/addresses only: never copy a URL, credentials or arbitrary config text.
    return (
        value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", value) else ""
    )


async def _dial(host: str, port: int, *, server_name: str = "") -> dict[str, Any]:
    writer = None
    try:
        kwargs: dict[str, Any] = {}
        if server_name:
            kwargs.update(ssl=ssl.create_default_context(), server_hostname=server_name)
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, **kwargs), timeout=1.5
        )
        source = writer.get_extra_info("sockname")
        return {"status": "connected", "source_ip": source[0] if source else ""}
    except (OSError, asyncio.TimeoutError) as exc:
        # Exception strings can contain data controlled by a peer. Keep only type.
        return {"status": "failed", "error": type(exc).__name__}
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=0.2)


async def _connection_context(
    state, clash, selector: str, config_path: str | Path, *, probe_network: bool = False
) -> bytes:
    from kitewrt.singbox.config import active_tag

    intended = active_tag(state)
    info: dict[str, Any] = {"vpn_on": state.vpn_on, "applying": state.applying}
    # Read only a bounded local config and whitelist the fields written to disk.
    try:
        with Path(config_path).open("rb") as source:
            raw = source.read((4 << 20) + 1)
        if len(raw) > 4 << 20:
            raise ValueError("config too large")
        outbounds = json.loads(raw).get("outbounds", [])
        out = next((o for o in outbounds if o.get("tag") == intended), {})
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        info["config_error"] = type(exc).__name__
        out = {}
    info["configured_endpoint"] = {
        "protocol": _host(out.get("type")),
        "address": _host(out.get("server")),
        "port": out.get("server_port") if type(out.get("server_port")) is int else None,
    }
    try:
        actual = await asyncio.wait_for(clash.current(selector), timeout=0.75)
        expected = intended if state.vpn_on and intended else "direct"
        info["selector_matches_intent"] = actual == expected
        info["selector_is_direct"] = actual == "direct"
    except Exception as exc:
        info["selector_error"] = type(exc).__name__
    endpoint = info["configured_endpoint"]
    # Probes run only on node-unreachable snapshots, against the selected public
    # IP already on disk. No DNS lookups, UDP guesses or additional destinations.
    try:
        address = ipaddress.ip_address(endpoint["address"])
        public = address.is_global and not address.is_multicast
    except ValueError:
        public = False
    if not probe_network or state.applying or not state.vpn_on:
        info["tcp_probe"] = {"status": "skipped", "reason": "not an idle node-unreachable incident"}
    elif not public or not endpoint["port"] or not 0 < endpoint["port"] < 65536:
        info["tcp_probe"] = {"status": "skipped", "reason": "no public pinned endpoint"}
    elif out.get("type") not in {"vless", "vmess", "trojan", "shadowtls"}:
        info["tcp_probe"] = {"status": "skipped", "reason": "not a TCP protocol"}
    else:
        info["tcp_probe"] = await _dial(endpoint["address"], endpoint["port"])
        tls = out.get("tls") or {}
        name = _host(tls.get("server_name"))
        if info["tcp_probe"]["status"] == "connected" and tls.get("enabled") and name:
            # Generic TLS only: not a Reality authentication or a client VPN test.
            info["unauthenticated_tls_probe"] = await _dial(
                endpoint["address"], endpoint["port"], server_name=name
            )
    if probe_network and state.vpn_on and not state.applying and intended:
        try:
            # Reuse the existing outbound URL-test, not a new destination or a
            # background schedule. Record unknown separately from failed transit.
            probe = await asyncio.wait_for(
                clash.probe_delay(intended, timeout_ms=1000), timeout=1.5
            )
            info["proxy_probe"] = {"reachable": probe.reachable, "delay_ms": probe.delay_ms}
        except Exception as exc:
            info["proxy_probe"] = {"reachable": None, "error": type(exc).__name__}
    return ("\n===== connection context =====\n" + json.dumps(info, sort_keys=True) + "\n").encode()


async def snapshot(
    directory: str | Path,
    reason: str,
    *,
    timeout_s: float = 20.0,
    state=None,
    clash=None,
    selector: str = "select",
    config_path: str | Path = "/etc/sing-box/config.json",
) -> Path | None:
    """Once-per-incident evidence, under one shared time budget. Never raises."""
    try:
        started = asyncio.get_running_loop().time()
        context = b""
        if state is not None:
            try:
                context = await asyncio.wait_for(
                    _connection_context(
                        state,
                        clash,
                        selector,
                        config_path,
                        probe_network=reason == "watchdog: node_unreachable",
                    ),
                    timeout=min(6.0, timeout_s / 2),
                )
            except Exception:
                context = b"\n===== connection context =====\n(unavailable within budget)\n"
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            "sh",
            "-c",
            _SCRIPT,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        remaining = max(0.01, timeout_s - (asyncio.get_running_loop().time() - started))
        try:
            out, _ = await wait_process(proc, communicate(proc), remaining, process_group=True)
        except (asyncio.TimeoutError, OutputLimitError):
            out = b"(snapshot exceeded its time/output budget)\n"
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        # Private from creation, with unique names even for simultaneous faults.
        fd, name = tempfile.mkstemp(prefix=stamp + "-", suffix=".txt", dir=d)
        path = Path(name)
        with os.fdopen(fd, "wb") as dest:
            dest.write(f"kitewrt diagnostic snapshot\nreason: {reason}\n".encode())
            dest.write(context)
            dest.write(out or b"")
        _prune(d)
        logger.warning("diagnostic snapshot written: %s (%s)", path, reason)
        return path
    except Exception:
        logger.warning("diagnostic snapshot failed", exc_info=True)
        return None


def _prune(d: Path) -> None:
    snaps = sorted(d.glob("*.txt"))
    for old in snaps[:-KEEP]:
        with contextlib.suppress(OSError):
            old.unlink()
