#!/usr/bin/env python3
"""Validate KiteWrt-generated sing-box configs against a real `sing-box check`.

The unit tests assert config *shape* (dict keys) but never run the actual
binary, so a shape that drifts from what sing-box 1.13.x accepts (e.g. the 1.14
DNS-format removal the code already anticipates) would pass tests yet be rejected
on the router — and a rejected *first* apply leaves the LAN behind strict_route.

This script builds one config per protocol plus rules / DNS / off variants and
runs `sing-box check` on each, exiting non-zero if any is rejected. Runnable
locally (`python scripts/check_configs.py`) and in CI after installing the
pinned sing-box. Finds the binary via $SING_BOX_BIN or PATH.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# How long to let a smoke `run` stay up before killing it. A config that starts
# cleanly runs until this timeout (→ pass); a bad one FATALs and exits first.
_SMOKE_SECONDS = 2.5

# Make `kitewrt` importable when run from the repo root without an install.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kitewrt.singbox.config import build_config  # noqa: E402
from kitewrt.state import ActiveServerRef, Data, DnsState, Subscription  # noqa: E402
from kitewrt.vless import Server  # noqa: E402

# A real x25519 public key (from `sing-box generate reality-keypair`) so the
# reality outbound passes validation — sing-box checks the key is a valid curve
# point before it ever looks at later outbounds.
REALITY_PBK = "NL6IX8y4cbP7_eGgXUUelTBDDv_XLSWuiqwam_Vx8hM"


def _server(type_: str, **params: str) -> Server:
    common = {
        "id": f"{type_}.example:8443",
        "name": type_.upper(),
        "country": "DE",
        "type": type_,
        "host": f"{type_}.example",
        "port": 8443,
    }
    return Server(**common, **params)  # type: ignore[arg-type]


def _reality() -> Server:
    return _server(
        "vless",
        uuid="11111111-2222-3333-4444-555555555555",
        params={
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": "storage.example.com",
            "fp": "firefox",
            "pbk": REALITY_PBK,
            "sid": "abcd1234",
            "type": "tcp",
        },
    )


def _snap(
    servers: list[Server],
    *,
    rules=None,
    rule_sets=None,
    dns: DnsState | None = None,
    vpn_on=True,
) -> Data:
    sub = Subscription(id="s1", label="ex", source="https://x", fetched_at="t", servers=servers)
    ref = ActiveServerRef(subscription_id="s1", server_id=servers[0].id) if servers else None
    return Data(
        subscriptions=[sub] if servers else [],
        active_server=ref,
        vpn_on=vpn_on,
        rules=rules or [],
        rule_sets=rule_sets or [],
        dns=dns or DnsState(),
    )


def cases() -> dict[str, Data]:
    ws_vless = _server(
        "vless",
        uuid="11111111-2222-3333-4444-555555555555",
        params={
            "security": "tls",
            "type": "ws",
            "path": "/r",
            "host": "cdn.example",
            "sni": "cdn.example",
        },
    )
    hy2 = _server("hysteria2", password="s3cr3t", params={"sni": "fi.example", "insecure": "1"})
    trojan = _server("trojan", password="p", params={"sni": "t.example"})
    tuic = _server(
        "tuic",
        uuid="11111111-2222-3333-4444-555555555555",
        password="p",
        params={"sni": "u.example"},
    )
    ss = _server("shadowsocks", method="aes-256-gcm", password="p")
    vmess = _server(
        "vmess", uuid="11111111-2222-3333-4444-555555555555", params={"net": "ws", "path": "/v"}
    )
    user_rules = [
        {"domain_suffix": ["ads.example"], "outbound": "block"},
        {"domain": ["x.example"], "outbound": "proxy"},
        {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"},
    ]
    return {
        "reality-vision-tcp": _snap([_reality()]),
        "vless-ws-tls": _snap([ws_vless]),
        "hysteria2": _snap([hy2]),
        "trojan": _snap([trojan]),
        "tuic": _snap([tuic]),
        "shadowsocks": _snap([ss]),
        "vmess-ws": _snap([vmess]),
        "mixed-with-rules": _snap([_reality(), hy2], rules=user_rules),
        "direct-dns-ip": _snap([_reality()], dns=DnsState(direct_dns="9.9.9.9")),
        "direct-dns-host-port": _snap([_reality()], dns=DnsState(direct_dns="9.9.9.9:5353")),
        "vpn-off-empty": _snap([], vpn_on=False),
        "rules-and-rule-sets": _snap(
            [_reality()],
            rules=[{"rule_set": ["geo-home"], "outbound": "direct"}],
            # Inline, not remote: the smoke `run` must not need the network.
            rule_sets=[
                {
                    "tag": "geo-home",
                    "type": "inline",
                    "rules": [{"ip_cidr": ["203.0.113.0/24"]}],
                }
            ],
        ),
    }


def _smoke_variant(cfg: dict) -> dict:
    """A copy of `cfg` that a real `sing-box run` can start unprivileged in CI.

    The tun inbound needs CAP_NET_ADMIN + /dev/net/tun (absent on a CI runner),
    and would fail *before* service init — masking the errors we want to catch.
    Swap it for a loopback `mixed` inbound so `run` reaches DNS/outbound/route
    service start (where a bad server detour, resolver ref, etc. surface). Drop
    `experimental` (cache-file lock + clash-api port bind) — not needed to
    exercise those services, and it avoids port/lock contention across cases.
    """
    cfg = copy.deepcopy(cfg)
    cfg["inbounds"] = [{"type": "mixed", "tag": "smoke", "listen": "127.0.0.1", "listen_port": 0}]
    cfg.pop("experimental", None)
    return cfg


def _smoke_run(binary: str, cfg: dict, tmp: str, name: str) -> str | None:
    """Actually `run` the config briefly; return an error string, or None if it
    started cleanly. Catches the class `sing-box check` misses: config is valid
    but a *service* refuses to start (e.g. a DNS server `detour` sing-box rejects
    only at runtime — the bug this guard exists for)."""
    path = Path(tmp) / f"{name}.smoke.json"
    path.write_text(json.dumps(_smoke_variant(cfg), indent=2))
    try:
        proc = subprocess.run(
            [binary, "run", "-c", str(path)],
            capture_output=True,
            text=True,
            timeout=_SMOKE_SECONDS,
        )
        # Exited on its own within the window → a start failure (a healthy run
        # would still be up and get killed by the timeout below).
        return " ".join((proc.stderr or proc.stdout).split()) or f"exited rc={proc.returncode}"
    except subprocess.TimeoutExpired as e:
        # Still running when we killed it = clean start. Scan the captured output
        # anyway in case a service FATAL'd without exiting the process.
        raw = e.stderr or e.output or b""
        out = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        if "FATAL" in out or "start service" in out:
            return " ".join(out.split())
        return None


def main() -> int:
    binary = os.environ.get("SING_BOX_BIN") or shutil.which("sing-box")
    if not binary:
        print("ERROR: sing-box binary not found (set $SING_BOX_BIN or put it on PATH)")
        return 2

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, snap in cases().items():
            cfg = build_config(snap)
            path = Path(tmp) / f"{name}.json"
            path.write_text(json.dumps(cfg, indent=2))
            proc = subprocess.run(
                [binary, "check", "-c", str(path)],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                failures += 1
                print(f"  FAIL {name} (check): {' '.join((proc.stderr or proc.stdout).split())}")
                continue
            err = _smoke_run(binary, cfg, tmp, name)
            if err:
                failures += 1
                print(f"  FAIL {name} (run): {err}")
            else:
                print(f"  ok   {name}")

    print(f"\n{len(cases())} configs checked (check + run), {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
