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

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Make `kitewrt` importable when run from the repo root without an install.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kitewrt.singbox.config import build_config  # noqa: E402
from kitewrt.state import ActiveServerRef, Data, DnsState, Subscription  # noqa: E402
from kitewrt.vless import Server  # noqa: E402

# A real x25519 public key (from `sing-box generate reality-keypair`) so the
# reality outbound passes validation — sing-box checks the key is a valid curve
# point before it ever looks at later outbounds.
REALITY_PBK = "W0x-U75gtm9NgH6V8O-dtLxsAHLNVUKU4Z9LH6OTI0E"


def _server(type_: str, **params: str) -> Server:
    common = dict(
        id=f"{type_}.example:8443",
        name=type_.upper(),
        country="DE",
        type=type_,
        host=f"{type_}.example",
        port=8443,
    )
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


def _snap(servers: list[Server], *, rules=None, dns: DnsState | None = None, vpn_on=True) -> Data:
    sub = Subscription(id="s1", label="ex", source="https://x", fetched_at="t", servers=servers)
    ref = ActiveServerRef(subscription_id="s1", server_id=servers[0].id) if servers else None
    return Data(
        subscriptions=[sub] if servers else [],
        active_server=ref,
        vpn_on=vpn_on,
        rules=rules or [],
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
    }


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
            if proc.returncode == 0:
                print(f"  ok   {name}")
            else:
                failures += 1
                msg = " ".join((proc.stderr or proc.stdout).split())
                print(f"  FAIL {name}: {msg}")

    print(f"\n{len(cases())} configs checked, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
