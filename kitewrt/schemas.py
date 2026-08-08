"""Pydantic request schemas for the HTTP API, plus the outgoing state payload.

Kept separate from the route handlers so they're easy to find and easy to
import from tests. `kitewrt.state.Data` is the on-disk model every state
endpoint answers from; `state_payload` below is what actually goes on the wire.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from kitewrt.state import Data, redact_state_dict
from kitewrt.vless import NODE_SCHEMES, unwrap_subscription_uri

MAX_LABEL_LEN = 100
MAX_SOURCE_LEN = 4096
MAX_DOH_URL_LEN = 2048
MAX_RULES_URL_LEN = 4096


# --- Outgoing state payload -------------------------------------------------


# Everything the parsed rules document contributes to `Data` scales with the
# document, and the UI renders none of it — only `.length` of each. Measured on
# the /api/state body, which the dashboard polls and which is also pushed over
# the WS on every state change (/api/health is 45 bytes / 0.56 ms for scale):
#
#     8640-network bypass list          147,363 B   4.27 ms p50
#     20000 inline domain_suffix        489,448 B   7.57 ms p50
#
# Neither is pathological: 8640 is one country's CIDR list, and 20000 domains is
# half the 1 MiB `fetch_url` cap. Sending counts instead pins the body at ~400 B
# whatever the document holds (measured 408 B / 1.99 ms and 404 B / 3.47 ms).
_BULK_AS_COUNT = {
    "rules": "rules_count",
    "rule_sets": "rule_sets_count",
    "rules_bypass_address": "rules_bypass_count",
}


def state_payload(snap: Data) -> dict[str, Any]:
    """The state snapshot as it leaves the daemon: per-server secrets stripped,
    and each bulk rules list replaced by its count (see `_BULK_AS_COUNT`).

    `exclude=` rather than popping the keys afterwards is what drops the
    *serialization* cost along with the bytes — pydantic never materializes the
    8640 strings, so the dump goes 0.126 ms → 0.002 ms. What remains is
    `State.snapshot()`'s deep copy, which still carries the lists.
    """
    data = snap.model_dump(mode="json", exclude=set(_BULK_AS_COUNT))
    for field, count_key in _BULK_AS_COUNT.items():
        data[count_key] = len(getattr(snap, field))
    # Redacted here, not only in the /api middleware, so the WS push — which
    # never passes through it — is covered by the same one function.
    return redact_state_dict(data)


class AddSubscriptionReq(BaseModel):
    label: str = ""
    source: str

    @field_validator("label")
    @classmethod
    def _label_size(cls, v: str) -> str:
        if len(v) > MAX_LABEL_LEN:
            raise ValueError(f"label is too long (max {MAX_LABEL_LEN} chars)")
        return v

    @field_validator("source")
    @classmethod
    def _source_shape(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("source is required")
        if len(v) > MAX_SOURCE_LEN:
            raise ValueError(f"source is too long (max {MAX_SOURCE_LEN} chars)")
        # A `sub://` wrapper is checked by what it DECODES to, so a non-http
        # scheme can't be smuggled past this guard inside the base64 blob. An
        # undecodable blob stays as-is and fails the check below.
        unwrapped, _ = unwrap_subscription_uri(v)
        if not unwrapped.startswith(("http://", "https://", *NODE_SCHEMES)):
            raise ValueError(
                "source must start with http(s)://, sub:// or a node URI "
                "(vless / hysteria2 / hysteria / ss / vmess / trojan / tuic)"
            )
        return v


class PatchSubscriptionReq(BaseModel):
    label: str = ""

    @field_validator("label")
    @classmethod
    def _size(cls, v: str) -> str:
        if len(v) > MAX_LABEL_LEN:
            raise ValueError(f"label is too long (max {MAX_LABEL_LEN} chars)")
        return v


class ServerSelectReq(BaseModel):
    """Both null → deselect (set active to None)."""

    subscription_id: str | None = None
    server_id: str | None = None


class ToggleReq(BaseModel):
    on: bool


class RulesURLReq(BaseModel):
    """`url` of null/"" → clear and fall back to bundled default rules."""

    url: str | None = Field(default=None, max_length=MAX_RULES_URL_LEN)

    @field_validator("url")
    @classmethod
    def _scheme(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return ""  # explicit clear → bundled default rules
        # Same http(s) allowlist as a subscription source: the daemon fetches
        # this URL, so don't rely solely on httpx to reject odd schemes
        # (file://, ftp://, …). The SSRF guard still runs in fetch_url.
        if not v.startswith(("http://", "https://")):
            raise ValueError("rules URL must start with http:// or https://")
        return v


class DnsConfigReq(BaseModel):
    """Update either resolver; a field left None is unchanged.

    `doh_url` — DoH endpoint for proxy-routed (foreign) domains.
    `direct_dns` — plain-UDP resolver IP for direct (home/regional) domains;
    empty string means "use the system default" (sing-box `type: local`).
    """

    doh_url: str | None = Field(default=None, max_length=MAX_DOH_URL_LEN)
    direct_dns: str | None = Field(default=None, max_length=255)

    @field_validator("doh_url")
    @classmethod
    def _must_be_https(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("DoH URL cannot be empty")
        if not v.startswith("https://"):
            raise ValueError("DoH URL must start with https://")
        host = urlparse(v).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            # sing-box wires this as `route.default_domain_resolver`, whose
            # server must be an IP literal — a hostname there needs resolving
            # to be resolved. sing-box rejects the config outright ("missing
            # domain resolver for domain server address"), and because the
            # value persists in state.json, EVERY later apply fails too. Worse,
            # after a reboot `apply()` returns before `ensure_capture()`, so
            # following `sweep()` nothing reinstalls the capture: the UI reads
            # "on", sing-box looks healthy, and the whole LAN goes direct.
            raise ValueError(
                f"DoH URL must use an IP address, not a hostname ({host!r}): it is also "
                "what resolves the proxy servers' own domains, so a name here cannot "
                "be resolved. Try https://1.1.1.1/dns-query"
            ) from None
        return v

    @field_validator("direct_dns")
    @classmethod
    def _direct_shape(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return ""  # empty → system default (type: local)
        # A bare resolver IP/host — no scheme, path, or port.
        if "://" in v or "/" in v or " " in v:
            raise ValueError(f"direct DNS must be a bare resolver IP/host: {v!r}")
        if ":" in v:
            # IPv6 literal — the data plane is IPv4-only: `divert` speaks
            # iptables and not ip6tables, and the DNS block is `ipv4_only`.
            raise ValueError("direct DNS must be an IPv4 resolver (the data plane is IPv4-only)")
        # Must be an IPv4 literal. NOT because it is the domain resolver — it
        # stopped being that when `dns-bootstrap` took over
        # `route.default_domain_resolver` (see singbox/config.py) — but because
        # `_direct_server` emits it as a typed `udp` server, whose `server` field
        # sing-box expects to be an address, and because a hostname here would
        # have to be resolved by the very block it is a member of.
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(
                "direct DNS must be an IPv4 resolver address, not a hostname"
            ) from None
        # And it must not point at the router itself. Under the tun inbound
        # this deadlocked every lookup — the router's own resolver forwarded
        # upstream, `hijack-dns` pulled that straight back into sing-box — and
        # it 0-byte'd the VPN on the first deploy. That mechanism is gone with
        # the tun: the capture hooks PREROUTING only, and dnsmasq's upstream
        # queries are router-origin, so they take OUTPUT and are never captured.
        # **Not re-tested under TPROXY**; kept because sending regional lookups
        # back through the router's own forwarder hands them to the ISP resolver
        # and defeats the point of setting a regional one. (The rejection message
        # below still names the tun-era mechanism — it is user-facing copy, left
        # for the UI pass that owns `web/src/components/Settings.tsx`, which
        # repeats it verbatim.)
        if ip.is_loopback or ip.is_unspecified:
            raise ValueError(
                "direct DNS must not be the router's own resolver "
                "(loopback / 0.0.0.0 loops through the tunnel and deadlocks DNS)"
            )
        return v
