"""Pydantic request schemas for the HTTP API.

Kept separate from the route handlers so they're easy to find and easy to
import from tests. Response models live in `kitewrt.state` (the `Data` type
is what every successful endpoint returns).
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, Field, field_validator

from kitewrt.vless import NODE_SCHEMES

MAX_LABEL_LEN = 100
MAX_SOURCE_LEN = 4096
MAX_DOH_URL_LEN = 2048


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
        if not v.startswith(("http://", "https://", *NODE_SCHEMES)):
            raise ValueError(
                "source must start with http(s):// or a node URI "
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

    url: str | None = None


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
            # IPv6 literal — the data plane is IPv4-only (v4 tun + ipv4_only).
            raise ValueError("direct DNS must be an IPv4 resolver (the data plane is IPv4-only)")
        # Must be an IPv4 literal: this resolver bootstraps name resolution
        # (it's the default_domain_resolver), so a hostname here is circular.
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(
                "direct DNS must be an IPv4 resolver address, not a hostname"
            ) from None
        # And it must not point at the router itself: a loopback / 0.0.0.0
        # resolver loops through the tun's DNS hijack and deadlocks every lookup
        # (this 0-byte'd the VPN on the first deploy).
        if ip.is_loopback or ip.is_unspecified:
            raise ValueError(
                "direct DNS must not be the router's own resolver "
                "(loopback / 0.0.0.0 loops through the tunnel and deadlocks DNS)"
            )
        return v
