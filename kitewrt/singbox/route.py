"""sing-box `route` block builder.

kitewrt ships NO geo data or block-lists — only the wrapper. The baseline keeps
private/LAN traffic direct and proxies everything else; any country/geo split
is opt-in, supplied by the user as routing rules + their own rule-sets (which
sing-box fetches remotely at runtime). See docs/rules-format.md.
"""

from __future__ import annotations

from typing import Any

# In user-supplied rules, `outbound: "proxy"` (and `download_detour: "proxy"`
# on a rule-set) is a stable alias for "via the VPN" — rewritten to the real
# selector tag at build time, so a config stays portable without baking in
# kitewrt's internal selector tag name.
PROXY_ALIAS = "proxy"


def default_route_rules() -> list[dict[str, Any]]:
    """The bundled fallback when the user supplies no rules: nothing extra —
    private/LAN already goes direct (baseline), everything else is proxied via
    `final`. No geo, no country assumptions."""
    return []


def build_route(
    user_rules: list[dict[str, Any]] | None,
    user_rule_sets: list[dict[str, Any]] | None,
    selector_tag: str,
) -> dict[str, Any]:
    """Assemble the full `route` block.

    `user_rules` are sing-box-native route rules (validated upstream); they run
    after the baseline (sniff + DNS hijack + private→direct). `user_rule_sets`
    are the rule-set *definitions* those rules reference — typically
    `type: remote` so sing-box downloads the geo/block data itself (kitewrt
    bundles none). When both are empty the result is a plain full tunnel:
    private direct, everything else via the selector.
    """
    rules: list[dict[str, Any]] = [
        # Recover the destination domain (TLS SNI / HTTP Host) so domain and
        # rule-set rules can match. We deliberately do NOT add a `resolve`
        # action: tun capture delivers every packet with its real destination
        # IP intact, so geoip/ip_is_private match the original IP directly.
        # `resolve` would re-resolve the *sniffed* SNI and overwrite that
        # destination — which silently breaks a nested proxy tunnel (e.g. an
        # on-device Reality VPN) whose camouflage SNI is a decoy host.
        {"action": "sniff"},
        # Own LAN DNS: LAN clients' port-53 traffic is pulled into the tun by
        # auto_route, sniff tags it as the `dns` protocol, and this hijacks it
        # into the internal resolver (foreign over DoH, direct via the local
        # resolver). Must precede ip_is_private (DNS to the router is a private
        # dst that would otherwise route direct, unhijacked).
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]
    chosen = user_rules if user_rules else default_route_rules()
    rules.extend(_resolve_proxy_alias(rule, selector_tag) for rule in chosen)

    route: dict[str, Any] = {
        "rules": rules,
        "final": selector_tag,
        "auto_detect_interface": True,
    }
    if user_rule_sets:
        route["rule_set"] = [_resolve_detour_alias(rs, selector_tag) for rs in user_rule_sets]
    return route


def _resolve_proxy_alias(rule: dict[str, Any], selector_tag: str) -> dict[str, Any]:
    """Rewrite `outbound: "proxy"` to the real selector tag; pass through else."""
    if rule.get("outbound") == PROXY_ALIAS:
        return {**rule, "outbound": selector_tag}
    return rule


def _resolve_detour_alias(rule_set: dict[str, Any], selector_tag: str) -> dict[str, Any]:
    """Rewrite a remote rule-set's `download_detour: "proxy"` to the selector,
    so the geo data downloads through the VPN (it's typically blocked direct).
    Pass through any explicit detour or none."""
    if rule_set.get("download_detour") == PROXY_ALIAS:
        return {**rule_set, "download_detour": selector_tag}
    return rule_set
