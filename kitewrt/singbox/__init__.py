"""sing-box data-plane support.

These modules generate a complete sing-box configuration from kitewrt's state
and talk to its Clash API. The setup is the one proven on the Flint 2
(OpenWrt/fw3): a single sing-box process with two inbounds — a `tproxy` one,
whose LAN capture `kitewrt.divert` installs and owns, and a loopback `http`
proxy the daemon sends its own requests through, because router-origin traffic
takes OUTPUT and the capture never sees it. sing-box is handed established
sockets and knows nothing about netfilter. Server switching and on/off go
through the selector outbound via live Clash API calls (no process restart).

All builders here are pure (state in, dict out) so they're fully unit-testable
without a router. I/O and process control live in `service.py` / `clash.py`.
"""
