"""Client for sing-box's Clash API (the experimental.clash_api controller).

This is how kitewrt switches servers and toggles on/off at runtime: a `PUT`
against the `selector` outbound changes the active server live — no process
restart, no firewall flush, existing connections to the old server just drain.
Live switching like this is why structural reloads stay rare.

The controller has no secret (we configure `external_controller` only), so
requests are unauthenticated and local-only (127.0.0.1).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

# Default URL delay-test target: a tiny 204-no-content endpoint reachable
# worldwide. The probe measures the full path (ISP → server → target), not just
# latency to the server's edge — so a node that connects fast but proxies poorly
# scores honestly. gstatic's generate_204 is the de-facto standard (clash, SR).
DEFAULT_DELAY_URL = "http://www.gstatic.com/generate_204"


class ClashError(RuntimeError):
    """A Clash API call failed (sing-box down, unknown proxy/selector, etc.)."""


class ClashClient:
    """Thin async wrapper over the Clash API.

    Takes an httpx.AsyncClient so tests can inject a MockTransport. `base_url`
    points at the controller (matching `CLASH_API_ADDR` in the config).
    """

    def __init__(self, client: httpx.AsyncClient, base_url: str = "http://127.0.0.1:9090"):
        self._client = client
        self._base = base_url.rstrip("/")

    async def select(self, selector: str, name: str) -> None:
        """Switch `selector` to outbound `name` (the live server switch).

        `name` goes in the body, not the URL, so composite tags with `/` and
        `:` (e.g. "sub-1/host:443") need no escaping. Expects 204.
        """
        try:
            r = await self._client.put(f"{self._base}/proxies/{selector}", json={"name": name})
        except httpx.HTTPError as exc:
            raise ClashError(f"clash select failed: {exc}") from exc
        if r.status_code != 204:
            raise ClashError(f"clash select {selector}→{name}: HTTP {r.status_code} {r.text[:200]}")

    async def current(self, selector: str) -> str:
        """Return the selector's currently-selected outbound (`now`)."""
        try:
            r = await self._client.get(f"{self._base}/proxies/{selector}")
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ClashError(f"clash current failed: {exc}") from exc
        return r.json().get("now", "")

    async def connections(self) -> dict[str, Any]:
        """Snapshot from the Clash `/connections` endpoint: cumulative byte
        totals (`downloadTotal`/`uploadTotal`), the active connection list, and
        `memory`. Used for live UI metrics (the UI derives rates from deltas)."""
        try:
            r = await self._client.get(f"{self._base}/connections")
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise ClashError(f"clash connections failed: {exc}") from exc
        data: dict[str, Any] = r.json()
        return data

    async def proxies(self) -> dict[str, Any]:
        """The Clash `/proxies` map (outbound tag → info), or {} if unreachable.

        Used after a reload to confirm the per-outbound entries are registered
        before delay-testing: sing-box answers `/version` (and `/proxies/select`)
        a beat before every individual outbound appears, so a delay-test fired
        immediately post-restart would 404 on nodes that simply aren't ready yet.
        """
        try:
            r = await self._client.get(f"{self._base}/proxies")
            r.raise_for_status()
        except httpx.HTTPError:
            return {}
        data = r.json()
        return data.get("proxies", {}) if isinstance(data, dict) else {}

    async def delay(
        self, name: str, *, url: str = DEFAULT_DELAY_URL, timeout_ms: int = 5000
    ) -> int | None:
        """URL delay-test the `name` outbound: HTTP RTT (ms) through that proxy
        to `url`, or None if it failed/timed out (unreachable, handshake error).

        sing-box opens a real connection *through* the proxy and times the
        round-trip, so this reflects the end-to-end path the user's traffic
        takes — a far better "which server actually works from here" signal than
        a TCP-connect to the server's edge. The HTTP client's own timeout is set
        above `timeout_ms` so the server-side test is what bounds the call.
        """
        path = quote(name, safe="")  # composite tags carry '/' and ':'
        try:
            r = await self._client.get(
                f"{self._base}/proxies/{path}/delay",
                params={"url": url, "timeout": timeout_ms},
                timeout=timeout_ms / 1000 + 3,
            )
        except httpx.HTTPError:
            return None
        if r.status_code != 200:
            return None  # non-200 → the node failed the test (timeout/refused)
        try:
            return int(r.json().get("delay"))
        except (ValueError, TypeError):
            return None

    async def healthy(self) -> bool:
        """True when the controller answers — used by the watchdog to detect a
        wedged sing-box (process up but API unresponsive)."""
        try:
            r = await self._client.get(f"{self._base}/version")
            return r.status_code == 200
        except httpx.HTTPError:
            return False
