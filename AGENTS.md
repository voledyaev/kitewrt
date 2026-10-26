# Working on KiteWrt

KiteWrt is a neutral, open-source OpenWrt VPN orchestrator. Keep country-specific
routing and personal router credentials out of this public repository.

## Architecture and accepted decisions

- Python daemon + FastAPI, React/TypeScript UI in `web/`, bundled UI in `kitewrt/static/`;
  Mac-side installer in `installer/`. Keep daemon source compatibility with Python 3.9.
  New ARM64/x86-64 installs use pinned managed CPython under `/usr/lib/kitewrt`;
  keep firmware Python/libc intact. Legacy 3.9/3.10 dependency branches are not
  supported security baselines.
- The current data plane is TPROXY. Old TUN-era DNS-loop and throughput claims are
  superseded. Empty direct DNS intentionally means system/dnsmasq upstream; advanced
  overrides remain optional. Test changes against the current pinned sing-box.
- LAN is trusted; WAN is the security boundary. LAN-readable configuration is an
  accepted design, not a newly discovered vulnerability.
- VPN-on failure must fail closed with a useful emergency page. The user must still
  be able to switch VPN off and regain ordinary internet. Do not silently fail open.
- The guard is its own procd service. A dead upstream must not prevent sing-box
  binding listeners: rule-set download and cache recovery cannot depend on that node.
- Preserve generic ruleset placeholders, server-IP bypass for device-local VPN
  clients, explicit errors, bounded retries and watchdog backoff. Do not hide dead
  nodes or introduce centralized telemetry as an unsolicited improvement.
- Use synthetic fixture data for published screenshots; never the live router.
  The old screenshot harness is absent; see `docs/development.md` before
  capturing new images.
  Hue communicates state; keep the dashboard's safety claim from one source.

## Verification and delivery

Read `.github/workflows/` before changing CI or compatibility assumptions. Run the
relevant pytest tests, Ruff, Python 3.9 compatibility and generated-config checks;
verify the web build and bundled asset consistency for frontend changes.
Review new failure paths introduced by a fix, including VPN off and daemon death.
Router-destroying experiments belong in an available lab first. Live deployment
needs a deadman rollback and post-deploy checks. Old chat permissions are context,
not automatic authorization to touch the router in a new maintenance task.

Do not push or deploy merely for documentation migration. Verify live state
before relying on historical deployment reports. Keep credentials, private
continuity notes and chat archives outside the repository. Do not append
automatic AI coauthor or generator signatures to commit messages.
