# Offline install artifacts

The installer normally downloads two things **on the router**: the sing-box
binary (from GitHub) and the Python deps (from PyPI). Some ISPs block GitHub
(and occasionally PyPI) from the router's WAN, which makes those downloads fail.

This folder is the escape hatch. Download the files on a machine that *can*
reach them (e.g. your laptop, behind a working VPN), drop them here, and the
installer uses them instead of fetching — no auto-bundling, it just checks
whether the file is present first. Anything you don't provide is still
downloaded the normal way, so you can offline-ize just sing-box, just the
wheels, or both.

Files dropped here are git-ignored (except this README).

## sing-box (the usual blocker — GitHub)

Drop the official release tarball, named **exactly** as GitHub publishes it:

```
sing-box-<VERSION>-linux-<GOARCH>.tar.gz
```

- `<VERSION>` is the pinned version — see `SINGBOX_VERSION` in `installer/steps.py`
  (currently **1.13.13**).
- `<GOARCH>` matches your router's CPU. The installer prints the exact name it
  wants during `[1/6]`; common ones:
  - GL.iNet Flint 2 / most aarch64 routers → `arm64`
  - 32-bit ARM (mvebu, ipq40xx) → `armv7`
  - x86-64 → `amd64`

Example for the Flint 2:

```sh
curl -fLO https://github.com/SagerNet/sing-box/releases/download/v1.13.13/sing-box-1.13.13-linux-arm64.tar.gz
mv sing-box-1.13.13-linux-arm64.tar.gz installer/artifacts/
```

The installer uploads the tarball and extracts it on the router — leave it
packed as `.tar.gz`.

## Python deps (optional — PyPI)

Only needed if PyPI is also blocked from the router. Put wheels in a `wheels/`
subfolder here:

```
installer/artifacts/wheels/*.whl
```

Download them **for the router's Python and platform**, which differs by OpenWrt
release — OpenWrt 21.02 ships Python 3.9, 22.03+ ships 3.10 — so resolve against
the right tag (musllinux, aarch64). From a machine with `pip`:

```sh
pip download --only-binary=:all: \
  --platform musllinux_1_2_aarch64 --python-version 3.10 \
  -d installer/artifacts/wheels \
  fastapi uvicorn websockets httpx pydantic eval_type_backport
```

(adjust `--python-version` / `--platform` to your router — check with
`kitewrt --probe root@<router>`). The installer runs `pip install --no-index`
against these, so every transitive dependency must be present in the folder.
If in doubt, leave this empty and let the router fetch from PyPI.

## What this can't offline-ize

`python3` / `python3-pip` themselves come from the **OpenWrt opkg feed**, which
has no escape hatch here — if that feed is blocked from the router, the install
can't proceed (only sing-box and the pip wheels can be pre-placed). OpenWrt/
GL.iNet feeds are usually reachable even where GitHub is blocked.
