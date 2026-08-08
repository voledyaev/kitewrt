# Offline install artifacts

The installer downloads **three** things *on the router*: the sing-box binary
and the **uv** binary (both from GitHub), and the Python deps (from PyPI). Some
ISPs block GitHub — and occasionally PyPI — from the router's WAN, which makes
those downloads fail.

This folder is the escape hatch. Download the files on a machine that *can*
reach them (e.g. your laptop, behind a working VPN), drop them here, and the
installer uses them instead of fetching — no auto-bundling, it just checks
whether the file is present first. Anything you don't provide is still
downloaded the normal way.

**If GitHub is what's blocked, you need both tarballs, not just sing-box.** uv
is fetched from GitHub too, at step `[2/6]` — *before* sing-box — so pre-placing
only the sing-box tarball moves the failure earlier rather than fixing it. This
is the single most common mistake with this folder.

Files dropped here are git-ignored (except this README).

## What to know first: your router's arch

The installer prints it during `[1/6]` (`CPU arch: arm64`), or:

```sh
ssh root@192.168.8.1 uname -m      # aarch64 → arm64, x86_64 → amd64, armv7l → armv7
```

Substitute your own router address everywhere below; `192.168.8.1` is just the
GL.iNet default.

| `uname -m` | arch token | sing-box file | uv file |
|---|---|---|---|
| `aarch64` | `arm64` | `sing-box-<VER>-linux-arm64.tar.gz` | `uv-aarch64-unknown-linux-musl.tar.gz` |
| `x86_64` | `amd64` | `sing-box-<VER>-linux-amd64.tar.gz` | `uv-x86_64-unknown-linux-musl.tar.gz` |
| `armv7l` | `armv7` | `sing-box-<VER>-linux-armv7.tar.gz` | `uv-armv7-unknown-linux-musleabihf.tar.gz` |

Names must match **exactly** — the installer looks for that filename, it does
not glob. Leave both packed as `.tar.gz`; they're extracted on the router.

Both tarballs are checked against a pinned SHA-256 before anything is executed,
whether they came from GitHub or from this folder. A file that doesn't match
aborts the install; there is no override. So if you fetch them by hand, fetch
them from the official releases — a mirror with a repacked tarball will fail.

## sing-box (the usual blocker — GitHub)

The pinned version is `SINGBOX_VERSION` in [`installer/steps.py`](../steps.py)
(currently **1.13.16**). For a Flint 2 / any aarch64 router:

```sh
curl -fLO https://github.com/SagerNet/sing-box/releases/download/v1.13.16/sing-box-1.13.16-linux-arm64.tar.gz
mv sing-box-1.13.16-linux-arm64.tar.gz installer/artifacts/
```

## uv (also GitHub)

The pinned version is `UV_VERSION` in [`installer/steps.py`](../steps.py)
(currently **0.12.3**). uv is what installs the daemon's Python deps on the
router — it replaced pip, so this is not optional. Same arch, `musl` target:

```sh
curl -fLO https://github.com/astral-sh/uv/releases/download/0.12.3/uv-aarch64-unknown-linux-musl.tar.gz
mv uv-aarch64-unknown-linux-musl.tar.gz installer/artifacts/
```

uv is staged in `/tmp` and deleted once the deps are installed — it's a build
tool, not part of the runtime.

## Python deps (optional — only if PyPI is blocked too)

Put wheels in a `wheels/` subfolder here:

```
installer/artifacts/wheels/*.whl
```

The installer then runs `uv pip install --offline --find-links` against that
folder, so **every transitive dependency must be present** — resolve from the
checked-in lock export rather than a hand-written package list, which is where
this usually goes wrong:

**Do not type this command from memory — ask the probe for it.** It prints the
whole thing, filled in for the router it just looked at:

```sh
uv run kitewrt --probe root@192.168.8.1     # substitute your router's address
```

```
python: 3.11.14
arch: aarch64 (musl)
--
to build an offline wheel bundle, run this on your admin machine:
  uv run --no-project --python 3.11 --with pip pip download \
    --only-binary=:all: --platform musllinux_1_1_aarch64 \
    --python-version 3.11 -d installer/artifacts/wheels \
    -r installer/resources/requirements.txt
```

It needs nothing installed beyond SSH, and `python3` is put there by opkg at
the *start* of step `[2/6]`, before the PyPI download — so even a run that
failed at the download leaves it present.

Three things in that command are easy to get wrong, and each produces a bundle
that silently does not satisfy the router:

- **`--python-version` must match the router's.** `requirements.txt` is `uv
  export`'s output — every version pinned to what CI tested, every wheel hashed,
  with markers that select different pins per interpreter. OpenWrt 21.02 ships
  Python 3.9; 23.05 and 24.10 ship 3.11. A 3.9 bundle on a 3.11 router resolves
  a different set of pins and uv reports `unsatisfiable`, then falls back to
  PyPI — which is exactly what you were trying to avoid. Measured on 24.10.
- **`--platform` is `musllinux_1_1_<arch>`, not `_1_2`.** The tag has to match
  wheels that exist, and `pydantic-core` — the only compiled dependency, so the
  only one that can fail — publishes `musllinux_1_1` and nothing newer.
- **pip has to run *under* that Python, and with `--no-project`.**
  Run under your own interpreter it evaluates the markers against *that* one and
  resolves a set the router cannot use. `uv` itself has no `download`
  subcommand, so this step is pip's.

Get this wrong and the install stops with *"the daemon's deps don't import
under the router's python"* — pydantic-core is a compiled extension tagged for
exactly one arch and one Python version. If in doubt, leave `wheels/` empty and
let the router fetch from PyPI; the installer also falls back to PyPI on its own
when a bundle doesn't satisfy the router.

## What this can't offline-ize

`python3` itself comes from the **OpenWrt opkg feed**, as do `ip-full`,
`iptables-mod-tproxy`, `ipset`, `curl` and `kmod-tcp-bbr` — there's no escape
hatch here for any of them. If that feed is unreachable from the router, the
install can't proceed. OpenWrt / GL.iNet feeds are usually reachable even where
GitHub is blocked, which is exactly why this folder covers GitHub and PyPI only.
