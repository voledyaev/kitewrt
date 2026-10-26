"""Exercise the real installer on musl 1.1.24 without touching a router."""

from __future__ import annotations

import argparse
import hashlib
import platform
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from installer import steps


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]
    target = steps.PYTHON_TARGETS[arch]
    python_name = (
        f"cpython-{steps.PYTHON_VERSION}+{steps.PYTHON_BUILD}-{target}-install_only_stripped.tar.gz"
    )
    uv_name = steps.uv_artifact_name(arch)
    assert uv_name is not None
    with tempfile.TemporaryDirectory(prefix="kitewrt-runtime-") as temp:
        artifacts = args.artifacts or Path(temp)
        artifacts.mkdir(exist_ok=True, parents=True)
        for name, url, digest in [
            (
                python_name,
                f"https://github.com/astral-sh/python-build-standalone/releases/download/{steps.PYTHON_BUILD}/{python_name}",
                steps.PYTHON_SHA256[target],
            ),
            (
                uv_name,
                steps.UV_URL_TMPL.format(ver=steps.UV_VERSION, asset=uv_name),
                steps.UV_SHA256[steps.UV_TARGETS[arch]],
            ),
        ]:
            path = artifacts / name
            if not path.exists():
                with urllib.request.urlopen(url, timeout=120) as response, path.open("wb") as out:
                    while chunk := response.read(65536):
                        out.write(chunk)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("checksum mismatch: " + name)
        # Bootstrap is from the verified official archive. The production
        # installer is then exercised in its entirety, including its extractor,
        # checksum gates, runtime activation, wheel install and import smoke.
        code = """import asyncio
from installer import steps
from installer.ssh import LocalRouter
steps.REMOTE_APP='/labinstall'
steps.REMOTE_VENDOR='/labinstall/vendor'
steps.REMOTE_PYTHON='/labinstall/python/bin/python3'
async def main():
    router=LocalRouter()
    python=await steps.install_managed_python(router, ARCH, artifacts_dir='/artifacts')
    await steps.install_python_deps(router, ARCH, artifacts_dir='/artifacts', python=python)
    await router.run('PYTHONPATH=/repo:/labinstall/vendor '+python+' /repo/scripts/check_runtime_http.py',check=True)
    await router.run('PYTHONPATH=/labinstall/vendor '+python+' -c "import sys,ssl,fastapi,starlette; print(sys.version.split()[0],ssl.OPENSSL_VERSION,fastapi.__version__,starlette.__version__)"',check=True)
asyncio.run(main())
""".replace("ARCH", repr(arch))
        command = f"mkdir /candidate; tar xzf /artifacts/{python_name} -C /candidate; PATH=/candidate/python/bin:$PATH PYTHONPATH=/repo /candidate/python/bin/python3 -"
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--platform",
                "linux/" + arch,
                "-v",
                str(artifacts.resolve()) + ":/artifacts:ro",
                "-v",
                str(Path(__file__).resolve().parent.parent) + ":/repo:ro",
                "alpine:3.12",
                "sh",
                "-ec",
                command,
            ],
            input=code.encode(),
            check=True,
        )
    print("Managed Python + locked wheels passed on musl 1.1.24 (" + arch + ")")


if __name__ == "__main__":
    main()
