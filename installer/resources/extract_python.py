"""Extract a checksummed standalone Python without trusting archive paths.

Runs under the router's bootstrap Python (including 3.9). Symlinks are needed
for python3/libpython; directory-link traversal and special files are refused.
"""

from __future__ import annotations

import os
import posixpath
import sys
import tarfile
from pathlib import Path

MAX_BYTES = 512 << 20


def extract(archive: str, destination: str) -> None:
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if not m.name.startswith("python/share/")]
        if len(members) > 100000 or sum(m.size for m in members) > MAX_BYTES:
            raise ValueError("Python archive exceeds extraction limits")
        links = set()
        for member in members:
            name = posixpath.normpath(member.name)
            if (
                member.name.startswith("/")
                or name != member.name.rstrip("/")
                or not (name == "python" or name.startswith("python/"))
            ):
                raise ValueError("unsafe Python archive path")
            if member.issym():
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(name), member.linkname)
                )
                if member.linkname.startswith("/") or not target.startswith("python/"):
                    raise ValueError("unsafe Python archive link")
                links.add(name)
            elif not (member.isfile() or member.isdir()):
                raise ValueError("unsupported Python archive member")
        for member in members:
            if any(str(parent) in links for parent in Path(member.name).parents):
                raise ValueError("Python archive traverses a symlink")
        # No pre-existing files, all ancestors are ordinary directories, and
        # only validated in-tree symlinks may be created (after regular files).
        for member in members:
            if not member.issym():
                tar.extract(member, root, filter="data") if sys.version_info >= (
                    3,
                    12,
                ) else tar.extract(member, root)
        for member in members:
            if member.issym():
                path = root / member.name
                path.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, path)


if __name__ == "__main__":
    extract(sys.argv[1], sys.argv[2])
