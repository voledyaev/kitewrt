"""Check a built wheel carries every runtime resource shipped from the checkout."""

from __future__ import annotations

import sys
from pathlib import Path
from zipfile import ZipFile


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    resources = [root / "kitewrt/guard.sh"]
    for directory in ("kitewrt/static", "installer/resources"):
        resources.extend(
            p for p in (root / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts
        )
    with ZipFile(sys.argv[1]) as wheel:
        names = set(wheel.namelist())
        missing = [
            str(p.relative_to(root))
            for p in resources
            if p.relative_to(root).as_posix() not in names
        ]
    if missing:
        print("Missing runtime resources: " + ", ".join(missing))
        return 1
    print(f"Wheel includes all {len(resources)} runtime resources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
