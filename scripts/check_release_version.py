#!/usr/bin/env python3
"""Fail CI when VERSION, package metadata, and CHANGELOG are out of sync."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_ROOT = Path(__file__).resolve().parents[1]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    version = _read_text(_ROOT / "VERSION").strip()
    if not _VERSION_RE.fullmatch(version):
        _fail(f"VERSION must be x.y or x.y.z, got {version!r}")

    pyproject = tomllib.loads(_read_text(_ROOT / "pyproject.toml"))
    py_version = str(pyproject["project"]["version"]).strip()
    if py_version != version:
        _fail(f"pyproject.toml version {py_version!r} != VERSION {version!r}")

    package = json.loads(_read_text(_ROOT / "web-vue" / "package.json"))
    package_version = str(package.get("version") or "").strip()
    if package_version != version:
        _fail(f"web-vue/package.json version {package_version!r} != VERSION {version!r}")

    lock = json.loads(_read_text(_ROOT / "web-vue" / "package-lock.json"))
    lock_version = str(lock.get("version") or "").strip()
    packages = lock.get("packages")
    root_pkg = packages.get("") if isinstance(packages, dict) else {}
    lock_root_version = (
        str(root_pkg.get("version") or "").strip() if isinstance(root_pkg, dict) else ""
    )
    if lock_version != version or lock_root_version != version:
        _fail(
            "web-vue/package-lock.json version "
            f"{lock_version!r}/{lock_root_version!r} != VERSION {version!r}"
        )

    uv_lock = _read_text(_ROOT / "uv.lock")
    uv_match = re.search(
        r'(?m)^\[\[package\]\]\r?\nname = "chatgpt-2api"\r?\nversion = "([^"]+)"\r?\n',
        uv_lock,
    )
    uv_version = uv_match.group(1) if uv_match else ""
    if uv_version != version:
        _fail(f"uv.lock chatgpt-2api version {uv_version!r} != VERSION {version!r}")

    changelog = _read_text(_ROOT / "CHANGELOG.md")
    heading = rf"(?m)^## {re.escape(version)} - "
    if re.search(heading, changelog) is None:
        _fail(f"CHANGELOG.md missing heading '## {version} - ' at start of line")

    print(f"release version {version} is consistent")


if __name__ == "__main__":
    main()
