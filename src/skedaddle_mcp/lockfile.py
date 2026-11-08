"""Read exact (name, version) pins from lockfiles: package-lock.json (v2/v3), requirements.txt (== pins)."""

from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .core import check_package

MAX_PACKAGES = 2000


def read_pins(path: str) -> tuple[str, list[tuple[str, str]], list[str]]:
    """(ecosystem, [(name, version)], skipped lines). Raises ValueError on an unsupported file."""
    base = os.path.basename(path)
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        pins = []
        for key, meta in (doc.get("packages") or {}).items():
            if not key or meta.get("link") or not meta.get("version"):
                continue  # "" is the root project; links are workspace packages
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            pins.append((name, meta["version"]))
        if not pins and doc.get("dependencies"):  # lockfileVersion 1
            stack = list((doc.get("dependencies") or {}).items())
            while stack:
                name, meta = stack.pop()
                if meta.get("version"):
                    pins.append((name, meta["version"]))
                stack.extend((meta.get("dependencies") or {}).items())
        return "npm", sorted(set(pins)), []
    if base.endswith(".txt"):
        pins, skipped = [], []
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                m = re.match(
                    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s;,]+)",
                    line,
                )
                if m:
                    pins.append((m[1], m[3]))
                else:
                    skipped.append(
                        line
                    )  # unpinned / URL / -r include: not checkable as an exact version
        return "pypi", sorted(set(pins)), skipped
    raise ValueError(
        f"unsupported lockfile {base!r}: package-lock.json, npm-shrinkwrap.json or a requirements*.txt"
    )


def audit(path: str, workers: int = 8) -> dict[str, Any]:
    eco, pins, skipped = read_pins(path)
    truncated = len(pins) > MAX_PACKAGES
    pins = pins[:MAX_PACKAGES]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        reports = list(ex.map(lambda p: check_package(eco, p[0], p[1]).to_dict(), pins))
    flagged = [r for r in reports if r["verdict"] != "allow"]
    order = {"block": 0, "error": 1, "warn": 2}
    flagged.sort(key=lambda r: (order.get(r["verdict"], 3), r["name"]))
    verdicts = {
        v: sum(r["verdict"] == v for r in reports)
        for v in ("block", "warn", "error", "allow")
    }
    return {
        "lockfile": path,
        "ecosystem": eco,
        "checked": len(reports),
        "verdicts": verdicts,
        "verdict": "block"
        if verdicts["block"]
        else "error"
        if verdicts["error"]
        else "warn"
        if verdicts["warn"]
        else "allow",
        "flagged": flagged,
        "skipped_unpinned": skipped,
        "truncated": truncated,
    }
