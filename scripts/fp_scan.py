"""False-positive scan: check the latest version of the most popular npm and PyPI packages.

Popular packages are almost never compromised at any given moment, so a block on one is a bug in skedaddle, and the
warn rate is the noise users would see. Fails (exit 1) on any block or a warn rate above --max-warn-rate.

    uv run python scripts/fp_scan.py --npm 500 --pypi 500
Sources: PyPI top list by hugovk (ClickHouse downloads, 30 days); npm registry search sorted by popularity across
common keywords. Writes a Markdown summary to $GITHUB_STEP_SUMMARY when set.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from skedaddle_mcp.core import check_package
from skedaddle_mcp.http import get_json

PYPI_TOP = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
NPM_KEYWORDS = [
    "react",
    "typescript",
    "cli",
    "node",
    "webpack",
    "eslint",
    "test",
    "http",
    "util",
    "aws",
    "babel",
    "vue",
    "css",
    "json",
    "stream",
    "promise",
    "date",
    "logger",
    "parser",
    "framework",
    "database",
    "plugin",
    "api",
]


def pypi_names(n: int) -> list[str]:
    return [r["project"] for r in get_json(PYPI_TOP, timeout=30)["rows"][:n]]


def npm_names(n: int) -> list[str]:
    seen: dict[str, None] = {}
    for kw in NPM_KEYWORDS:
        q = urllib.parse.urlencode({"text": f"keywords:{kw}", "popularity": 1.0, "quality": 0, "maintenance": 0, "size": 250})
        for o in get_json(f"https://registry.npmjs.org/-/v1/search?{q}", timeout=30).get("objects") or []:
            seen.setdefault(o["package"]["name"], None)
        if len(seen) >= n * 2:
            break
    names = list(seen)
    dl: dict[str, int] = {}
    unscoped = [x for x in names if not x.startswith("@")]
    for i in range(0, len(unscoped), 128):  # bulk download counts: unscoped names only, 128 per call
        res = get_json("https://api.npmjs.org/downloads/point/last-week/" + ",".join(unscoped[i : i + 128]), timeout=30)
        dl.update({k: (v or {}).get("downloads", 0) for k, v in res.items()})
    return sorted(unscoped, key=lambda x: dl.get(x, 0), reverse=True)[:n]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--npm", type=int, default=500)
    ap.add_argument("--pypi", type=int, default=500)
    ap.add_argument("--max-warn-rate", type=float, default=0.005)
    a = ap.parse_args()
    jobs = [("npm", x) for x in npm_names(a.npm)] + [("pypi", x) for x in pypi_names(a.pypi)]
    with ThreadPoolExecutor(max_workers=8) as ex:
        reps = list(ex.map(lambda j: check_package(j[0], j[1]).to_dict(), jobs))
    by = {v: [r for r in reps if r["verdict"] == v] for v in ("block", "warn", "error", "allow")}
    warn_rate = len(by["warn"]) / max(1, len(reps))
    lines = [
        f"## skedaddle false-positive scan: {len(reps)} popular packages (latest versions)",
        "",
        f"block {len(by['block'])} · warn {len(by['warn'])} ({warn_rate:.2%}) · error {len(by['error'])} · allow {len(by['allow'])}",
        "",
    ]
    for v in ("block", "warn", "error"):
        for r in by[v]:
            msg = "; ".join(f["signal"] + ": " + f["message"][:140] for f in r["findings"] if f["severity"] != "info")
            lines.append(f"- **{v}** {r['ecosystem']}:{r['name']}@{r['version']} — {msg}")
    text = "\n".join(lines)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    with open("fp-scan.json", "w", encoding="utf-8") as fh:
        json.dump({"warn_rate": warn_rate, "reports": [r for r in reps if r["verdict"] != "allow"]}, fh, indent=1)
    with open(os.path.join(os.path.dirname(__file__), "fp_known.json"), encoding="utf-8") as fh:
        known = json.load(fh)
    unexpected = [r for r in by["block"] if f"{r['ecosystem']}:{r['name']}@{r['version']}" not in known]
    print(f"\nunexpected blocks: {len(unexpected)} (reviewed true signals skipped: {len(by['block']) - len(unexpected)})")
    return 1 if unexpected or warn_rate > a.max_warn_rate else 0


if __name__ == "__main__":
    sys.exit(main())
