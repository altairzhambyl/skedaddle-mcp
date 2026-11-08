"""Record real registry / OSV answers into tests/fixtures (run by hand when cases change; tests never hit the network).

Packuments are trimmed to the versions a case needs (plus `time`), so fixtures stay small and reviewable.
    uv run python tests/record_fixtures.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from skedaddle_mcp.http import NotFound, fixture_key, get_json

OUT = os.path.join(os.path.dirname(__file__), "fixtures")

# (ecosystem, name, versions to keep in the trimmed document, versions to query OSV for)
CASES = [
    ("npm", "event-stream", ["3.3.3", "3.3.4", "3.3.5", "4.0.0"], ["3.3.5", "3.3.6"]),
    ("npm", "ua-parser-js", ["0.7.24", "0.7.25", "0.7.26", "0.7.27", "0.7.28", "0.7.30"], ["0.7.29"]),
    (
        "npm",
        "axios",
        ["1.12.0", "1.12.1", "1.12.2", "1.13.0", "1.13.1", "1.13.2", "1.14.0", "1.15.0", "1.15.2"],
        ["1.14.0", "1.14.1", "1.15.2"],
    ),
    ("npm", "crossenv", None, [None]),
    ("npm", "express", ["4.21.0", "4.21.1", "4.21.2", "5.0.0", "5.1.0"], ["5.1.0"]),
    ("npm", "react-codeshift-ai-helper-pro", None, []),  # does not exist: slopsquat candidate
    ("pypi", "requests", ["2.32.2", "2.32.3"], ["2.32.3"]),
    ("pypi", "huggingface-cli-tools-pro", None, []),  # does not exist
]
OSV_ECO = {"npm": "npm", "pypi": "PyPI"}


def save(url: str, doc: object, body: dict | None = None) -> None:
    with open(os.path.join(OUT, fixture_key(url, body) + ".json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)


def trim_npm(doc: dict, keep: list[str] | None) -> dict:
    if keep is None:
        return doc
    vs = doc.get("versions") or {}
    return {
        "name": doc.get("name"),
        "dist-tags": doc.get("dist-tags"),
        "time": doc.get("time"),
        "versions": {
            v: {k: vs[v].get(k) for k in ("name", "version", "_npmUser", "dist", "scripts", "dependencies", "gitHead")}
            for v in keep
            if v in vs
        },
    }


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    for eco, name, keep, osv_versions in CASES:
        q = urllib.parse.quote(name, safe="@")
        url = f"https://registry.npmjs.org/{q}" if eco == "npm" else f"https://pypi.org/pypi/{q}/json"
        try:
            doc = get_json(url, timeout=30)
            if eco == "npm":
                doc = trim_npm(doc, keep)
                if keep and doc["dist-tags"]:
                    doc["dist-tags"] = {"latest": keep[-1]}
            elif keep:
                doc = {
                    "info": {"name": doc["info"]["name"], "version": keep[-1]},
                    "releases": {v: doc["releases"].get(v, []) for v in keep},
                }
            save(url, doc)
        except NotFound:
            print(f"404 (kept as absent): {url}")
        if eco == "npm":
            dl = f"https://api.npmjs.org/downloads/point/last-week/{q}"
            try:
                save(dl, get_json(dl, timeout=30))
            except NotFound:
                pass
        for v in osv_versions:
            body = {"package": {"name": name, "ecosystem": OSV_ECO[eco]}, **({"version": v} if v else {})}
            res = get_json("https://api.osv.dev/v1/query", body, timeout=30)
            res = {"vulns": [{"id": v.get("id"), "summary": v.get("summary"), "aliases": v.get("aliases"),
                              "database_specific": {"severity": (v.get("database_specific") or {}).get("severity")},
                              "affected": [{"package": a.get("package"), "ranges": a.get("ranges")} for a in v.get("affected") or []]}
                             for v in res.get("vulns") or []]}  # only the fields skedaddle reads
            save("https://api.osv.dev/v1/query", res, body)
        print(f"recorded {eco}:{name}")


if __name__ == "__main__":
    main()
