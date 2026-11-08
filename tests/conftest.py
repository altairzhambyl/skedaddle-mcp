import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from skedaddle_mcp.http import fixture_key

REAL = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """Offline registry: the recorded real answers, plus `put(url, doc, body=None)` for synthetic cases."""
    d = tmp_path / "fx"
    shutil.copytree(REAL, d)
    monkeypatch.setenv("SKEDADDLE_FIXTURES", str(d))

    def put(url, doc, body=None):
        (d / (fixture_key(url, body) + ".json")).write_text(json.dumps(doc))
        if url.startswith("https://registry.npmjs.org/"):  # synthetic packages are "popular": isolate the signal under test
            dl = "https://api.npmjs.org/downloads/point/last-week/" + url.rsplit("/", 1)[1]
            (d / (fixture_key(dl) + ".json")).write_text(json.dumps({"downloads": 100000}))

    return put


def npm_doc(name, releases, latest=None):
    """Synthetic packument. releases: [(version, iso_time, meta_overrides)] oldest first. SYNTHETIC: models a documented
    incident pattern whose real malicious version was unpublished from the registry."""
    time = {"created": releases[0][1], "modified": releases[-1][1]}
    versions = {}
    for v, t, meta in releases:
        time[v] = t
        if meta is not None:  # None = published then unpublished
            versions[v] = {
                "name": name,
                "version": v,
                "_npmUser": {"name": "maintainer"},
                "dist": {},
                "scripts": {},
                "dependencies": {"a": "^1.0.0"},
                "gitHead": "abc",
                **meta,
            }
    return {"name": name, "dist-tags": {"latest": latest or releases[-1][0]}, "time": time, "versions": versions}
