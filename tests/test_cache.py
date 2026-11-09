"""Disk cache: the second check of the same package must not hit the network (hook latency is the #1 friction)."""

import io
import json
import urllib.error

from skedaddle_mcp import http


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake(monkeypatch, answers):
    calls = []

    def urlopen(req, timeout=0):
        calls.append(req.full_url)
        code, body = answers[req.full_url]
        if code == 404:
            raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
        return _Resp(json.dumps(body).encode())

    monkeypatch.setattr(http.urllib.request, "urlopen", urlopen)
    return calls


def test_second_lookup_is_served_from_disk(tmp_path, monkeypatch):
    monkeypatch.delenv("SKEDADDLE_FIXTURES", raising=False)
    monkeypatch.setenv("SKEDADDLE_CACHE_DIR", str(tmp_path))
    url = "https://registry.npmjs.org/left-pad"
    calls = _fake(monkeypatch, {url: (200, {"name": "left-pad"})})
    assert http.get_json(url) == {"name": "left-pad"}
    assert http.get_json(url) == {"name": "left-pad"}
    assert calls == [url]


def test_not_found_is_cached_and_still_not_found(tmp_path, monkeypatch):
    monkeypatch.delenv("SKEDADDLE_FIXTURES", raising=False)
    monkeypatch.setenv("SKEDADDLE_CACHE_DIR", str(tmp_path))
    url = "https://registry.npmjs.org/zzq-not-a-package"
    calls = _fake(monkeypatch, {url: (404, None)})
    for _ in range(2):
        try:
            http.get_json(url)
            raise AssertionError("expected NotFound")
        except http.NotFound:
            pass
    assert calls == [url]


def test_expired_entry_is_refetched(tmp_path, monkeypatch):
    monkeypatch.delenv("SKEDADDLE_FIXTURES", raising=False)
    monkeypatch.setenv("SKEDADDLE_CACHE_DIR", str(tmp_path))
    url = "https://registry.npmjs.org/left-pad"
    calls = _fake(monkeypatch, {url: (200, {"v": 1})})
    http.get_json(url)
    real_time = http.time.time
    monkeypatch.setattr(http.time, "time", lambda: real_time() + 10 * 86400)
    http.get_json(url)
    assert len(calls) == 2


def test_cache_can_be_disabled_and_is_private(tmp_path, monkeypatch):
    import os
    import stat

    monkeypatch.delenv("SKEDADDLE_FIXTURES", raising=False)
    monkeypatch.setenv("SKEDADDLE_CACHE_DIR", str(tmp_path / "c"))
    url = "https://registry.npmjs.org/left-pad"
    calls = _fake(monkeypatch, {url: (200, {"v": 1})})
    http.get_json(url)
    mode = stat.S_IMODE(os.stat(tmp_path / "c").st_mode)
    assert mode == 0o700, oct(mode)
    monkeypatch.setenv("SKEDADDLE_CACHE", "0")
    http.get_json(url)
    assert len(calls) == 2


def test_trimmed_packument_gives_the_same_verdicts(registry, tmp_path):
    """The cache keeps a trimmed packument; every recorded incident must be judged exactly as on the full one."""
    import json as _json
    import os

    from skedaddle_mcp.core import _trim_npm_packument, check_package
    from skedaddle_mcp.http import fixture_key

    fx = os.environ["SKEDADDLE_FIXTURES"]
    cases = [("event-stream", "3.3.5"), ("event-stream", "3.3.6"), ("axios", "1.14.1"), ("axios", "1.14.0"), ("crossenv", None)]
    full = {c: check_package("npm", *c) for c in cases}
    for name in {c[0] for c in cases}:
        path = os.path.join(fx, fixture_key(f"https://registry.npmjs.org/{name}") + ".json")
        with open(path) as fh:
            doc = _json.load(fh)
        with open(path, "w") as fh:
            _json.dump(_trim_npm_packument(doc), fh)
    for c in cases:
        a, b = full[c], check_package("npm", *c)
        assert (a.verdict, sorted(f.signal for f in a.findings)) == (b.verdict, sorted(f.signal for f in b.findings)), c


def test_unpinned_install_never_judges_a_stale_latest(tmp_path, monkeypatch):
    """review of cbb7684: a cached packument said latest=1.0.4; a compromised 1.0.5 shipped since. `npm i pkg` installs
    1.0.5, so the check must too (the axios 1.14.1 window was ~3 hours)."""
    from skedaddle_mcp import core

    monkeypatch.delenv("SKEDADDLE_FIXTURES", raising=False)
    monkeypatch.setenv("SKEDADDLE_CACHE_DIR", str(tmp_path))
    att = {"attestations": {"url": "x"}}
    # five attested 1.0.x releases (the same-major history the provenance signal needs), latest 1.0.4
    old = {"name": "pkg-z", "dist-tags": {"latest": "1.0.4"},
           "time": {"created": "2020-01-01T00:00:00Z", **{f"1.0.{i}": f"2020-0{i + 1}-01T00:00:00Z" for i in range(5)}},
           "versions": {f"1.0.{i}": {"dist": att} for i in range(5)}}
    new = json.loads(json.dumps(old))
    new["dist-tags"]["latest"] = "1.0.5"
    new["time"]["1.0.5"] = "2021-02-01T00:00:00Z"
    new["versions"]["1.0.5"] = {"dist": {}}  # provenance lost: must block
    state = {"doc": old}
    pk = "https://registry.npmjs.org/pkg-z"

    def urlopen(req, timeout=0):
        u = req.full_url
        if u == pk:
            return _Resp(json.dumps(state["doc"]).encode())
        if u.endswith("/-/package/pkg-z/dist-tags"):
            return _Resp(json.dumps(state["doc"]["dist-tags"]).encode())
        if "downloads" in u:
            return _Resp(b'{"downloads": 100000}')
        return _Resp(b'{"vulns": []}')

    monkeypatch.setattr(http.urllib.request, "urlopen", urlopen)
    assert core.check_package("npm", "pkg-z").verdict == "allow"  # 1.0.4, cached now
    state["doc"] = new  # the compromised release ships
    rep = core.check_package("npm", "pkg-z")
    assert rep.version == "1.0.5" and rep.verdict == "block", (rep.version, rep.findings)
