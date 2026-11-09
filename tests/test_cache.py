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
