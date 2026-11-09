"""Tiny JSON-over-HTTP client with an offline fixture mode.

SKEDADDLE_FIXTURES=<dir> serves every request from <dir>/<key>.json, where <key> is a filesystem-safe form of the URL
(see `fixture_key`); a missing file is a 404. This keeps the test suite deterministic and offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "skedaddle-mcp (+https://github.com/altairzhambyl/skedaddle-mcp)"


class NotFound(Exception):
    """The registry answered 404: the package or version does not exist."""


class FetchError(Exception):
    """Network failure, timeout, or a non-JSON / non-404 error answer."""


def fixture_key(url: str, body: dict[str, Any] | None = None) -> str:
    key = re.sub(r"[^A-Za-z0-9._-]+", "_", re.sub(r"^https?://", "", url)).strip("_")
    if body is not None:
        key += "__" + hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:12]
    return key[:180]


def get_json(
    url: str,
    body: dict[str, Any] | None = None,
    timeout: float = 10.0,
    retries: int = 1,
    fresh: bool = False,
) -> Any:
    fx = os.environ.get("SKEDADDLE_FIXTURES")
    if fx:
        path = os.path.join(fx, fixture_key(url, body) + ".json")
        if not os.path.exists(path):
            raise NotFound(url)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    cached = None if fresh else _cache_get(url, body)  # fresh: decide on live data (the answer is still cached)
    if cached is not None:
        if cached.get("status") == 404:
            raise NotFound(url)
        return cached.get("body")
    try:
        doc = _fetch(url, body, timeout, retries)
        trim = next((fn for prefix, fn in TRIMMERS if url.startswith(prefix)), None)
        if trim is not None:
            doc = trim(doc)  # keep only what the checks read: next's packument is 31 MB, its trimmed form a fraction
    except NotFound:
        _cache_put(url, body, 404, None)
        raise
    _cache_put(url, body, 200, doc)
    return doc


# ---------------------------------------------------------------- disk cache
# A hook that adds 1-4 s to every install gets uninstalled. Registry metadata changes slowly; OSV and the registries
# are re-asked after the TTL. A cached 404 keeps blocking (the safe direction) only briefly, so a name that gets
# registered is re-checked soon. Private: the directory is 0700 and files are 0600. SKEDADDLE_CACHE=0 disables it.
TTL = [  # (url prefix, seconds)
    ("https://api.osv.dev/", 600),  # malware records appear within hours: an allow must not lean on an old answer
    ("https://api.npmjs.org/downloads/", 86400),
    ("https://pypi.org/integrity/", 86400),
]
DEFAULT_TTL, NOT_FOUND_TTL = 600, 300
TRIMMERS: list[tuple[str, Any]] = []  # (url prefix, fn(doc) -> smaller doc); registered by core


def _cache_dir() -> str | None:
    if os.environ.get("SKEDADDLE_CACHE") == "0":
        return None
    d = os.environ.get("SKEDADDLE_CACHE_DIR") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"), "skedaddle"
    )
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    except OSError:
        return None
    return d


def _cache_path(url: str, body: dict[str, Any] | None) -> str | None:
    d = _cache_dir()
    if d is None:
        return None
    key = hashlib.sha256((url + "\0" + json.dumps(body, sort_keys=True)).encode()).hexdigest()
    return os.path.join(d, key + ".json")


def _cache_get(url: str, body: dict[str, Any] | None) -> dict[str, Any] | None:
    path = _cache_path(url, body)
    if path is None:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            entry = json.load(fh)
    except (OSError, ValueError):
        return None
    ttl = NOT_FOUND_TTL if entry.get("status") == 404 else next((t for p, t in TTL if url.startswith(p)), DEFAULT_TTL)
    if not isinstance(entry, dict) or entry.get("url") != url or time.time() - float(entry.get("t", 0)) > ttl:
        return None
    return entry


def _cache_put(url: str, body: dict[str, Any] | None, status: int, doc: Any) -> None:
    path = _cache_path(url, body)
    if path is None:
        return
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"url": url, "t": time.time(), "status": status, "body": doc}, fh)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _fetch(url: str, body: dict[str, Any] | None, timeout: float, retries: int) -> Any:
    last: Exception | None = None
    for _ in range(retries + 1):
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST" if body is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotFound(url) from e
            last = e
            if e.code == 429:  # rate limited: wait as asked (capped) before the retry
                try:
                    wait = float(e.headers.get("Retry-After") or 1)
                except ValueError:
                    wait = 1.0
                time.sleep(min(max(wait, 0.2), 2.0))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = e
    raise FetchError(f"{url}: {type(last).__name__}: {last}")
