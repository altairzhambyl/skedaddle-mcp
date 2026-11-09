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
        key += (
            "__"
            + hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:12]
        )
    return key[:180]


def get_json(
    url: str,
    body: dict[str, Any] | None = None,
    timeout: float = 10.0,
    retries: int = 1,
) -> Any:
    fx = os.environ.get("SKEDADDLE_FIXTURES")
    if fx:
        path = os.path.join(fx, fixture_key(url, body) + ".json")
        if not os.path.exists(path):
            raise NotFound(url)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
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
