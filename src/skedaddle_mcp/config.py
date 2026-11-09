"""Team / company policy: trusted mirrors, internal package names, time-boxed exceptions.

Read from ~/.config/skedaddle/config.toml and the nearest .skedaddle.toml from cwd up to the repo root (the file a
team commits). Lists are merged. Every setting here can only RELAX a check, so a file that cannot be parsed is
ignored (stricter), never half-applied.

    trusted_registries = ["https://artifactory.corp.example/api/npm/"]   # mirrors: still checked by name
    internal_scopes    = ["@corp"]                                         # npm scopes that are yours
    internal_names     = ["corp-*"]                                        # fnmatch, any ecosystem
    [[allow]]
    package = "npm:left-pad@1.3.0"   # or "pypi:name" for every version
    reason  = "SEC-123 reviewed"
    expires = "2026-12-31"           # required: an exception without an end date is ignored
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import os
import urllib.parse
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Config:
    trusted_registries: list[str] = field(default_factory=list)
    internal_scopes: list[str] = field(default_factory=list)
    internal_names: list[str] = field(default_factory=list)
    allow: list[dict[str, Any]] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    untrusted: str | None = None  # a repo policy file that exists but is not (or no longer) trusted by the user

    def trusted(self, url: str) -> bool:
        """https, no userinfo, the exact host of a trusted entry, and its path as a prefix."""
        try:
            u = urllib.parse.urlsplit(url.strip())
        except ValueError:
            return False
        if u.scheme != "https" or u.username or u.password:
            return False
        for t in self.trusted_registries:
            tu = urllib.parse.urlsplit(t)
            if tu.scheme == "https" and tu.hostname == u.hostname and (tu.port or 443) == (u.port or 443):
                prefix = tu.path.rstrip("/")
                if not prefix or u.path == prefix or u.path.startswith(prefix + "/"):
                    return True
        return False

    def internal(self, ecosystem: str, name: str) -> bool:
        if ecosystem == "npm" and any(name.startswith(s.rstrip("/") + "/") for s in self.internal_scopes):
            return True
        return any(fnmatch.fnmatchcase(name.lower(), pat.lower()) for pat in self.internal_names)

    def allowed(self, ecosystem: str, name: str, version: str | None) -> dict[str, Any] | None:
        today = dt.date.today().isoformat()
        for a in self.allow:
            pkg, exp = str(a.get("package") or ""), str(a.get("expires") or "")
            if not exp or exp < today:
                continue  # no end date, or expired: not an exception
            eco, _, rest = pkg.partition(":")
            if eco.lower() not in (ecosystem.lower(), {"pypi": "pypi", "crates.io": "crates"}.get(ecosystem.lower(), "")):
                continue
            n, _, v = rest.rpartition("@") if rest.count("@") > (1 if rest.startswith("@") else 0) else (rest, "", "")
            if n.lower() == name.lower() and (not v or v == version):
                return a
        return None


def _parse_toml(raw: bytes) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]
    return tomllib.loads(raw.decode("utf-8"))


def _toml(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]
    return tomllib.loads(raw.decode("utf-8"))


def _repo_file(cwd: str) -> str | None:
    d = os.path.abspath(cwd)
    for _ in range(40):
        p = os.path.join(d, ".skedaddle.toml")
        if os.path.exists(p):
            return p
        if os.path.exists(os.path.join(d, ".git")):
            return None  # the repo root: do not read a parent project's policy
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    return None


def _state_dir() -> str:
    return os.environ.get("SKEDADDLE_STATE_DIR") or os.path.join(
        os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state"), "skedaddle")


def _sha(path: str) -> str | None:
    import hashlib

    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def _trusted_hashes() -> dict[str, str]:
    import json

    try:
        with open(os.path.join(_state_dir(), "trusted.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def trust(path: str) -> str:
    """Record that the user reviewed this exact repo policy file (by sha256). Any later edit voids it."""
    import json

    path, digest = os.path.realpath(path), _sha(path)
    if digest is None:
        raise OSError(f"cannot read {path}")
    d = _state_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    hashes = {**_trusted_hashes(), path: digest}
    tmp = os.path.join(d, f"trusted.json.{os.getpid()}")
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as fh:
        json.dump(hashes, fh, indent=1)
    os.replace(tmp, os.path.join(d, "trusted.json"))
    return digest


def load(cwd: str | None = None) -> Config:
    cfg = Config()
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    user = os.environ.get("SKEDADDLE_USER_CONFIG") or os.path.join(xdg, "skedaddle", "config.toml")
    import hashlib

    repo = _repo_file(cwd or os.getcwd())
    sources: list[tuple[str, bytes]] = []
    for path, is_repo in ((user, False), (repo, True)):
        if not path:
            continue
        try:
            with open(path, "rb") as fh:
                raw = fh.read()  # read ONCE: the bytes that are hashed are the bytes that are parsed (review of c18f46b)
        except OSError:
            continue
        if is_repo and _trusted_hashes().get(os.path.realpath(path)) != hashlib.sha256(raw).hexdigest():
            # a repo file can come from a malicious PR or be written by the agent itself: it relaxes checks only
            # after the user reviewed this exact content (`skedaddle-mcp trust`); an edit voids it (review of c0fe100)
            cfg.untrusted = path
            continue
        sources.append((path, raw))
    for path, raw in sources:
        try:
            doc = _parse_toml(raw) or {}
        except ValueError as e:
            cfg.errors.append(f"{path}: {e} (ignored)")
            continue
        cfg.files.append(path)
        cfg.trusted_registries += [str(x) for x in doc.get("trusted_registries") or []]
        cfg.internal_scopes += [str(x) for x in doc.get("internal_scopes") or []]
        cfg.internal_names += [str(x) for x in doc.get("internal_names") or []]
        cfg.allow += [a for a in doc.get("allow") or [] if isinstance(a, dict)]
    return cfg
