"""MCP server (stdio): check_package and audit_lockfile tools."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__
from .core import check_package as _check
from .core import parse_spec
from .lockfile import audit

mcp = MCPServer("skedaddle")


@mcp.tool()
def check_package(ecosystem: str, package: str) -> dict[str, Any]:
    """Check a package BEFORE installing it. ecosystem: npm | pypi | crates. package: a name with an optional exact
    version, e.g. "axios@1.15.0", "requests==2.32.3", "serde@1.0.210". Returns verdict allow | warn | block | error and
    findings with evidence and source URLs: nonexistent (hallucinated) names, malware, CVEs in that exact version,
    fresh packages/releases, and signs of a compromised release (provenance lost, new publisher, install script added).
    Do not install on block; tell the user about warn."""
    name, version = parse_spec(ecosystem, package)
    return _check(ecosystem, name, version).to_dict()


@mcp.tool()
def audit_lockfile(path: str) -> dict[str, Any]:
    """Audit every exact pin in a package-lock.json / npm-shrinkwrap.json / requirements*.txt. Returns counts per
    verdict and only the flagged packages (block first)."""
    return audit(path)


def main() -> None:
    mcp.run()


__all__ = ["__version__", "main", "mcp"]
