"""A block that says what to do instead: the agent fixes its own command without a human (power-user eval #3)."""

from conftest import npm_doc

from skedaddle_mcp.core import check_package
from skedaddle_mcp.hook import decide

OSV = "https://api.osv.dev/v1/query"


def _vuln(id_, sev, fixed):
    return {"id": id_, "summary": "bug", "database_specific": {"severity": sev},
            "affected": [{"package": {"name": "pkg-f"}, "ranges": [{"events": [{"introduced": "0"}] + [{"fixed": f} for f in fixed]}]}]}


def test_one_version_that_fixes_every_blocking_advisory_in_the_line(registry):
    rel = [(v, f"2025-0{i + 1}-01T00:00:00Z", {}) for i, v in enumerate(["3.0.0", "3.0.1", "3.0.4", "3.1.0", "4.0.0"])]
    registry("https://registry.npmjs.org/pkg-f", npm_doc("pkg-f", rel))
    body = {"package": {"name": "pkg-f", "ecosystem": "npm"}, "version": "3.0.0"}
    registry(OSV, {"vulns": [_vuln("GHSA-a", "HIGH", ["3.0.1", "4.0.0"]), _vuln("GHSA-b", "CRITICAL", ["3.0.4"])]}, body)
    rep = check_package("npm", "pkg-f", "3.0.0")
    assert rep.verdict == "block" and rep.suggestion == {"version": "3.0.4"}, rep.suggestion  # fixes both, same major
    out = decide("npm install pkg-f@3.0.0", "/tmp")
    assert "pkg-f@3.0.4" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_did_you_mean_for_a_hallucinated_npm_name(registry):
    registry("https://registry.npmjs.org/-/v1/search?text=reakt-dom&size=5",
             {"objects": [{"package": {"name": "react-dom"}}, {"package": {"name": "dom-utils"}}]})
    rep = check_package("npm", "reakt-dom")
    assert rep.verdict == "block" and rep.suggestion == {"did_you_mean": "react-dom"}
    out = decide("npm i reakt-dom", "/tmp")
    assert "react-dom" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_no_suggestion_when_nothing_is_close(registry):
    registry("https://registry.npmjs.org/-/v1/search?text=zzq-qwerty-unrelated&size=5", {"objects": [{"package": {"name": "react"}}]})
    assert check_package("npm", "zzq-qwerty-unrelated").suggestion is None
