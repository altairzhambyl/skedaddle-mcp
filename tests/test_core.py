"""Checks on real recorded registry/OSV answers (incidents and honest packages) and synthetic incident patterns."""

from conftest import npm_doc

from skedaddle_mcp.core import check_package, parse_spec

ATT = {"dist": {"attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/x", "provenance": {}}}}


def signals(rep, severity=None):
    return {f.signal for f in rep.findings if severity is None or f.severity == severity}


# ---- real incidents (recorded answers) --------------------------------------------------------------------------
def test_event_stream_new_publisher_real(registry):
    rep = check_package("npm", "event-stream", "3.3.5")  # right9ctrl took over from dominictarr (2018)
    assert "new-publisher" in signals(rep, "warn"), rep.findings
    assert rep.verdict == "warn"


def test_event_stream_malicious_version_unpublished_real(registry):
    rep = check_package("npm", "event-stream", "3.3.6")
    assert rep.verdict == "block"
    assert "unpublished-version" in signals(rep, "block")


def test_axios_compromised_release_unpublished_real(registry):
    rep = check_package("npm", "axios", "1.14.1")  # 2026-03-31, live ~3 h, then removed
    assert rep.verdict == "block" and "unpublished-version" in signals(rep)


def test_ua_parser_js_compromised_release_unpublished_real(registry):
    assert check_package("npm", "ua-parser-js", "0.7.29").verdict == "block"


def test_known_malware_real(registry):
    rep = check_package("npm", "crossenv")
    # npm took crossenv down (2017) and now serves its "0.0.2-security" placeholder: blocked as a taken-down name
    assert rep.verdict == "block" and signals(rep) & {"malware", "security-placeholder"}, rep.findings
    assert "new-publisher" not in signals(rep)  # the 'npm' account publishing the placeholder is not a takeover


def test_hallucinated_names_real(registry):
    for eco, name in (("npm", "react-codeshift-ai-helper-pro"), ("pypi", "huggingface-cli-tools-pro")):
        rep = check_package(eco, name)
        assert rep.verdict == "block" and "not-found" in signals(rep), (eco, name)


# ---- honest packages: no false alarms ------------------------------------------------------------------------
def test_axios_move_to_trusted_publishing_is_not_a_new_publisher(registry):
    rep = check_package("npm", "axios", "1.14.0")  # first release by "GitHub Actions", WITH provenance
    assert "new-publisher" not in signals(rep), rep.findings
    assert "provenance-lost" not in signals(rep)


def test_honest_releases_not_blocked(registry):
    for eco, name, ver in (("npm", "axios", "1.15.2"), ("npm", "express", "5.1.0"), ("pypi", "requests", "2.32.3")):
        rep = check_package(eco, name, ver)
        integrity = signals(rep) & {
            "provenance-lost",
            "new-publisher",
            "install-script-added",
            "unpublished-version",
            "not-found",
            "malware",
            "fresh-package",
        }
        assert not integrity, (name, rep.findings)


# ---- synthetic incident patterns (the real malicious versions are gone from the registry) -----------------------
def test_provenance_lost_blocks(registry):
    rel = [(f"2.0.{i}", f"2026-01-0{i + 1}T00:00:00Z", ATT) for i in range(5)] + [("2.0.5", "2026-01-09T00:00:00Z", {})]
    registry("https://registry.npmjs.org/pkg-a", npm_doc("pkg-a", rel))
    rep = check_package("npm", "pkg-a", "2.0.5")
    assert rep.verdict == "block" and "provenance-lost" in signals(rep, "block")


def test_install_script_added_in_patch_blocks(registry):
    rel = [
        ("1.0.0", "2026-01-01T00:00:00Z", {}),
        ("1.0.1", "2026-01-02T00:00:00Z", {}),
        (
            "1.0.2",
            "2026-01-03T00:00:00Z",
            {"scripts": {"postinstall": "node setup.js"}, "dependencies": {"a": "^1.0.0", "plain-helper": "^4.2.1"}},
        ),
    ]
    registry("https://registry.npmjs.org/pkg-b", npm_doc("pkg-b", rel))
    rep = check_package("npm", "pkg-b", "1.0.2")
    assert rep.verdict == "block"
    assert {"install-script-added", "deps-added-in-patch"} <= signals(rep)


def test_cve_blocks_only_with_a_fix_and_only_high(registry):
    osv = "https://api.osv.dev/v1/query"
    rel = [("3.0.0", "2025-01-01T00:00:00Z", {}), ("3.0.1", "2025-02-01T00:00:00Z", {})]
    registry("https://registry.npmjs.org/pkg-c", npm_doc("pkg-c", rel))
    vuln = lambda sev, fixed: {
        "id": f"GHSA-{sev}",
        "summary": "bug",
        "database_specific": {"severity": sev},
        "affected": [
            {"package": {"name": "pkg-c"}, "ranges": [{"events": [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])}]}
        ],
    }
    body = {"package": {"name": "pkg-c", "ecosystem": "npm"}, "version": "3.0.0"}
    registry(osv, {"vulns": [vuln("HIGH", "3.0.1"), vuln("MODERATE", "3.0.1"), vuln("CRITICAL", None)]}, body)
    rep = check_package("npm", "pkg-c", "3.0.0")
    cves = [f for f in rep.findings if f.signal == "cve"]
    assert [f.evidence["id"] for f in cves] == ["GHSA-HIGH"], cves  # no fix / moderate: not reported (no firehose)
    assert rep.verdict == "block" and "3.0.1" in cves[0].message


def test_unreachable_registry_is_an_error_not_an_allow(registry, monkeypatch):
    from skedaddle_mcp import core
    from skedaddle_mcp.http import FetchError

    def boom(*a, **k):
        raise FetchError("offline")

    monkeypatch.setattr(core, "get_json", boom)
    assert check_package("npm", "anything").verdict == "error"


def test_parse_spec():
    assert parse_spec("npm", "@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3")
    assert parse_spec("npm", "axios@^1.2") == ("axios", None)
    assert parse_spec("pypi", "requests==2.32.3") == ("requests", "2.32.3")
    assert parse_spec("pypi", "requests[socks]") == ("requests", None)


def test_fresh_release_alone_is_info_but_warns_with_another_signal(registry):
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc)
    iso = lambda h: (now - dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = [("1.0.0", iso(24 * 400), {}), ("1.0.1", iso(24 * 300), {})]
    registry("https://registry.npmjs.org/pkg-d", npm_doc("pkg-d", base + [("1.0.2", iso(5), {})]))
    assert check_package("npm", "pkg-d", "1.0.2").verdict == "allow"  # popular packages ship daily: not noise
    registry("https://registry.npmjs.org/pkg-e",
             npm_doc("pkg-e", base + [("1.0.2", iso(5), {"_npmUser": {"name": "someone-new"}})]))
    rep = check_package("npm", "pkg-e", "1.0.2")
    assert rep.verdict == "warn" and {"fresh-release", "new-publisher"} <= signals(rep, "warn")


def test_new_publisher_on_a_major_bump_is_info(registry):
    rel = [("6.0.2", "2026-03-23T00:00:00Z", {}), ("6.0.3", "2026-04-16T00:00:00Z", {}),
           ("7.0.2", "2026-07-08T00:00:00Z", {"_npmUser": {"name": "release-org"}})]  # shape of typescript 7.0.2
    registry("https://registry.npmjs.org/pkg-f", npm_doc("pkg-f", rel))
    rep = check_package("npm", "pkg-f", "7.0.2")
    assert rep.verdict == "allow" and "new-publisher" in signals(rep, "info")
