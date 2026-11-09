"""Package checks: existence, malware, exact-version CVEs, freshness, and release-integrity signals.

Every finding carries the signal id, a severity (block | warn | info), a one-line message, the evidence, and the URL
it came from, so an agent (or a human) can verify it instead of trusting the verdict.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

from .http import FetchError, NotFound, get_json

ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "crates": "crates.io", "cargo": "crates.io"}
FRESH_PACKAGE_DAYS = 30  # a package this new is the typical typosquat / slopsquat vehicle
FRESH_RELEASE_DAYS = 3  # most malicious releases are found and pulled within days (cooldown, like pnpm minimumReleaseAge)
LOW_WEEKLY_DOWNLOADS = 50
# Ordinary CVEs (no fix, or below HIGH) are not reported unless asked: noise is the #1 reason developers mute security
# tools (npm maintainer survey, arXiv 2601.20240). A HIGH/CRITICAL CVE with a fixed version blocks, with the fix.
VERBOSE_CVES = os.environ.get("SKEDADDLE_ALL_CVES") == "1"
BLOCKING_CVE = {"CRITICAL", "HIGH"}
MALWARE_SUMMARY = re.compile(
    r"\bis malware\b|\bcontains malware\b|^\s*malicious (code|package|version)s? in\b|\bembedded malicious code\b",
    re.IGNORECASE,
)
INSTALL_HOOKS = ("preinstall", "install", "postinstall")


@dataclass
class Finding:
    signal: str
    severity: str  # block | warn | info
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = ""


@dataclass
class Report:
    ecosystem: str
    name: str
    version: str | None
    verdict: str = "allow"  # allow | warn | block | error
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def finish(self) -> Report:
        # a fresh release alone is information (popular packages ship daily); next to another integrity signal it warns
        integrity = {"provenance-lost", "new-publisher", "install-script-added", "deps-added-in-patch"}
        if not any(f.signal in integrity and f.severity != "info" for f in self.findings):
            for f in self.findings:
                if f.signal == "fresh-release":
                    f.severity = "info"
        sev = {f.severity for f in self.findings}
        if self.verdict != "error":
            self.verdict = "block" if "block" in sev else "warn" if "warn" in sev else "allow"
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _age_days(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return (_now() - t).total_seconds() / 86400


def _semver(v: str) -> tuple[int, int, int] | None:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", v or "")
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


# ---------------------------------------------------------------- OSV
def osv_findings(rep: Report, eco: str, name: str, version: str | None) -> None:
    body: dict[str, Any] = {"package": {"name": name, "ecosystem": eco}}
    if version:
        body["version"] = version
    url = "https://api.osv.dev/v1/query"
    try:
        vulns = get_json(url, body).get("vulns") or []
    except NotFound:
        vulns = []
    mal = [v for v in vulns if v.get("id", "").startswith("MAL-") or MALWARE_SUMMARY.search(v.get("summary") or "")]
    for v in mal[:3]:
        rep.add(
            Finding(
                "malware",
                "block",
                f"OSV flags {name} as malicious: {v.get('id')} {v.get('summary', '')}"[:200],
                {"id": v.get("id")},
                f"https://osv.dev/vulnerability/{v.get('id')}",
            )
        )
    if mal:
        return
    for v in vulns:
        sev = str((v.get("database_specific") or {}).get("severity") or "").upper()
        fixed = sorted(
            {
                ev["fixed"]
                for a in v.get("affected") or []
                if (a.get("package") or {}).get("name") == name
                for r in a.get("ranges") or []
                for ev in r.get("events") or []
                if "fixed" in ev
            }
        )
        if version and sev in BLOCKING_CVE and fixed:
            rep.add(
                Finding(
                    "cve",
                    "block",
                    f"{name}@{version} has {sev} {v.get('id')}: {v.get('summary', '')}"[:200]
                    + (f"; fixed in {', '.join(fixed[:3])}" if fixed else "; no fixed version listed"),
                    {
                        "id": v.get("id"),
                        "severity": sev,
                        "fixed": fixed,
                        "aliases": v.get("aliases") or [],
                    },
                    f"https://osv.dev/vulnerability/{v.get('id')}",
                )
            )
        elif VERBOSE_CVES:  # off by default: an unactionable alert stream is why devs mute these tools
            rep.add(
                Finding(
                    "cve",
                    "info",
                    f"{name}{'@' + version if version else ''}: {sev or 'unrated'} {v.get('id')} {v.get('summary', '')}"[:200],
                    {"id": v.get("id"), "severity": sev or None, "fixed": fixed},
                    f"https://osv.dev/vulnerability/{v.get('id')}",
                )
            )


# ---------------------------------------------------------------- npm
def _fresh_npm_dep(names: list[str], cap: int = 10) -> str | None:
    """Why an added dependency is suspicious (new, missing, unknown age, or too many to check), else None."""
    if len(names) > cap:
        return f"{len(names)} dependencies added, more than the {cap} checked"
    for dep in names:
        url = f"https://registry.npmjs.org/{urllib.parse.quote(dep, safe='@')}"
        try:
            created = (get_json(url).get("time") or {}).get("created")
        except NotFound:
            return f"{dep} does not exist in the registry"
        except FetchError:
            return f"{dep} could not be checked"
        age = _age_days(created)
        if age is None:
            return f"{dep} has no publication date"
        if age < FRESH_PACKAGE_DAYS:
            return f"{dep} was first published {age:.0f} days ago"
    return None


def _npm_publisher(meta: dict[str, Any]) -> str | None:
    return (meta.get("_npmUser") or {}).get("name")


def _npm_attested(meta: dict[str, Any]) -> bool:
    return bool((meta.get("dist") or {}).get("attestations"))


def npm_findings(rep: Report, name: str, version: str | None) -> str | None:
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}".replace("%40", "@", 1)
    doc = get_json(url)
    times: dict[str, str] = doc.get("time") or {}
    versions: dict[str, Any] = doc.get("versions") or {}
    version = version or (doc.get("dist-tags") or {}).get("latest")
    rep.version = version
    age = _age_days(times.get("created"))
    if age is not None and age < FRESH_PACKAGE_DAYS:
        rep.add(
            Finding(
                "fresh-package",
                "block",
                f"{name} was first published {age:.0f} days ago (< {FRESH_PACKAGE_DAYS})",
                {"created": times.get("created")},
                url,
            )
        )
    if version and version not in versions:
        if version in times:
            rep.add(
                Finding(
                    "unpublished-version",
                    "block",
                    f"{name}@{version} was published on {times[version]} and later removed from the registry "
                    "(removal usually follows a compromise or malware report)",
                    {"published": times[version]},
                    url,
                )
            )
        else:
            rep.add(
                Finding(
                    "no-such-version",
                    "block",
                    f"{name}@{version} does not exist",
                    {},
                    url,
                )
            )
        return version
    meta = versions.get(version) or {}
    if re.search(r"-security(\.\d+)?$", version) and _npm_publisher(meta) == "npm":
        # npm replaces a package removed for malware with a "0.0.x-security" placeholder published by npm itself
        rep.add(
            Finding(
                "security-placeholder",
                "block",
                f"{name} was taken down by npm for security reasons (its latest version {version} is npm's placeholder); "
                "the name was used for malware",
                {"version": version},
                url,
            )
        )
        return version
    hooks = {k: meta["scripts"][k] for k in INSTALL_HOOKS if k in (meta.get("scripts") or {})}
    rel_age = _age_days(times.get(version))
    if rel_age is not None and rel_age < FRESH_RELEASE_DAYS:
        rep.add(
            Finding(
                "fresh-release",
                "warn",
                f"{name}@{version} is {rel_age * 24:.0f} hours old: compromised releases are usually caught within days; "
                "prefer the previous version or wait",
                {"published": times.get(version)},
                url,
            )
        )
    # history: stable releases published before this one, newest first, IN THE SAME MAJOR LINE (projects maintain
    # parallel lines with different publishing setups: ox 0.14.x is attested, ox 1.8.x never was; FP scan 2026-11-09)
    tv = _semver(version)
    every = sorted(
        (v for v in versions if v != version and times.get(v, "") < times.get(version, "") and _semver(v)),
        key=lambda v: times[v],
        reverse=True,
    )
    same = [v for v in every if tv and _semver(v)[0] == tv[0]]
    prior = same or every  # the first release of a new major line is compared with the recent releases overall
    prev = versions.get(prior[0]) if prior else None
    if prev is not None:
        recent = [versions[v] for v in prior[:10]]
        attested_before = sum(_npm_attested(m) for m in recent[:5])
        if attested_before >= 3 and not _npm_attested(meta):
            rep.add(
                Finding(
                    "provenance-lost",
                    "block",
                    f"{name}@{version} has no provenance attestation, but {attested_before} of the previous 5 releases had one: "
                    "it was not published by the project's usual CI (stolen token / manual publish)",
                    {"previous": prior[:5]},
                    url,
                )
            )
        pub = _npm_publisher(meta)
        seen = {_npm_publisher(m) for m in recent}
        if pub and pub != "npm" and pub not in seen and not _npm_attested(meta):
            pv, tv = _semver(prior[0]), _semver(version)
            major_bump = bool(pv and tv and tv[0] > pv[0])  # release-process changes cluster on majors (typescript 7)
            rep.add(
                Finding(
                    "new-publisher",
                    "info" if major_bump else "warn",
                    f"{name}@{version} was published by '{pub}', who published none of the previous {len(recent)} releases "
                    f"({', '.join(sorted(p for p in seen if p))}), without provenance",
                    {
                        "publisher": pub,
                        "previous_publishers": sorted(p for p in seen if p),
                    },
                    url,
                )
            )
        prev_hooks = set(prev.get("scripts") or {}).intersection(INSTALL_HOOKS)
        if hooks and not prev_hooks:
            rep.add(
                Finding(
                    "install-script-added",
                    "block",
                    f"{name}@{version} adds install-time code ({', '.join(hooks)}) that {prior[0]} did not have",
                    {"scripts": hooks, "previous": prior[0]},
                    url,
                )
            )
        a, b = _semver(prior[0]), _semver(version)
        added = sorted(set(meta.get("dependencies") or {}) - set(prev.get("dependencies") or {}))
        if a and b and a[:2] == b[:2] and added:
            # an added dependency that is itself new is the axios 1.14.1 pattern (plain-crypto-js); an old one is routine
            new_dep = _fresh_npm_dep(added)
            rep.add(
                Finding(
                    "deps-added-in-patch",
                    "warn" if new_dep else "info",
                    f"{name}@{version} is a patch release that adds dependencies: {', '.join(added[:5])}"
                    + (f" ({new_dep})" if new_dep else ""),
                    {"added": added, "previous": prior[0]},
                    url,
                )
            )
        if prev.get("gitHead") and not meta.get("gitHead"):
            rep.add(
                Finding(
                    "no-git-head",
                    "info",  # weak proxy: many projects publish from CI without gitHead
                    f"{name}@{version} has no gitHead (not published from a git checkout), unlike {prior[0]}",
                    {"previous": prior[0]},
                    url,
                )
            )
    elif hooks:
        rep.add(
            Finding(
                "install-script",
                "warn",
                f"{name}@{version} runs code at install time ({', '.join(hooks)})",
                {"scripts": hooks},
                url,
            )
        )
    dl_url = f"https://api.npmjs.org/downloads/point/last-week/{urllib.parse.quote(name, safe='@')}"
    try:
        dl = get_json(dl_url).get("downloads", 0)
        if dl < LOW_WEEKLY_DOWNLOADS:
            rep.add(
                Finding(
                    "low-downloads",
                    "warn",
                    f"{name} had {dl} downloads last week",
                    {"downloads": dl},
                    dl_url,
                )
            )
    except NotFound:
        rep.add(
            Finding(
                "low-downloads",
                "warn",
                f"{name} has no download statistics",
                {},
                dl_url,
            )
        )
    except FetchError as e:  # stats are a soft signal: rate-limited/unavailable stats never make the check fail
        rep.add(Finding("low-downloads", "info", f"download statistics unavailable ({str(e)[:80]})", {}, dl_url))
    return version


# ---------------------------------------------------------------- PyPI / crates
def pypi_findings(rep: Report, name: str, version: str | None) -> str | None:
    url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    doc = get_json(url)
    version = version or (doc.get("info") or {}).get("version")
    rep.version = version
    rels = doc.get("releases") or {}
    ups = [u.get("upload_time_iso_8601") or u.get("upload_time") for files in rels.values() for u in files]
    ups = sorted(u for u in ups if u)
    age = _age_days(ups[0]) if ups else None
    if age is not None and age < FRESH_PACKAGE_DAYS:
        rep.add(
            Finding(
                "fresh-package",
                "block",
                f"{name} was first uploaded {age:.0f} days ago (< {FRESH_PACKAGE_DAYS})",
                {"first_upload": ups[0]},
                url,
            )
        )
    if version and version not in rels:
        rep.add(
            Finding(
                "no-such-version",
                "block",
                f"{name}=={version} does not exist on PyPI",
                {},
                url,
            )
        )
        return version
    files = rels.get(version) or []
    if files and all(f.get("yanked") for f in files):
        rep.add(
            Finding(
                "yanked",
                "block",
                f"{name}=={version} is yanked: {files[0].get('yanked_reason') or 'no reason given'}",
                {},
                url,
            )
        )
    _pypi_provenance(rep, name, version, rels)
    ts = min(
        (f.get("upload_time_iso_8601") or f.get("upload_time") for f in files),
        default=None,
    )
    rel_age = _age_days(ts)
    if rel_age is not None and rel_age < FRESH_RELEASE_DAYS:
        rep.add(
            Finding(
                "fresh-release",
                "warn",
                f"{name}=={version} is {rel_age * 24:.0f} hours old",
                {"uploaded": ts},
                url,
            )
        )
    return version


def _pypi_publisher(name: str, version: str, files: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """(has a PEP 740 attestation, 'repository/workflow' of its trusted publisher) for the release's first file."""
    if not files:
        return False, None
    url = f"https://pypi.org/integrity/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/{files[0]['filename']}/provenance"
    try:
        doc = get_json(url)
    except NotFound:
        return False, None
    pub = (doc.get("attestation_bundles") or [{}])[0].get("publisher") or {}
    return True, (pub.get("repository") or None)  # a renamed workflow in the same repo is the same publisher (pluggy)


def _pypi_provenance(rep: Report, name: str, version: str, rels: dict[str, list[dict[str, Any]]]) -> None:
    """Lost PEP 740 attestation (the litellm 1.82.7 class: a stolen token uploads outside CI) or a changed publisher."""

    def up(v: str) -> str:
        return min((f.get("upload_time_iso_8601") or f.get("upload_time") or "" for f in rels.get(v) or []), default="")

    here = up(version)
    prior = sorted((v for v in rels if v != version and up(v) and up(v) < here), key=up, reverse=True)[:3]
    if not prior:
        return
    has, pub = _pypi_publisher(name, version, rels.get(version) or [])
    before = [_pypi_publisher(name, v, rels[v]) for v in prior]
    url = f"https://pypi.org/project/{name}/{version}/"
    attested = sum(b[0] for b in before)
    if not has and attested >= 2:
        rep.add(
            Finding(
                "provenance-lost",
                "block",
                f"{name}=={version} has no PEP 740 attestation, but {attested} of the previous {len(prior)} releases had one: "
                "it was not uploaded by the project's usual trusted publisher (stolen token / manual upload)",
                {"previous": prior},
                url,
            )
        )
    seen = {b[1] for b in before if b[1]}
    if has and pub and seen and pub not in seen:
        rep.add(
            Finding(
                "new-publisher",
                "warn",
                f"{name}=={version} was published by {pub}; previous releases by {', '.join(sorted(seen))}",
                {"publisher": pub, "previous_publishers": sorted(seen)},
                url,
            )
        )


def crates_findings(rep: Report, name: str, version: str | None) -> str | None:
    url = f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}"
    doc = get_json(url)
    crate = doc.get("crate") or {}
    version = version or crate.get("max_stable_version") or crate.get("newest_version")
    rep.version = version
    age = _age_days(crate.get("created_at"))
    if age is not None and age < FRESH_PACKAGE_DAYS:
        rep.add(
            Finding(
                "fresh-package",
                "block",
                f"{name} was first published {age:.0f} days ago (< {FRESH_PACKAGE_DAYS})",
                {"created": crate.get("created_at")},
                url,
            )
        )
    vs = {v.get("num"): v for v in doc.get("versions") or []}
    if version and vs and version not in vs:
        rep.add(
            Finding(
                "no-such-version",
                "block",
                f"{name} {version} does not exist on crates.io",
                {},
                url,
            )
        )
    elif version and (vs.get(version) or {}).get("yanked"):
        rep.add(Finding("yanked", "block", f"{name} {version} is yanked", {}, url))
    return version


def check_package(ecosystem: str, name: str, version: str | None = None) -> Report:
    """Check one package (optionally one exact version). Never raises: a failure is verdict 'error' with the reason."""
    eco = ECOSYSTEMS.get(ecosystem.lower())
    rep = Report(ecosystem, name, version)
    if eco is None:
        rep.verdict = "error"
        rep.add(
            Finding(
                "unsupported",
                "warn",
                f"unsupported ecosystem {ecosystem!r}; use one of: npm, pypi, crates",
            )
        )
        return rep
    try:
        fn = {"npm": npm_findings, "PyPI": pypi_findings, "crates.io": crates_findings}[eco]
        version = fn(rep, name, version)
    except NotFound:
        rep.add(
            Finding(
                "not-found",
                "block",
                f"{ecosystem} package '{name}' does not exist: a hallucinated or mistyped name that anyone could register "
                "(slopsquatting)",
            )
        )
        return rep.finish()
    except FetchError as e:
        rep.verdict = "error"
        rep.add(Finding("unverifiable", "warn", f"could not reach the registry ({e}); treat the package as unchecked"))
        return rep
    except (AttributeError, TypeError, KeyError, ValueError, IndexError) as e:  # an unexpected registry answer shape
        rep.verdict = "error"
        rep.add(Finding("unverifiable", "warn", f"unexpected registry answer ({type(e).__name__}: {str(e)[:120]})"))
        return rep
    try:
        osv_findings(rep, eco, name, version)
    except (FetchError, AttributeError, TypeError, KeyError, ValueError) as e:
        # malware and CVE status unknown: not an allow (the hook asks the user)
        rep.add(
            Finding(
                "unverifiable",
                "warn",
                f"could not check OSV ({type(e).__name__}: {str(e)[:120]}); malware and CVE status unknown",
            )
        )
        rep.finish()
        if rep.verdict != "block":
            rep.verdict = "error"
        return rep
    return rep.finish()


SPEC_RX = {
    "npm": re.compile(r"^(?P<name>@?[^@\s]+)(?:@(?P<version>[^\s]+))?$"),
    "pypi": re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:==(?P<version>[^\s;,]+))?$"),
    "crates": re.compile(r"^(?P<name>[A-Za-z0-9_-]+)(?:@(?P<version>[^\s]+))?$"),
}


def parse_spec(ecosystem: str, spec: str) -> tuple[str, str | None]:
    """'axios@1.15.0' / 'requests==2.32.3' / 'serde@1.0.0' -> (name, exact version or None). Ranges are not exact."""
    spec = spec.strip()
    if ecosystem.lower() == "npm":
        alias = re.match(r"^(@?[^@]+)@npm:(.+)$", spec)  # x@npm:real@1.0.0 installs `real`: check that
        if alias:
            spec = alias[2]
    if re.match(r"^(git(\+[a-z]+)?:|[a-z]+\+https?:|https?:|github:|gitlab:|bitbucket:|file:|link:)", spec) or re.search(
        r"@(git(\+[a-z]+)?:|https?:|github:|file:)", spec
    ):
        raise ValueError(f"{spec!r} is a git/URL/file source, not a registry package: it cannot be checked")
    rx = SPEC_RX.get("crates" if ecosystem.lower() == "cargo" else ecosystem.lower())
    m = rx.match(spec) if rx else None
    if not m:
        raise ValueError(f"cannot parse {ecosystem} package spec {spec!r}")
    ver = m["version"]
    if ver and not re.match(r"^v?\d+(\.\d+)*([.-][0-9A-Za-z.-]+)?$", ver):
        ver = None  # a range or tag (^1.2, latest): the check runs on the latest version
    return m["name"], ver
