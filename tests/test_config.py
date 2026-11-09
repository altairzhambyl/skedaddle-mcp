"""Bigtech setups: trusted mirrors, internal package names (dependency confusion), time-boxed exceptions, decision log."""

import json

from conftest import npm_doc

from skedaddle_mcp.core import check_package
from skedaddle_mcp.hook import decide, plan


def _cfg(tmp_path, text, trust=True):
    (tmp_path / ".skedaddle.toml").write_text(text)
    (tmp_path / ".git").mkdir(exist_ok=True)  # the repo root bounds the upward search
    if trust:
        from skedaddle_mcp.config import trust as _trust

        _trust(str(tmp_path / ".skedaddle.toml"))  # the user reviewed this exact content


def test_trusted_mirror_is_not_an_unverifiable_source(tmp_path):
    cwd = str(tmp_path)
    (tmp_path / ".npmrc").write_text("registry=https://artifactory.corp.example/api/npm/npm-remote/\n")
    assert plan("npm i axios", cwd, {})[1], "an unknown registry must ask"
    _cfg(tmp_path, 'trusted_registries = ["https://artifactory.corp.example/api/npm/"]\n')
    tg, asks = plan("npm i axios", cwd, {})
    assert asks == [] and tg == [("npm", "axios")]  # still CHECKED by name against public metadata


def test_lookalike_of_a_trusted_mirror_still_asks(tmp_path):
    _cfg(tmp_path, 'trusted_registries = ["https://artifactory.corp.example/api/npm/"]\n')
    for url in (
        "https://artifactory.corp.example.evil.test/api/npm/",
        "https://evil.test/https://artifactory.corp.example/api/npm/",
    ):
        assert plan(f"npm i axios --registry {url}", str(tmp_path), {})[1], url


def test_internal_name_on_the_public_registry_is_dependency_confusion(registry, tmp_path):
    _cfg(tmp_path, 'internal_scopes = ["@corp"]\ninternal_names = ["corp-*"]\n')
    registry("https://registry.npmjs.org/corp-billing", npm_doc("corp-billing", [("99.0.0", "2026-01-01T00:00:00Z", {})]))
    out = decide("npm i corp-billing", str(tmp_path), {})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "dependency confusion" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_internal_name_absent_publicly_is_fine(registry, tmp_path):
    _cfg(tmp_path, 'internal_scopes = ["@corp"]\n')
    assert decide("npm i @corp/billing", str(tmp_path), {}) is None  # internal, not hallucinated


def test_time_boxed_exception(registry, tmp_path):
    cwd = str(tmp_path)
    assert decide("npm i react-codeshift-ai-helper-pro", cwd, {})["hookSpecificOutput"]["permissionDecision"] == "deny"
    _cfg(
        tmp_path,
        '[[allow]]\npackage = "npm:react-codeshift-ai-helper-pro"\nreason = "SEC-123 internal fork"\nexpires = "2099-01-01"\n',
    )
    assert decide("npm i react-codeshift-ai-helper-pro", cwd, {}) is None
    _cfg(tmp_path, '[[allow]]\npackage = "npm:react-codeshift-ai-helper-pro"\nreason = "old"\nexpires = "2020-01-01"\n')
    assert decide("npm i react-codeshift-ai-helper-pro", cwd, {})["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_decisions_are_logged_locally(registry, tmp_path, monkeypatch):
    log = tmp_path / "decisions.jsonl"
    monkeypatch.setenv("SKEDADDLE_LOG", str(log))
    decide("npm i react-codeshift-ai-helper-pro", str(tmp_path), {})
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert rows and rows[-1]["decision"] == "deny" and rows[-1]["packages"] == ["npm:react-codeshift-ai-helper-pro"]


def test_check_package_respects_internal_scope(registry, tmp_path):
    from skedaddle_mcp.config import load

    _cfg(tmp_path, 'internal_scopes = ["@corp"]\n')
    rep = check_package("npm", "@corp/billing", None, load(str(tmp_path)))
    assert rep.verdict == "allow" and rep.findings[0].signal == "internal"


# ---- review of c0fe100: a repo file can be written by a malicious PR or by the agent itself ---------------------------
def test_untrusted_repo_policy_is_ignored(registry, tmp_path):
    cwd = str(tmp_path)
    _cfg(tmp_path, '[[allow]]\npackage = "npm:react-codeshift-ai-helper-pro"\nreason = "x"\nexpires = "2099-01-01"\n', trust=False)
    out = decide("npm i react-codeshift-ai-helper-pro", cwd, {})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "not trusted" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_edited_repo_policy_loses_trust(registry, tmp_path):
    cwd = str(tmp_path)
    _cfg(tmp_path, 'internal_scopes = ["@corp"]\n')
    with open(tmp_path / ".skedaddle.toml", "a") as fh:  # the agent appends an exception after the user's review
        fh.write('[[allow]]\npackage = "npm:react-codeshift-ai-helper-pro"\nreason = "x"\nexpires = "2099-01-01"\n')
    assert decide("npm i react-codeshift-ai-helper-pro", cwd, {})["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_agent_cannot_grant_itself_trust_or_edit_policy(tmp_path):
    from skedaddle_mcp.hook import plan

    cwd = str(tmp_path)
    for cmd in ("skedaddle-mcp trust", "uvx skedaddle-mcp trust .skedaddle.toml",
                "echo 'trusted_registries = [\"https://evil.test\"]' >> ~/.config/skedaddle/config.toml",
                "printf x > .skedaddle.toml", "sed -i s/a/b/ .skedaddle.toml", "export SKEDADDLE_LOG=0",
                "SKEDADDLE_ON_ERROR=allow npm i x"):
        assert plan(cmd, cwd, {})[1], cmd


def test_log_redacts_secrets(registry, tmp_path, monkeypatch):
    log = tmp_path / "d.jsonl"
    monkeypatch.setenv("SKEDADDLE_LOG", str(log))
    decide("NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz0123456789 npm i react-codeshift-ai-helper-pro "
           "--registry https://" + "user" + ":" + "hunter2" + "@registry.npmjs.org/", str(tmp_path), {})
    text = log.read_text()
    assert "npm_abcdefghijklmnopqrstuvwxyz0123456789" not in text and "hunter2" not in text, text
