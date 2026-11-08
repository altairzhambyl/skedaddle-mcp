"""The agent pre-install hook: which commands are installs, and what the agent is told."""

import json

from skedaddle_mcp.hook import decide, targets


def test_targets_cover_package_managers(tmp_path):
    cwd = str(tmp_path)
    cases = {
        "npm install axios@1.15.2 --save-dev": [("npm", "axios@1.15.2")],
        "cd app && pnpm add -D express lodash": [("npm", "express"), ("npm", "lodash")],
        "yarn global add typescript": [("npm", "typescript")],
        "npx -y create-vite@5.0.0 my-app": [("npm", "create-vite@5.0.0")],
        "pnpm dlx cowsay hi": [("npm", "cowsay")],
        "bun x prettier --write .": [("npm", "prettier")],
        "pip install 'requests>=2' flask==3.0.0": [("pypi", "requests"), ("pypi", "flask==3.0.0")],
        "python3 -m pip install --upgrade httpx": [("pypi", "httpx")],
        "uv add pydantic": [("pypi", "pydantic")],
        "uv pip install numpy": [("pypi", "numpy")],
        "uvx ruff check": [("pypi", "ruff")],
        "sudo FOO=1 npm i -g left-pad": [("npm", "left-pad")],
    }
    for cmd, want in cases.items():
        assert targets(cmd, cwd) == want, cmd


def test_not_installs(tmp_path):
    for cmd in (
        "npm test",
        "npm run build",
        "pnpm install --frozen-lockfile",
        "pip list",
        "uv run pytest",
        "git status",
        "npm install ./local-pkg",
        "pip install -e .",
        "echo npm install axios",
    ):
        assert targets(cmd, str(tmp_path)) == [], cmd


def test_bare_install_checks_the_manifest_delta(tmp_path):
    """The bypass: the agent edits package.json, then runs a bare `npm install`."""
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"axios": "^1.15.0", "new-dep": "1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/axios": {"version": "1.15.2"}}}))
    assert targets("npm install", str(tmp_path)) == [("npm", "new-dep@1.0.0")]


def test_requirements_file(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n# c\n-e .\nflask>=3\n")
    assert targets("pip install -r requirements.txt", str(tmp_path)) == [("pypi", "requests==2.32.3"), ("pypi", "flask")]


def test_decide_denies_a_hallucinated_package(registry, tmp_path):
    out = decide("npm install react-codeshift-ai-helper-pro", str(tmp_path))
    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny" and "react-codeshift-ai-helper-pro" in hs["permissionDecisionReason"]


def test_decide_warns_without_blocking(registry, tmp_path):
    out = decide("npm install event-stream@3.3.5", str(tmp_path))
    hs = out["hookSpecificOutput"]
    assert "permissionDecision" not in hs and "right9ctrl" in hs["additionalContext"]


def test_decide_silent_on_non_install(registry, tmp_path):
    assert decide("npm test", str(tmp_path)) is None


def test_decide_asks_when_unverifiable(registry, tmp_path, monkeypatch):
    from skedaddle_mcp import core
    from skedaddle_mcp.http import FetchError

    monkeypatch.setattr(core, "get_json", lambda *a, **k: (_ for _ in ()).throw(FetchError("offline")))
    out = decide("npm install anything", str(tmp_path))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
