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
    # new-dep is not in the lockfile; with no git baseline the locked direct dependency is checked too (review of 6e13197)
    assert targets("npm install", str(tmp_path)) == [("npm", "new-dep@1.0.0"), ("npm", "axios@1.15.2")]


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


def test_hook_crash_asks_instead_of_allowing(monkeypatch, capsys):
    import io

    from skedaddle_mcp import hook

    def boom(*a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(hook, "decide", boom)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": "npm i x"}})))
    assert hook.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


# ---- review of 8605b68: nothing unverifiable may pass silently ---------------------------------------------------
def _asks(cmd, cwd, env=None):
    from skedaddle_mcp.hook import plan

    return plan(cmd, cwd, env or {})[1]


def test_alias_checks_the_real_package(tmp_path):
    from skedaddle_mcp.hook import plan

    assert plan("npm install lodash@npm:evil-pkg@1.0.0", str(tmp_path), {})[0] == [("npm", "evil-pkg@1.0.0")]


def test_git_url_and_custom_registries_ask(tmp_path):
    cwd = str(tmp_path)
    for cmd in ("npm install user/repo", "npm install github:user/repo", "npm i https://x.test/p.tgz",
                "pip install git+https://github.com/x/y", "pip install https://x.test/p.whl",
                "npm install axios --registry https://evil.test", "pip install requests -i https://evil.test/simple",
                "uv pip install requests --extra-index-url https://evil.test"):
        assert _asks(cmd, cwd), cmd
    assert _asks("npm install axios", cwd, {"npm_config_registry": "https://evil.test"})
    assert _asks("pip install requests", cwd, {"PIP_INDEX_URL": "https://evil.test"})


def test_per_manager_flags(tmp_path):
    from skedaddle_mcp.hook import plan

    cwd = str(tmp_path)
    assert plan("npm install -e axios", cwd, {})[0] == [("npm", "axios")]  # npm has no -e value flag
    assert plan("pnpm add -w lodash", cwd, {})[0] == [("npm", "lodash")]  # pnpm -w is boolean
    assert plan("pip install -e . requests", cwd, {})[0] == [("pypi", "requests")]
    assert plan("npm exec -- cowsay hi", cwd, {})[0] == [("npm", "cowsay")]
    assert plan("npm create vite@5.0.0", cwd, {})[0] == [("npm", "create-vite@5.0.0")]
    assert plan("npm it left-pad", cwd, {})[0] == [("npm", "left-pad")]
    assert plan("sudo -u node npm i left-pad", cwd, {})[0] == [("npm", "left-pad")]
    assert plan("bash -c 'npm i left-pad'", cwd, {})[0] == [("npm", "left-pad")]


def test_cd_changes_the_manifest_dir(tmp_path):
    from skedaddle_mcp.hook import plan

    sub = tmp_path / "web"
    sub.mkdir()
    (sub / "package.json").write_text(json.dumps({"dependencies": {"new-dep": "1.0.0"}}))
    assert plan("cd web && npm install", str(tmp_path), {})[0] == [("npm", "new-dep@1.0.0")]


def test_too_many_targets_ask(tmp_path):
    assert _asks("npm i " + " ".join(f"p{i}" for i in range(80)), str(tmp_path))


def test_requirements_includes_and_index_lines(tmp_path):
    from skedaddle_mcp.hook import plan

    (tmp_path / "base.txt").write_text("flask==3.0.0\n")
    (tmp_path / "req.txt").write_text("-r base.txt\nrequests==2.32.3\n")
    assert sorted(plan("pip install -r req.txt", str(tmp_path), {})[0]) == [("pypi", "flask==3.0.0"), ("pypi", "requests==2.32.3")]
    (tmp_path / "evil.txt").write_text("--index-url https://evil.test/simple\nrequests\n")
    assert _asks("pip install -r evil.txt", str(tmp_path))


def test_lockfile_entries_changed_since_head_are_checked(tmp_path):
    import subprocess

    from skedaddle_mcp.hook import plan

    g = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)
    g("init", "-q")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"axios": "^1.0.0"}}))
    lock = {"packages": {"node_modules/axios": {"version": "1.15.2"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    g("add", "-A")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
    lock["packages"]["node_modules/axios"]["version"] = "1.14.1"  # the agent edits the lockfile directly
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    assert plan("npm ci", str(tmp_path), {})[0] == [("npm", "axios@1.14.1")]


# ---- review of 6e13197 ---------------------------------------------------------------------------------------------
def test_more_unverifiable_sources_ask(tmp_path):
    cwd = str(tmp_path)
    for cmd in ("npm i x@gitlab:a/b", "npm i x@user/repo", "npm i x@git+ssh://git@h/r.git", "pip install 'pkg @ https://x.test/p.whl'",
                "pip install -e git+https://github.com/x/y#egg=y", "npm i axios --@acme:registry=https://evil.test",
                "npm i axios --userconfig ./evil.npmrc"):
        assert _asks(cmd, cwd), cmd
    assert _asks("pip install requests", cwd, {"PIP_CONFIG_FILE": "/tmp/pip.conf"})
    (tmp_path / ".npmrc").write_text("registry=https://evil.test/\n")
    assert _asks("npm i axios", cwd)


def test_requirements_direct_reference_asks(tmp_path):
    (tmp_path / "r.txt").write_text("pkg @ https://x.test/p.whl\n")
    assert _asks("pip install -r r.txt", str(tmp_path))


def test_shell_flags_and_env_s(tmp_path):
    from skedaddle_mcp.hook import plan

    cwd = str(tmp_path)
    assert plan("bash -lc 'npm i left-pad'", cwd, {})[0] == [("npm", "left-pad")]
    assert plan("env -S 'npm i left-pad'", cwd, {})[0] == [("npm", "left-pad")]


def test_lockfile_without_head_checks_direct_deps_and_foreign_resolved_asks(tmp_path):
    from skedaddle_mcp.hook import plan

    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"axios": "^1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/axios": {
        "version": "1.14.1", "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"}}}))
    assert plan("npm ci", str(tmp_path), {})[0] == [("npm", "axios@1.14.1")]  # no git baseline: direct deps checked
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/axios": {
        "version": "1.15.2", "resolved": "https://evil.test/axios-1.15.2.tgz"}}}))
    assert _asks("npm ci", str(tmp_path))
