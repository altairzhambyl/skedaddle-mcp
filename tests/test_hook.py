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


# ---- independent review of 8605b68 + review of 2c79f51 ---------------------------------------------------------------
def test_more_commands(tmp_path):
    from skedaddle_mcp.hook import plan

    cwd = str(tmp_path)
    cases = {
        "python3.12 -m pip install httpx": [("pypi", "httpx")],
        "pip3.12 install httpx": [("pypi", "httpx")],
        "uv tool install ruff": [("pypi", "ruff")],
        "uv run --with rich python x.py": [("pypi", "rich")],
        "poetry add requests": [("pypi", "requests")],
        "cargo add serde": [("crates", "serde")],
        "cargo install ripgrep": [("crates", "ripgrep")],
        "timeout 60 npm i left-pad": [("npm", "left-pad")],
        "bash -o pipefail -c 'npm i left-pad'": [("npm", "left-pad")],
    }
    for cmd, want in cases.items():
        assert plan(cmd, cwd, {})[0] == want, cmd


def test_registry_lookalikes_and_env_s_assignments_ask(tmp_path):
    cwd = str(tmp_path)
    assert _asks("npm i axios --registry https://registry.npmjs.org@evil.test/", cwd)
    assert _asks("npm i axios --registry http://registry.npmjs.org/", cwd)  # not https
    assert _asks("env -S 'npm_config_registry=https://evil.test npm i axios'", cwd)
    assert _asks("env npm_config_registry=https://evil.test npm i axios", cwd)
    assert not _asks("npm i axios --registry https://registry.npmjs.org/", cwd)
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n@acme:registry=https://evil.test/\n")
    assert _asks("npm i axios", cwd)  # every registry line, not the first


def test_hook_time_budget_asks(registry, tmp_path, monkeypatch):
    import time

    from skedaddle_mcp import hook

    monkeypatch.setenv("SKEDADDLE_HOOK_BUDGET", "1")
    monkeypatch.setattr(hook, "check_package", lambda *a, **k: time.sleep(5))
    t = time.time()
    out = hook.decide("npm i a b c", str(tmp_path), {})
    assert time.time() - t < 3 and out["hookSpecificOutput"]["permissionDecision"] == "ask"


# ---- review of 9e0c8bf ----------------------------------------------------------------------------------------------
def test_shell_option_clusters_with_values(tmp_path):
    from skedaddle_mcp.hook import plan

    cwd = str(tmp_path)
    assert plan("bash -eo pipefail -c 'npm i left-pad'", cwd, {})[0] == [("npm", "left-pad")]
    assert plan("bash -co pipefail 'npm i left-pad'", cwd, {})[0] == [("npm", "left-pad")]


def test_cargo_and_poetry_custom_sources_ask(tmp_path):
    cwd = str(tmp_path)
    assert _asks("cargo add serde --config 'source.crates-io.replace-with=\"evil\"'", cwd)
    assert _asks("cargo add serde", cwd, {"CARGO_REGISTRIES_EVIL_INDEX": "https://evil.test"})
    assert _asks("poetry add requests --source evil", cwd)
    assert _asks("poetry add requests", cwd, {"POETRY_REPOSITORIES_EVIL_URL": "https://evil.test"})
    (tmp_path / ".cargo").mkdir()
    (tmp_path / ".cargo" / "config.toml").write_text('[source.crates-io]\nreplace-with = "evil"\n')
    assert _asks("cargo add serde", cwd)
    (tmp_path / "pyproject.toml").write_text('[[tool.poetry.source]]\nname = "evil"\nurl = "https://evil.test/simple"\n')
    assert _asks("poetry add requests", cwd)
    import tempfile

    # a subdirectory INHERITS the parent's pyproject (poetry/uv look upward); only a project-less tree is clean
    assert _asks("poetry add requests", str(tmp_path / ".cargo"))
    assert not _asks("poetry add requests", tempfile.mkdtemp())


def test_hook_process_exits_after_answering(tmp_path):
    """A check still running in a thread must not keep the process alive past the answer (budget defeated)."""
    import subprocess
    import sys
    import time

    code = ("import time, skedaddle_mcp.hook as h; h.check_package = lambda *a, **k: time.sleep(30); "
            "import sys; sys.argv = ['skedaddle-mcp', 'hook']; from skedaddle_mcp.cli import main; main()")
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "npm i a"}, "cwd": str(tmp_path)})
    t = time.time()
    r = subprocess.run([sys.executable, "-c", code], check=False, input=payload, capture_output=True, text=True, timeout=25,
                       env={**__import__("os").environ, "SKEDADDLE_HOOK_BUDGET": "1"})
    assert time.time() - t < 10, "the process waited for the abandoned check"
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


# ---- review of 5926631 ----------------------------------------------------------------------------------------------
def test_python_project_sources_found_like_the_tools_do(tmp_path):
    cwd = str(tmp_path)
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[tool.uv]\nindex-url = "https://evil.test/simple"\n')
    assert _asks("uv add requests", str(proj / "src"))  # found in a parent, like uv does
    assert _asks("uv add requests --project proj", cwd)
    (proj / "pyproject.toml").write_text('[[tool.uv.index]]\nname = "x"\nurl = "https://evil.test/simple"\n')
    assert _asks("uv pip install requests", str(proj))
    (proj / "pyproject.toml").write_text('[tool.uv.sources]\nrequests = { git = "https://github.com/x/y" }\n')
    assert _asks("uv add requests", str(proj))
    (proj / "pyproject.toml").write_text("[tool.uv\nbroken")
    assert _asks("uv add requests", str(proj))  # unparseable config: cannot tell, ask
    (proj / "pyproject.toml").write_text('[project]\nname = "ok"\n')
    assert not _asks("uv add requests", str(proj))


def test_cargo_config_parsed_at_any_depth_and_cargo_home(tmp_path):
    cwd = str(tmp_path)
    home = tmp_path / "ch"
    home.mkdir()
    (home / "config.toml").write_text('[registry]\ndefault = "evil"\n')
    assert _asks("cargo add serde", cwd, {"CARGO_HOME": str(home)})
    (home / "config.toml").write_text('[net]\nretry = 2\n')
    assert not _asks("cargo add serde", cwd, {"CARGO_HOME": str(home)})
    (home / "config.toml").write_text("[source\nbroken")
    assert _asks("cargo add serde", cwd, {"CARGO_HOME": str(home)})


def test_shell_getopt_clusters(tmp_path):
    from skedaddle_mcp.hook import plan

    cwd = str(tmp_path)
    assert plan("bash -opipefail -c 'npm i left-pad'", cwd, {})[0] == [("npm", "left-pad")]  # value glued to -o
    assert plan("zsh -eo pipefail -c 'npm i left-pad'", cwd, {})[0] == [("npm", "left-pad")]
    assert _asks("bash -c", cwd)  # -c with no command string: cannot tell what runs


def test_shell_cluster_with_o_and_c(tmp_path):
    """review of 328712e: `-oc` / `-co`: with -c present, every remaining word is walked (an extra check, never a skip)."""
    from skedaddle_mcp.hook import plan

    cwd = str(tmp_path)
    assert ("npm", "left-pad") in plan("bash -oc pipefail 'npm i left-pad'", cwd, {})[0]
    assert ("npm", "left-pad") in plan("bash -co pipefail 'npm i left-pad'", cwd, {})[0]
