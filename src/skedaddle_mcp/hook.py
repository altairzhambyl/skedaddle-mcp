"""Agent pre-install hook (Claude Code PreToolUse on Bash; any harness that can run a command before a shell call).

Reads the hook JSON on stdin, finds package installs in the command, checks them, and answers:
  block -> deny (the agent must not install; the user can still run it themselves, e.g. `! npm install x`)
  warn  -> allow, with the findings added to the agent's context
  unverifiable -> ask the user (offline, a git/URL source, a custom registry or index, too many packages) unless
                  SKEDADDLE_ON_ERROR=allow|deny
Rule: what cannot be checked is asked about, never silently allowed. A bare `npm install` / `npm ci` / `pip install -r`
is checked through the manifest and the lockfile: dependencies the lockfile does not pin yet, and lockfile entries that
changed since git HEAD (the "agent edits package.json or the lockfile, then installs" path).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from typing import Any

from .core import check_package, parse_spec

SEP = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
NPM_LIKE = {"npm", "pnpm", "yarn", "bun"}
NPM_INSTALL = {"install", "i", "add", "a", "in", "isntall", "install-test", "it"}
NPM_BARE = {"install", "i", "ci", "clean-install", "install-clean", "add", "it", "install-test"}
NPM_EXEC = {"exec", "x", "dlx"}
RUNNERS = {"npx", "pnpx", "bunx"}
# value-taking options per tool family; an option not listed is boolean (its next word is an operand, so it is CHECKED)
NPM_VALUES = {
    "--registry",
    "--prefix",
    "--cache",
    "--tag",
    "--workspace",
    "--userconfig",
    "--globalconfig",
    "-C",
    "--dir",
    "--filter",
    "-F",
    "--package",
    "-p",
    "--call",
    "-c",
    "--node-version",
    "--reporter",
    "--network-concurrency",
}
PNPM_BOOL = {"-w", "--workspace-root"}
PIP_VALUES = {
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-e",
    "--editable",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
    "-p",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--src",
    "--log",
    "--trusted-host",
    "--upgrade-strategy",
    "--report",
    "-C",
    "--config-settings",
    "--no-binary",
    "--only-binary",
    "--progress-bar",
    "--with",
    "--from",
    "--group",
    "--extra",
    "--index",
    "--default-index",
    "--with-requirements",
    "--cache-dir",
    "--directory",
    "--project",
}
REGISTRY_FLAGS = {"--registry", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index", "--default-index"}
REGISTRY_ENV = (
    "npm_config_registry",
    "NPM_CONFIG_REGISTRY",
    "YARN_REGISTRY",
    "YARN_NPM_REGISTRY_SERVER",
    "BUN_CONFIG_REGISTRY",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_FIND_LINKS",
    "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_INDEX",
    "UV_DEFAULT_INDEX",
    "UV_FIND_LINKS",
)
WRAPPER_OPTS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"},
    "nice": {"-n"},
    "env": {"-u", "-C", "-S"},
    "time": {"-f", "-o"},
    "nohup": set(),
    "command": set(),
    "exec": {"-a"},
    "timeout": {"-s", "-k"},
}
SHELLS = {"sh", "bash", "zsh", "dash"}
MAX_TARGETS = 50
LOCAL = re.compile(r"^(\.{0,2}/|~|file:|link:|workspace:|portal:)")
REMOTE = re.compile(r"^(git(\+[a-z]+)?:|[a-z]+\+https?:|https?:|github:|gitlab:|bitbucket:|gist:)|^[\w.-]+/[\w.-]+(#.*)?$")


class Plan:
    def __init__(self, env: dict[str, str]):
        self.env, self.targets, self.asks = env, [], []

    def add(self, eco: str, spec: str) -> None:
        if LOCAL.match(spec) or spec in (".", ".."):
            return  # local code the user already has
        if REMOTE.match(spec) or spec.endswith((".tgz", ".tar.gz", ".whl", ".zip")):
            self.asks.append(f"{spec}: a git/URL/tarball source, not a registry package skedaddle can check")
            return
        if eco == "npm":
            m = re.match(r"^(@?[^@]+)@npm:(.+)$", spec)  # alias: x@npm:real@1.0.0 installs `real`
            if m:
                spec = m[2]
        self.targets.append((eco, spec))


def _words(seg: str) -> list[str]:
    try:
        w = shlex.split(seg)
    except ValueError:
        w = seg.split()
    while w:
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w[0]):
            w = w[1:]
            continue
        base = os.path.basename(w[0])
        if base in WRAPPER_OPTS:
            i = 1
            while i < len(w) and w[i].startswith("-"):
                i += 2 if w[i] in WRAPPER_OPTS[base] else 1
            if base == "timeout" and i < len(w):
                i += 1  # the duration
            w = w[i:]
            continue
        break
    return w


def _env_assignments(seg: str) -> dict[str, str]:
    try:
        w = shlex.split(seg)
    except ValueError:
        return {}
    out = {}
    for t in w:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", t)
        if not m:
            break
        out[m[1]] = m[2]
    return out


def _operands(
    args: list[str], values: set[str], booleans: frozenset[str] = frozenset()
) -> tuple[list[str], dict[str, list[str]]]:
    ops: list[str] = []
    flags: dict[str, list[str]] = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            ops += args[i + 1 :]
            break
        if a.startswith("-") and a != "-":
            name, eq, val = a.partition("=")
            if eq:
                flags.setdefault(name, []).append(val)
            elif a in values and a not in booleans and i + 1 < len(args):
                flags.setdefault(a, []).append(args[i + 1])
                i += 1
            else:
                flags.setdefault(a, [])
        else:
            ops.append(a)
        i += 1
    return ops, flags


def _pypi_name(spec: str) -> str:
    """'requests>=2' -> 'requests' (a range: latest is checked); 'requests==2.32.3' stays exact."""
    if "==" in spec and not re.search(r"[<>!~,]", spec):
        return spec.split(";")[0].strip()
    return re.split(r"[<>=!~;,\s\[]", spec, maxsplit=1)[0]


def _registry_override(flags: dict[str, list[str]], env: dict[str, str]) -> str | None:
    hit = next((f for f in flags if f in REGISTRY_FLAGS), None)
    if hit:
        return f"{hit} {' '.join(flags[hit])[:80]}"
    return next((f"{k}={env[k][:80]}" for k in REGISTRY_ENV if env.get(k)), None)


def plan(command: str, cwd: str, env: dict[str, str] | None = None, depth: int = 0) -> tuple[list[tuple[str, str]], list[str]]:
    """([(ecosystem, spec)] to check, [reasons to ask the user]) for a shell command."""
    p = Plan(dict(os.environ if env is None else env))
    _walk(command, cwd, p, depth)
    tg = list(dict.fromkeys(p.targets))
    if len(tg) > MAX_TARGETS:
        p.asks.append(f"{len(tg)} packages in one command (over {MAX_TARGETS}): too many to check before it runs")
        tg = tg[:MAX_TARGETS]
    return tg, p.asks


def _walk(command: str, cwd: str, p: Plan, depth: int) -> None:
    for seg in SEP.split(command):
        env = {**p.env, **_env_assignments(seg)}
        w = _words(seg)
        if not w:
            continue
        prog, args = os.path.basename(w[0]), w[1:]
        if prog == "cd" and args:
            cwd = os.path.normpath(os.path.join(cwd, os.path.expanduser(args[0])))
            continue
        if prog in SHELLS and len(args) >= 2 and args[0] == "-c" and depth < 3:
            _walk(args[1], cwd, p, depth + 1)
            continue
        if prog in ("python", "python3") and args[:2] == ["-m", "pip"]:
            prog, args = "pip", args[2:]
        if prog in RUNNERS:
            ops, fl = _operands(args, NPM_VALUES)
            _reg(p, fl, env)
            for s in (fl.get("--package", []) + fl.get("-p", [])) or ops[:1]:
                p.add("npm", s)
        elif prog in NPM_LIKE:
            ops, fl = _operands(args, NPM_VALUES, frozenset(PNPM_BOOL) if prog == "pnpm" else frozenset())
            _reg(p, fl, env)
            sub = ops[0] if ops else ("install" if prog == "yarn" else "")
            rest = ops[1:]
            if sub == "global" and rest:  # yarn global add x
                sub, rest = rest[0], rest[1:]
            if sub in NPM_EXEC or (prog == "bun" and sub == "x"):
                for s in (fl.get("--package", []) + fl.get("-p", [])) or rest[:1]:
                    p.add("npm", s)
            elif sub in ("create", "init") and rest and not rest[0].startswith("-"):
                name = rest[0]
                if name.startswith("@"):
                    scope, _, nm = name.partition("/")
                    p.add("npm", f"{scope}/create-{nm}" if nm else f"{scope}/create")
                else:
                    p.add("npm", f"create-{name}")
            elif sub in NPM_INSTALL and rest:
                for s in rest:
                    p.add("npm", s)
            elif sub in NPM_BARE or (prog == "yarn" and not ops):
                for s in _npm_manifest_delta(cwd) + _npm_lock_changes(cwd):
                    p.add("npm", s)
        elif prog in ("pip", "pip3") or (prog == "uv" and args[:1] == ["pip"]):
            a = args[1:] if prog == "uv" else args
            if a[:1] in (["install"], ["sync"]):
                ops, fl = _operands(a[1:], PIP_VALUES)
                _reg(p, fl, env)
                for o in ops[1:] if a[:1] == ["sync"] else ops:
                    p.add("pypi", _pypi_name(o) if not REMOTE.match(o) else o)
                for f in fl.get("-r", []) + fl.get("--requirement", []) + (ops[:1] if a[:1] == ["sync"] else []):
                    _requirements(os.path.join(cwd, f), p, set())
        elif prog == "uv" and args[:1] == ["add"]:
            ops, fl = _operands(args[1:], PIP_VALUES)
            _reg(p, fl, env)
            for o in ops:
                p.add("pypi", _pypi_name(o) if not REMOTE.match(o) else o)
        elif prog in ("uvx", "pipx"):
            a = args[1:] if prog == "pipx" and args[:1] in (["install"], ["run"], ["inject"]) else args
            ops, fl = _operands(a, PIP_VALUES)
            _reg(p, fl, env)
            for s in (fl.get("--from", []) or ops[:1]) + fl.get("--with", []):
                p.add("pypi", _pypi_name(s) if not REMOTE.match(s) else s)


def _reg(p: Plan, flags: dict[str, list[str]], env: dict[str, str]) -> None:
    why = _registry_override(flags, env)
    if why:
        p.asks.append(f"custom registry/index ({why}): packages would come from a source skedaddle does not check")


def _npm_manifest_delta(cwd: str) -> list[str]:
    try:
        with open(os.path.join(cwd, "package.json"), encoding="utf-8") as fh:
            pkg = json.load(fh)
    except (OSError, ValueError):
        return []
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {}), **(pkg.get("optionalDependencies") or {})}
    locked = _lock_versions(_read(os.path.join(cwd, "package-lock.json")))
    out = []
    for name, rng in deps.items():
        rng = str(rng)
        if name in locked:
            continue  # pinned; lockfile changes are checked by _npm_lock_changes
        if rng.startswith("npm:"):
            out.append(f"{name}@{rng}")
        elif LOCAL.match(rng) or REMOTE.match(rng):
            out.append(rng)
        else:
            out.append(f"{name}@{rng}" if re.match(r"^\d+\.\d+\.\d+$", rng) else name)
    return out


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _lock_versions(text: str) -> dict[str, str]:
    try:
        pk = (json.loads(text) if text else {}).get("packages") or {}
    except ValueError:
        return {}
    return {
        k.rsplit("node_modules/", 1)[-1]: m["version"]
        for k, m in pk.items()
        if "node_modules/" in k and isinstance(m, dict) and m.get("version")
    }


def _npm_lock_changes(cwd: str) -> list[str]:
    """Lockfile entries that are new or changed since git HEAD: a direct lockfile edit installs without a manifest change."""
    now = _lock_versions(_read(os.path.join(cwd, "package-lock.json")))
    if not now:
        return []
    try:
        r = subprocess.run(["git", "-C", cwd, "show", "HEAD:./package-lock.json"], check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    if r.returncode != 0:
        return []  # not committed yet: the manifest delta covers a fresh project
    head = _lock_versions(r.stdout)
    return [f"{n}@{v}" for n, v in sorted(now.items()) if head.get(n) != v]


def _requirements(path: str, p: Plan, seen: set[str]) -> None:
    real = os.path.realpath(path)
    if real in seen or len(seen) > 20:
        return
    seen.add(real)
    text = _read(path)
    if not text and not os.path.exists(path):
        p.asks.append(f"{path}: requirements file not found, cannot check what it installs")
        return
    for raw in text.splitlines():
        ln = raw.split(" #", 1)[0].strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("-"):
            opt, _, val = ln.partition(" ")
            opt, eq, v2 = opt.partition("=")
            val = (v2 if eq else val).strip()
            if opt in ("-r", "--requirement", "-c", "--constraint"):
                _requirements(os.path.join(os.path.dirname(path), val), p, seen)
            elif opt in REGISTRY_FLAGS:
                p.asks.append(
                    f"{os.path.basename(path)} sets {opt} {val[:80]}: packages would come from a source skedaddle does not check"
                )
            elif opt in ("-e", "--editable"):
                p.add("pypi", val)
            continue
        p.add("pypi", _pypi_name(ln) if not REMOTE.match(ln) else ln)


def targets(command: str, cwd: str) -> list[tuple[str, str]]:
    """Packages the command would fetch (see `plan` for the reasons to ask as well)."""
    return plan(command, cwd, {})[0]


def decide(command: str, cwd: str, env: dict[str, str] | None = None) -> dict[str, Any] | None:
    tg, asks = plan(command, cwd, env)
    if not tg and not asks:
        return None
    blocks, warns, errors = [], [], list(asks)
    for eco, spec in tg:
        try:
            name, version = parse_spec(eco, spec)
        except ValueError as e:
            errors.append(str(e))
            continue
        rep = check_package(eco, name, version)
        label = f"{eco}:{name}{'@' + rep.version if rep.version else ''}"
        shown = [f for f in rep.findings if f.severity != "info" and (rep.verdict != "block" or f.severity == "block")]
        lines = [f"{label}: {f.message}" + (f" ({f.source})" if f.source else "") for f in shown]
        {"block": blocks, "warn": warns, "error": errors}.get(rep.verdict, []).extend(lines)
    if blocks:
        return _out(
            "deny",
            "skedaddle blocked this install:\n- "
            + "\n- ".join(blocks[:8])
            + "\nDo not retry with another spelling or a mirror. If the user trusts it, they can run the command themselves.",
        )
    if errors:
        mode = os.environ.get("SKEDADDLE_ON_ERROR", "ask")
        return _out(mode if mode in ("allow", "deny") else "ask", "skedaddle could not verify:\n- " + "\n- ".join(errors[:6]))
    if warns:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": "skedaddle warnings (install allowed):\n- " + "\n- ".join(warns[:8]),
            }
        }
    return None


def _out(decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}
    }


def main() -> int:
    try:
        data = json.loads(sys.stdin.read(4_000_000) or "{}")
    except ValueError:
        return 0  # not a hook payload: nothing to judge
    if data.get("tool_name") != "Bash":
        return 0
    cmd = (data.get("tool_input") or {}).get("command") or ""
    try:
        res = decide(cmd, data.get("cwd") or os.getcwd())
    except Exception as e:  # noqa: BLE001 — last line of defence: a crash would print nothing = allow; ask instead
        res = _out("ask", f"skedaddle failed while checking this command ({type(e).__name__}: {str(e)[:160]})")
    if res:
        print(json.dumps(res))
    return 0
