"""Agent pre-install hook (Claude Code PreToolUse on Bash; any harness that can run a command before a shell call).

Reads the hook JSON on stdin, finds package installs in the command, checks them, and answers:
  block -> deny (the agent must not install; the user can still run it themselves, e.g. `! npm install x`)
  warn  -> allow, with the findings added to the agent's context
  error -> ask the user (could not verify: offline, registry down) unless SKEDADDLE_ON_ERROR=allow|deny
A bare `npm install` / `pip install -r` is checked through the manifest: dependencies the lockfile does not pin yet
(the "agent edits package.json, then runs npm install" path).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from typing import Any

from .core import check_package, parse_spec

SEP = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")
WRAPPERS = {"sudo", "time", "nice", "nohup", "command", "exec", "env"}
NPM_LIKE = {"npm", "pnpm", "yarn", "bun"}
INSTALL = {"install", "i", "add", "a", "in", "isntall"}
RUNNERS = {"npx", "pnpx", "bunx"}
VALUE_FLAGS = {
    "--registry",
    "--prefix",
    "-C",
    "--dir",
    "--filter",
    "-F",
    "--workspace",
    "-w",
    "--cache",
    "--tag",
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-i",
    "--index-url",
    "--extra-index-url",
    "--python",
    "-p",
    "--package",
    "--with",
    "--from",
    "-e",
    "--editable",
    "--target",
    "-t",
    "--group",
    "--extra",
}
MAX_TARGETS = 50


def _words(seg: str) -> list[str]:
    try:
        w = shlex.split(seg)
    except ValueError:
        w = seg.split()
    while w and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w[0]) or w[0] in WRAPPERS):
        w = w[1:]
    return w


def _operands(args: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    ops, flags, i = [], {}, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            ops += args[i + 1 :]
            break
        if a.startswith("-"):
            name, _, val = a.partition("=")
            if val:
                flags.setdefault(name, []).append(val)
            elif a in VALUE_FLAGS and i + 1 < len(args):
                flags.setdefault(a, []).append(args[i + 1])
                i += 1
            else:
                flags.setdefault(a, [])
        else:
            ops.append(a)
        i += 1
    return ops, flags


def _local(spec: str) -> bool:
    return bool(
        re.match(r"^(\.{0,2}/|~|file:|link:|workspace:|git(\+\w+)?:|https?:|github:|[\w.-]+/[\w.-]+$)", spec)
    ) or spec.endswith((".tgz", ".tar.gz", ".whl", ".zip"))


def _pypi_name(spec: str) -> str:
    """'requests>=2' -> 'requests' (a range: latest is checked); 'requests==2.32.3' stays exact."""
    if "==" in spec and not re.search(r"[<>!~,]", spec):
        return spec.split(";")[0].strip()
    return re.split(r"[<>=!~;,\s\[]", spec, maxsplit=1)[0]


def targets(command: str, cwd: str) -> list[tuple[str, str]]:
    """[(ecosystem, spec)] the command would fetch; manifest deltas for bare installs."""
    out: list[tuple[str, str]] = []
    for seg in SEP.split(command):
        w = _words(seg)
        if not w:
            continue
        prog, args = os.path.basename(w[0]), w[1:]
        if prog in ("python", "python3") and args[:2] == ["-m", "pip"]:
            prog, args = "pip", args[2:]
        if prog in RUNNERS or (prog in ("pnpm", "yarn") and args[:1] == ["dlx"]) or (prog == "bun" and args[:1] == ["x"]):
            ops, fl = _operands(args[1:] if prog not in RUNNERS else args)
            pk = fl.get("--package", []) + fl.get("-p", [])
            out += [("npm", p) for p in (pk or ops[:1]) if not _local(p)]
        elif prog in NPM_LIKE:
            ops, fl = _operands(args)
            sub = ops[0] if ops else ("install" if prog == "yarn" else "")
            if sub == "global" and len(ops) > 1:  # yarn global add x
                ops = ops[1:]
                sub = ops[0]
            if sub in INSTALL or (prog == "yarn" and not ops):
                specs = [o for o in ops[1:] if not _local(o)]
                out += [("npm", s) for s in specs] if specs or ops[1:] else _npm_manifest_delta(cwd)
        elif prog in ("pip", "pip3") or (prog == "uv" and args[:1] == ["pip"]):
            a = args[1:] if prog == "uv" else args
            if a[:1] == ["install"]:
                ops, fl = _operands(a[1:])
                out += [("pypi", _pypi_name(o)) for o in ops if not _local(o)]
                out += [
                    ("pypi", s)
                    for f in fl.get("-r", []) + fl.get("--requirement", [])
                    for s in _requirements(os.path.join(cwd, f))
                ]
        elif prog == "uv" and args[:1] == ["add"]:
            ops, _ = _operands(args[1:])
            out += [("pypi", _pypi_name(o)) for o in ops if not _local(o)]
        elif prog in ("uvx", "pipx"):
            ops, fl = _operands(args[1:] if prog == "pipx" and args[:1] in (["install"], ["run"]) else args)
            out += [("pypi", _pypi_name(p)) for p in (fl.get("--from", []) or ops[:1]) + fl.get("--with", []) if not _local(p)]
    return list(dict.fromkeys(out))[:MAX_TARGETS]


def _npm_manifest_delta(cwd: str) -> list[tuple[str, str]]:
    try:
        with open(os.path.join(cwd, "package.json"), encoding="utf-8") as fh:
            pkg = json.load(fh)
    except (OSError, ValueError):
        return []
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {}), **(pkg.get("optionalDependencies") or {})}
    locked: dict[str, str] = {}
    try:
        with open(os.path.join(cwd, "package-lock.json"), encoding="utf-8") as fh:
            for k, m in (json.load(fh).get("packages") or {}).items():
                if k.startswith("node_modules/") and m.get("version"):
                    locked[k[len("node_modules/") :]] = m["version"]
    except (OSError, ValueError):
        pass
    out = []
    for name, rng in deps.items():
        if name in locked or _local(str(rng)):
            continue  # pinned already (checked when it was added) or a local/git dependency
        exact = re.match(r"^\d+\.\d+\.\d+$", str(rng))
        out.append(("npm", f"{name}@{rng}" if exact else name))
    return out


def _requirements(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = [ln.split("#", 1)[0].strip() for ln in fh]
    except OSError:
        return []
    return [_pypi_name(ln) for ln in lines if ln and not ln.startswith("-") and not _local(ln)]


def decide(command: str, cwd: str) -> dict[str, Any] | None:
    tg = targets(command, cwd)
    if not tg:
        return None
    blocks, warns, errors = [], [], []
    for eco, spec in tg:
        try:
            name, version = parse_spec(eco, spec)
        except ValueError as e:
            errors.append(str(e))
            continue
        rep = check_package(eco, name, version)
        label = f"{eco}:{name}{'@' + rep.version if rep.version else ''}"
        lines = [f"{label}: {f.message}" + (f" ({f.source})" if f.source else "") for f in rep.findings if f.severity != "info"]
        {"block": blocks, "warn": warns, "error": errors}.get(rep.verdict, []).extend(
            [
                ln
                for ln, f in zip(lines, [f for f in rep.findings if f.severity != "info"])
                if rep.verdict != "block" or f.severity == "block"
            ]
        )
    if blocks:
        return _out(
            "deny",
            "skedaddle blocked this install:\n- "
            + "\n- ".join(blocks[:8])
            + "\nDo not retry with another spelling or a mirror. If the user trusts it, they can run the command themselves.",
        )
    if errors:
        mode = os.environ.get("SKEDADDLE_ON_ERROR", "ask")
        why = "skedaddle could not verify: " + "; ".join(errors[:4])
        return _out(mode if mode in ("allow", "deny") else "ask", why)
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
    res = decide(cmd, data.get("cwd") or os.getcwd())
    if res:
        print(json.dumps(res))
    return 0
