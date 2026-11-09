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
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any

from .config import load as load_config
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
REGISTRY_FLAGS = {
    "--registry",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--index",
    "--default-index",
    "--userconfig",
    "--globalconfig",
    "--config-file",
}
OFFICIAL_HOSTS = {"registry.npmjs.org": "", "registry.yarnpkg.com": "", "pypi.org": "/simple", "files.pythonhosted.org": ""}


_ACTIVE: list = [None]  # the Config of the command being planned (trusted mirrors count as official)


def official(url: str) -> bool:
    cfg = _ACTIVE[0]
    if cfg is not None and cfg.trusted(url):
        return True
    return _public_official(url)


def _public_official(url: str) -> bool:
    """https, no user:password@, an exact official host (pypi.org only under /simple)."""
    try:
        u = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return False
    if u.scheme != "https" or u.username or u.password or u.port not in (None, 443) or u.hostname not in OFFICIAL_HOSTS:
        return False
    prefix = OFFICIAL_HOSTS[u.hostname]
    return not prefix or u.path == prefix or u.path.startswith(prefix + "/")


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
    "NPM_CONFIG_USERCONFIG",
    "npm_config_userconfig",
    "NPM_CONFIG_GLOBALCONFIG",
    "PIP_CONFIG_FILE",
    "UV_CONFIG_FILE",
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
            ver = re.match(r"^@?[^@]+@(.+)$", spec)
            if ver and re.search(r"[:/]", ver[1]):  # x@gitlab:a/b, x@user/repo, x@git+ssh://...
                self.asks.append(f"{spec}: a git/URL source in the version, not a registry package skedaddle can check")
                return
        elif eco == "pypi":
            if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*@\s*\S", spec):  # PEP 508: name @ url
                self.asks.append(f"{spec}: a direct URL reference, not a registry package skedaddle can check")
                return
            spec = _pypi_name(spec)
        self.targets.append((eco, spec))


def _unwrap(seg: str) -> tuple[list[str], dict[str, str]]:
    """Program words of a shell segment with leading NAME=VALUE assignments, `env [-S 'cmd']`, sudo/nice/timeout...
    removed; the assignments (wherever they appeared) are returned so registry overrides set there are seen."""
    try:
        w = shlex.split(seg)
    except ValueError:
        w = seg.split()
    assigns: dict[str, str] = {}
    while w:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", w[0], re.DOTALL)
        if m:
            assigns[m[1]] = m[2]
            w = w[1:]
            continue
        base = os.path.basename(w[0])
        if base == "env":
            for j, t in enumerate(w[1:], 1):
                if not t.startswith("-"):
                    break
                split = (
                    w[j + 1]
                    if t in ("-S", "--split-string") and j + 1 < len(w)
                    else (
                        t.split("=", 1)[1]
                        if t.startswith("--split-string=")
                        else t[2:]
                        if t.startswith("-S") and len(t) > 2
                        else None
                    )
                )
                if split is not None:
                    inner, more = _unwrap(split)
                    rest = w[j + 2 :] if t in ("-S", "--split-string") else w[j + 1 :]
                    return inner + rest, {**assigns, **more}
        if base in WRAPPER_OPTS:
            i = 1
            while i < len(w) and w[i].startswith("-"):
                i += 2 if w[i] in WRAPPER_OPTS[base] else 1
            if base == "timeout" and i < len(w):
                i += 1  # the duration
            w = w[i:]
            continue
        break
    return w, assigns


def _words(seg: str) -> list[str]:
    return _unwrap(seg)[0]


SHELL_VALUE_OPTS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}


def _shell_command(args: list[str]) -> list[str] | None:
    """Candidate command strings of `sh -c ...`: None if no -c; [] if -c but nothing follows (the caller asks).
    Option values (`-o pipefail`, `-opipefail`, `-oc pipefail`) and the command are not told apart: with -c anywhere in
    the options, every non-option word is a candidate. Walking an extra word is an extra check, never a skip."""
    opts = [a for a in args if a.startswith(("-", "+")) and len(a) > 1 and not a.startswith("--")]
    if not any("c" in a[1:] for a in opts):
        return None
    return [a for a in args if not (a.startswith(("-", "+")) and len(a) > 1)]


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
    hit = next(
        (
            f
            for f in flags
            if (f in REGISTRY_FLAGS or re.match(r"^--@[^:]+:registry$", f)) and not all(official(v) for v in flags[f] or ["?"])
        ),
        None,
    )
    if hit:
        return f"{hit} {' '.join(flags[hit])[:80]}"
    return next((f"{k}={env[k][:80]}" for k in REGISTRY_ENV if env.get(k) and not official(env[k])), None)


def plan(command: str, cwd: str, env: dict[str, str] | None = None, depth: int = 0) -> tuple[list[tuple[str, str]], list[str]]:
    """([(ecosystem, spec)] to check, [reasons to ask the user]) for a shell command."""
    p = Plan(dict(os.environ if env is None else env))
    _ACTIVE[0] = load_config(cwd)
    _walk(command, cwd, p, depth)
    tg = list(dict.fromkeys(p.targets))
    if len(tg) > MAX_TARGETS:
        p.asks.append(f"{len(tg)} packages in one command (over {MAX_TARGETS}): too many to check before it runs")
        tg = tg[:MAX_TARGETS]
    return tg, p.asks


HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


DATA_SINKS = re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(cat|tee)\b")


def _is_data_sink(line: str, command: str) -> bool:
    """A heredoc is data only when a plain cat/tee writes it and nothing in the command runs the result: no pipe,
    chain or substitution on that line, and the file it writes is not mentioned again (`; bash x.sh`, `source x.sh`)."""
    if not DATA_SINKS.match(line) or re.search(r"[|;&]|\$\(|>\(|`", HEREDOC.sub("", line)):
        return False
    targets = [t for t in re.findall(r">>?\s*([^\s<>|;&]+)", HEREDOC.sub("", line)) if t != "/dev/null"]
    m = re.match(r"^\s*tee\s+(?:-a\s+)?([^\s<>|;&]+)", line)
    targets += [m[1]] if m else []
    rest = command.split(line, 1)[1] if line in command else ""
    return not any(os.path.basename(t) in rest for t in targets)


def _strip_heredocs(command: str) -> str:
    """Drop heredoc BODIES only when a plain data sink writes them (`cat > notes.md <<EOF`): text written to a file
    is not executed. Fed to anything else (bash, sh, ssh, python, a pipe) or written to a file the command later runs,
    the body IS executed, so its lines stay and are checked; an unterminated heredoc keeps its lines (fails closed)."""
    out: list[str] = []
    held: list[str] = []
    delim, dash, sink = None, False, False
    for line in command.split("\n"):
        if delim is not None:
            if (line.lstrip("\t") if dash else line) == delim:
                if not sink:
                    out.extend(held)
                held, delim = [], None
            else:
                held.append(line)
            continue
        out.append(line)
        m = HEREDOC.search(line)
        if m and "<<<" not in line:
            dash, delim, sink = bool(m[1]), m[3], _is_data_sink(line, command)
    return "\n".join(out + held)  # an unterminated heredoc's lines are kept


def _walk(command: str, cwd: str, p: Plan, depth: int) -> None:
    for seg in SEP.split(_strip_heredocs(command)):
        w, assigns = _unwrap(seg)
        env = {**p.env, **assigns}
        guard = _self_protection(seg, w, assigns)
        if guard:
            p.asks.append(guard)
            continue
        if not w:
            continue
        prog, args = os.path.basename(w[0]), w[1:]
        if prog in ("claude", "codex", "gemini", "cursor-agent") and args[:2] in (["mcp", "add"], ["mcp", "add-json"]):
            # registering an MCP server is installing a package that runs with the agent's rights (postmark-mcp 2025)
            if args[1] == "add":
                if "--" in args:
                    inner = args[args.index("--") + 1 :]
                else:  # claude mcp add [opts] NAME COMMAND [ARGS...]
                    rest, i = args[2:], 0
                    while i < len(rest) and rest[i].startswith("-"):
                        i += 2 if rest[i] in ("-s", "--scope", "-e", "--env", "-t", "--transport", "-H", "--header") else 1
                    inner = rest[i + 1 :]
                    if inner and re.match(r"^https?://", inner[0]):
                        inner = []  # a remote (http/sse) server: nothing is installed locally
                if inner and depth < 3:
                    _walk(shlex.join(inner), cwd, p, depth + 1)
            elif args[1] == "add-json":
                blob = next((a for a in args[2:] if a.lstrip().startswith("{")), None)
                try:
                    srv = json.loads(blob) if blob else {}
                except ValueError:
                    srv = {}
                if srv.get("command") and depth < 3:
                    _walk(shlex.join([str(srv["command"]), *[str(x) for x in srv.get("args") or []]]), cwd, p, depth + 1)
                elif blob and not srv.get("url"):
                    p.asks.append("MCP server config that skedaddle cannot read: cannot tell what it runs")
            continue
        if prog == "cd" and args:
            cwd = os.path.normpath(os.path.join(cwd, os.path.expanduser(args[0])))
            continue
        if prog in SHELLS:
            inner = _shell_command(args)
            if inner == []:
                p.asks.append(f"{prog} -c with no command string: cannot tell what runs")
                continue
            if inner is not None and depth < 3:
                for cand in inner:
                    _walk(cand, cwd, p, depth + 1)
                continue
        if re.match(r"^python(\d+(\.\d+)?)?$", prog) and args[:2] == ["-m", "pip"]:
            prog, args = "pip", args[2:]
        if prog in RUNNERS:
            ops, fl = _operands(args, NPM_VALUES)
            _reg(p, fl, env, cwd)
            for s in (fl.get("--package", []) + fl.get("-p", [])) or ops[:1]:
                p.add("npm", s)
        elif prog in NPM_LIKE:
            ops, fl = _operands(args, NPM_VALUES, frozenset(PNPM_BOOL) if prog == "pnpm" else frozenset())
            _reg(p, fl, env, cwd)
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
                for s in _npm_manifest_delta(cwd) + _npm_lock_changes(cwd, p):
                    p.add("npm", s)
        elif re.match(r"^pip(\d+(\.\d+)?)?$", prog) or (prog == "uv" and args[:1] == ["pip"]):
            a = args[1:] if prog == "uv" else args
            if a[:1] in (["install"], ["sync"]):
                ops, fl = _operands(a[1:], PIP_VALUES)
                _reg(p, fl, env)
                src = _python_project_source(cwd, fl) if prog == "uv" else None  # uv pip reads [tool.uv.pip] / uv.toml
                if src:
                    p.asks.append(f"custom package index ({src}): packages would come from a source skedaddle does not check")
                for o in ops[1:] if a[:1] == ["sync"] else ops:
                    p.add("pypi", o)
                for e in fl.get("-e", []) + fl.get("--editable", []):
                    p.add("pypi", e)
                for f in fl.get("-r", []) + fl.get("--requirement", []) + (ops[:1] if a[:1] == ["sync"] else []):
                    _requirements(os.path.join(cwd, f), p, set())
        elif prog == "uv" and args[:2] == ["tool", "install"]:
            ops, fl = _operands(args[2:], PIP_VALUES)
            _reg(p, fl, env)
            for o in (fl.get("--from", []) or ops[:1]) + fl.get("--with", []):
                p.add("pypi", o)
        elif prog == "uv" and args[:1] == ["run"]:
            _, fl = _operands(args[1:], PIP_VALUES)
            if fl.get("--with"):
                _reg(p, fl, env)
            for o in fl.get("--with", []):
                p.add("pypi", o)
        elif prog == "cargo" and args[:1] in (["add"], ["install"]):
            ops, fl = _operands(
                args[1:],
                {
                    "--registry",
                    "--index",
                    "--git",
                    "--config",
                    "--path",
                    "-p",
                    "--package",
                    "--features",
                    "-F",
                    "--rename",
                    "--target",
                    "--root",
                    "--version",
                    "--vers",
                    "--branch",
                    "--tag",
                    "--rev",
                },
            )
            src = next((f for f in ("--registry", "--index", "--git", "--config") if f in fl), None)
            src = src or next(
                (k for k in env if k.startswith(("CARGO_REGISTRIES_", "CARGO_SOURCE_")) or k == "CARGO_REGISTRY_DEFAULT"), None
            )
            src = src or _cargo_config_source(cwd, env)
            if src:
                p.asks.append(f"cargo source override ({src}): crates would come from a source skedaddle does not check")
            ver = (fl.get("--version") or fl.get("--vers") or [None])[0]
            if "--path" not in fl:
                for o in ops:
                    p.add("crates", f"{o}@{ver}" if ver and "@" not in o else o)
        elif (prog == "uv" and args[:1] == ["add"]) or (prog == "poetry" and args[:1] == ["add"]):
            ops, fl = _operands(args[1:], PIP_VALUES | {"--source"})
            src = "--source" if "--source" in fl else next((k for k in env if k.startswith("POETRY_REPOSITORIES_")), None)
            src = src or _python_project_source(cwd, fl)
            if src:
                p.asks.append(f"custom package source ({src}): packages would come from a source skedaddle does not check")
            _reg(p, fl, env)
            for o in ops:
                p.add("pypi", o)
        elif prog in ("uvx", "pipx"):
            a = args[1:] if prog == "pipx" and args[:1] in (["install"], ["run"], ["inject"]) else args
            ops, fl = _operands(a, PIP_VALUES)
            _reg(p, fl, env)
            for s in (fl.get("--from", []) or ops[:1]) + fl.get("--with", []):
                p.add("pypi", s)


POLICY_PATHS = (".skedaddle.toml", "skedaddle/config.toml", "skedaddle/trusted.json", "skedaddle/decisions.jsonl")
READ_ONLY = {"cat", "less", "more", "head", "tail", "grep", "rg", "ls", "stat", "wc", "diff", "file", "bat", "jq"}


def _self_protection(seg: str, words: list[str], assigns: dict[str, str]) -> str | None:
    """The agent must not relax its own checks: trusting a repo policy, writing skedaddle's policy/state files, or
    setting SKEDADDLE_* for itself are the user's actions (inside-out: an agent editing its own guard)."""
    prog = os.path.basename(words[0]) if words else ""
    if any(k.startswith("SKEDADDLE_") for k in assigns) or (prog == "export" and "SKEDADDLE_" in seg):
        return "setting SKEDADDLE_* changes skedaddle's own behaviour: that is the user's decision, not the agent's"
    names = [os.path.basename(x) for x in words]
    runs_us = any(n in ("skedaddle-mcp", "skedaddle_mcp", "skedaddle_mcp.cli") for n in names) or "skedaddle" in seg
    if runs_us and "trust" in names:
        return "`skedaddle-mcp trust` approves a policy that relaxes checks: only the user may run it"
    if any(pth in seg for pth in POLICY_PATHS) and (prog not in READ_ONLY or re.search(r">|\btee\b", seg)):
        return "this command touches skedaddle's policy or state files: changing them is the user's decision"
    return None


def _reg(p: Plan, flags: dict[str, list[str]], env: dict[str, str], npmrc_dir: str | None = None) -> None:
    why = _registry_override(flags, env)
    if not why and npmrc_dir is not None:  # every registry line of a project .npmrc (cwd and its parents)
        d = os.path.abspath(npmrc_dir)
        for _ in range(12):
            for m in re.finditer(r"^\s*(@[^:\s]+:)?registry\s*=\s*(\S+)", _read(os.path.join(d, ".npmrc")), re.MULTILINE):
                if not official(m[2]):
                    why = f"{os.path.join(d, '.npmrc')}: {m[0].strip()[:80]}"
                    break
            parent = os.path.dirname(d)
            if why or parent == d:
                break
            d = parent
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


def _parents(cwd: str, limit: int = 12):
    d = os.path.abspath(cwd)
    for _ in range(limit):
        yield d
        parent = os.path.dirname(d)
        if parent == d:
            return
        d = parent


def _toml(path: str) -> dict[str, Any] | None:
    """Parsed TOML, {} if the file does not exist, None if it exists but cannot be parsed (or no tomllib)."""
    text = _read(path)
    if not text and not os.path.exists(path):
        return {}
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10: the tomli backport (a dependency there)
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return None  # cannot read it, so cannot tell
    try:
        return tomllib.loads(text)
    except ValueError:
        return None


def _cargo_config_source(cwd: str, env: dict[str, str] | None = None) -> str | None:
    """A cargo config (project .cargo/ in cwd and parents, then $CARGO_HOME) that replaces crates.io or adds registries."""
    env = env or {}
    home = env.get("CARGO_HOME") or os.environ.get("CARGO_HOME") or os.path.join(os.path.expanduser("~"), ".cargo")
    dirs = [os.path.join(d, ".cargo") for d in _parents(cwd)] + [home]
    for d in dirs:
        for name in ("config.toml", "config"):
            path = os.path.join(d, name)
            doc = _toml(path)
            if doc is None:
                return f"{path} (cannot be parsed)"
            if doc.get("source") or doc.get("registries") or (doc.get("registry") or {}).get("default"):
                return path
    return None


UV_INDEX_KEYS = ("index", "index-url", "extra-index-url", "find-links", "default-index")


def _python_project_source(cwd: str, flags: dict[str, list[str]] | None = None) -> str | None:
    """A custom index/source declared where uv/poetry would read it: the nearest pyproject.toml (cwd and parents, or
    --project/--directory), its uv.toml, and the user uv.toml."""
    flags = flags or {}
    base = os.path.join(cwd, (flags.get("--project") or flags.get("--directory") or ["."])[0])
    proj = next((d for d in _parents(base) if os.path.exists(os.path.join(d, "pyproject.toml"))), None)
    files = ([(os.path.join(proj, "pyproject.toml"), True), (os.path.join(proj, "uv.toml"), False)] if proj else []) + [
        (os.path.join(os.path.expanduser("~"), ".config", "uv", "uv.toml"), False)
    ]
    for path, is_pyproject in files:
        doc = _toml(path)
        if doc is None:
            return f"{path} (cannot be parsed)"
        tool = (doc.get("tool") or {}) if is_pyproject else {"uv": doc}
        uv, poetry = tool.get("uv") or {}, tool.get("poetry") or {}
        pip = uv.get("pip") or {}
        if any(uv.get(k) or pip.get(k) for k in UV_INDEX_KEYS) or poetry.get("source"):
            return path
        if any(isinstance(v, dict) and (v.keys() & {"index", "url", "git", "path"}) for v in (uv.get("sources") or {}).values()):
            return f"{path} [tool.uv.sources]"
    return None


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _lock_entries(text: str) -> dict[str, tuple[str, str]]:
    """name -> (version, resolved URL) from a package-lock.json v2/v3 text."""
    try:
        pk = (json.loads(text) if text else {}).get("packages") or {}
    except ValueError:
        return {}
    return {
        k.rsplit("node_modules/", 1)[-1]: (m["version"], str(m.get("resolved") or ""))
        for k, m in pk.items()
        if "node_modules/" in k and isinstance(m, dict) and m.get("version")
    }


def _lock_versions(text: str) -> dict[str, str]:
    return {n: v for n, (v, _) in _lock_entries(text).items()}


def _git_head_file(cwd: str, rel: str) -> str | None:
    """File content at git HEAD, or None. `cat-file blob` runs no textconv/filters; system config is ignored."""
    try:
        r = subprocess.run(
            ["git", "-C", cwd, "-c", "core.fsmonitor=false", "cat-file", "blob", f"HEAD:./{rel}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _npm_lock_changes(cwd: str, p: Plan) -> list[str]:
    """Lockfile entries new or changed since git HEAD (a direct lockfile edit installs with no manifest change); with no
    git baseline, the direct dependencies' locked versions. An entry resolved outside the official registry is asked."""
    now = _lock_entries(_read(os.path.join(cwd, "package-lock.json")))
    if not now:
        return []
    head_text = _git_head_file(cwd, "package-lock.json")
    if head_text is not None:
        head = _lock_entries(head_text)
        picked = {n: e for n, e in now.items() if head.get(n) != e}
    else:
        try:
            with open(os.path.join(cwd, "package.json"), encoding="utf-8") as fh:
                pkg = json.load(fh)
        except (OSError, ValueError):
            pkg = {}
        direct = {
            **(pkg.get("dependencies") or {}),
            **(pkg.get("devDependencies") or {}),
            **(pkg.get("optionalDependencies") or {}),
        }
        picked = {n: e for n, e in now.items() if n in direct}
    out = []
    for n, (v, resolved) in sorted(picked.items()):
        if resolved and not official(resolved):
            p.asks.append(f"{n}@{v} resolves to {resolved[:100]}, not the official registry")
            continue
        out.append(f"{n}@{v}")
    return out


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
        p.add("pypi", ln)


def targets(command: str, cwd: str) -> list[tuple[str, str]]:
    """Packages the command would fetch (see `plan` for the reasons to ask as well)."""
    return plan(command, cwd, {})[0]


def decide(command: str, cwd: str, env: dict[str, str] | None = None) -> dict[str, Any] | None:
    """The hook's answer for one shell command, logged locally (see `skedaddle-mcp stats`)."""
    _LAST[0] = []
    res = _decide(command, cwd, env)
    if _LAST[0]:
        hs = (res or {}).get("hookSpecificOutput") or {}
        decision = hs.get("permissionDecision") or ("warn" if hs.get("additionalContext") else "allow")
        log_decision(
            {
                "cwd": cwd,
                "command": redact(command)[:300],
                "decision": decision,
                "packages": [f"{e}:{s}" for e, s in _LAST[0]],
                "reason": redact(hs.get("permissionDecisionReason") or hs.get("additionalContext") or "")[:600],
            }
        )
    return res


_LAST: list = [[]]


def redact(text: str) -> str:
    """Strip what must never reach a log: NAME=VALUE values, user:password@ in URLs, long token-like strings."""
    text = re.sub(r"(?<![\w-])([A-Za-z_][A-Za-z0-9_]*)=(\S+)", r"\1=***", text)
    text = re.sub(r"(://)[^/@\s]+@", r"\1***@", text)
    return re.sub(r"\b[A-Za-z0-9_\-]{32,}\b", "***", text)


def log_path() -> str | None:
    v = os.environ.get("SKEDADDLE_LOG")
    if v == "0":
        return None
    return v or os.path.join(
        os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state"),
        "skedaddle",
        "decisions.jsonl",
    )


def log_decision(row: dict[str, Any]) -> None:
    """Append one JSON line (0600). Local only: nothing is sent anywhere. SKEDADDLE_LOG=0 disables it."""
    import time as _time

    path = log_path()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()), **row}) + "\n")
    except OSError:
        pass


def _decide(command: str, cwd: str, env: dict[str, str] | None = None) -> dict[str, Any] | None:
    tg, asks = plan(command, cwd, env)
    _LAST[0] = tg or [("-", a[:80]) for a in asks]
    if not tg and not asks:
        return None
    blocks, warns, errors = [], [], list(asks)
    jobs = []
    for eco, spec in tg:
        try:
            jobs.append((eco, *parse_spec(eco, spec)))
        except ValueError as e:
            errors.append(str(e))
    budget = float(os.environ.get("SKEDADDLE_HOOK_BUDGET", "20"))  # under the harness timeout: a killed hook = allowed
    ex = ThreadPoolExecutor(max_workers=8)
    cfg = _ACTIVE[0]
    futs = {ex.submit(check_package, eco, name, version, cfg): (eco, name) for eco, name, version in jobs}
    done, late = wait(futs, timeout=budget)
    ex.shutdown(wait=False, cancel_futures=True)
    errors += [f"{futs[fut][0]}:{futs[fut][1]}: not checked within {budget:.0f}s" for fut in late]
    for fut in done:
        eco, name = futs[fut]
        try:
            rep = fut.result()
        except Exception as e:  # noqa: BLE001 — any failure in one check is "could not verify", never an allow
            errors.append(f"{eco}:{name}: check failed ({type(e).__name__})")
            continue
        if rep is None:
            errors.append(f"{eco}:{name}: no result")
            continue
        label = f"{eco}:{name}{'@' + rep.version if rep.version else ''}"
        shown = [x for x in rep.findings if x.severity != "info" and (rep.verdict != "block" or x.severity == "block")]
        lines = [f"{label}: {x.message}" + (f" ({x.source})" if x.source else "") for x in shown]
        if rep.verdict == "block" and rep.suggestion:
            sug = rep.suggestion
            if "version" in sug:
                fixed = f"{name}=={sug['version']}" if eco == "pypi" else f"{name}@{sug['version']}"
                lines.append(f"-> install {fixed} instead: it fixes every blocking advisory above (same major line when possible)")
            elif "did_you_mean" in sug:
                lines.append(f"-> did you mean `{sug['did_you_mean']}`? Check it is the package you intended before installing")
        {"block": blocks, "warn": warns, "error": errors}.get(rep.verdict, []).extend(lines)
    untrusted = getattr(_ACTIVE[0], "untrusted", None)
    if untrusted:
        note = (f"(note: {untrusted} is not trusted, never reviewed or changed since, so its exceptions and mirrors are "
                "ignored until the user runs `skedaddle-mcp trust`)")
        if blocks:
            blocks.append(note)
        elif errors:
            errors.append(note)
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
