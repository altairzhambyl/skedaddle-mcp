"""Report which built-in package-manager protections are on, and print how to turn the missing ones on.

Most compromised releases are caught within hours to days (axios 2026-03-31 was live about 3 hours), so a release
cooldown in the package manager itself stops that class with no tool in the loop. skedaddle never edits these files;
it prints the lines to add. Setting names verified against the npm, pnpm and uv docs (2026-11-08).
"""

from __future__ import annotations

import os
import re

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the tomli backport
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _ini(text: str, key: str) -> str | None:
    m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(\S+)", text, re.MULTILINE)
    return m[1] if m else None


def _yaml(text: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s*:\s*['\"]?([^'\"\s#]+)", text, re.MULTILINE)
    return m[1] if m else None


def _toml_uv(path: str, table: bool) -> str | None:
    text = _read(path)
    if not text:
        return None
    if tomllib is not None:
        try:
            doc = tomllib.loads(text)
        except ValueError:
            return None
        val = (doc.get("tool", {}).get("uv", {}) if table else doc).get("exclude-newer")
        return str(val) if val is not None else None
    m = re.search(r'^exclude-newer\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m[1] if m else None


def report(root: str) -> list[tuple[str, bool, str, str]]:
    """[(check, ok, what is set, how to fix)] for the package managers this project uses."""
    home = os.path.expanduser("~")
    out: list[tuple[str, bool, str, str]] = []
    has = lambda *fs: any(os.path.exists(os.path.join(root, f)) for f in fs)
    js = has("package.json")
    if js and not has("pnpm-lock.yaml", "pnpm-workspace.yaml", "yarn.lock", "bun.lock", "bun.lockb"):
        rc = _read(os.path.join(root, ".npmrc")) + "\n" + _read(os.path.join(home, ".npmrc"))
        age = _ini(rc, "min-release-age")
        out.append(
            (
                "npm release cooldown",
                bool(age and age != "0"),
                f"min-release-age={age}" if age else "not set",
                "add `min-release-age=3` to .npmrc (npm 11.10+; days)",
            )
        )
        ign = _ini(rc, "ignore-scripts")
        out.append(
            (
                "npm install scripts",
                ign == "true",
                f"ignore-scripts={ign}" if ign else "not set (scripts run)",
                "add `ignore-scripts=true` to .npmrc, run the few you need explicitly",
            )
        )
    if has("pnpm-lock.yaml", "pnpm-workspace.yaml"):
        ws = _read(os.path.join(root, "pnpm-workspace.yaml"))
        age = _yaml(ws, "minimumReleaseAge")
        out.append(
            (
                "pnpm release cooldown",
                age != "0",
                f"minimumReleaseAge: {age}" if age else "default (1440 min in pnpm 11)",
                "set `minimumReleaseAge: 4320` (3 days) in pnpm-workspace.yaml",
            )
        )
        tp = _yaml(ws, "trustPolicy")
        out.append(
            (
                "pnpm provenance downgrade",
                tp == "no-downgrade",
                f"trustPolicy: {tp}" if tp else "default (off)",
                "set `trustPolicy: no-downgrade` in pnpm-workspace.yaml",
            )
        )
        sb = _yaml(ws, "strictDepBuilds")
        out.append(
            (
                "pnpm build scripts",
                sb != "false",
                f"strictDepBuilds: {sb}" if sb else "default (true)",
                "remove `strictDepBuilds: false`; allow builds per package with `allowBuilds`",
            )
        )
    if has("pyproject.toml", "uv.lock", "requirements.txt"):
        en = (
            _toml_uv(os.path.join(root, "pyproject.toml"), True)
            or _toml_uv(os.path.join(root, "uv.toml"), False)
            or _toml_uv(os.path.join(home, ".config", "uv", "uv.toml"), False)
        )
        out.append(
            (
                "uv release cooldown",
                bool(en and en != "False"),
                f"exclude-newer = {en}" if en else "not set",
                'add `exclude-newer = "3 days"` under [tool.uv] in pyproject.toml (or uv.toml)',
            )
        )
    return out


def main(args: list[str]) -> int:
    root = os.path.abspath(args[0] if args else os.getcwd())
    rows = report(root)
    if not rows:
        print(f"{root}: no package.json, pnpm or Python project found")
        return 0
    for name, ok, now, fix in rows:
        print(f"{'ok ' if ok else 'OFF'}  {name:28} {now}" + ("" if ok else f"\n     -> {fix}"))
    off = sum(not r[1] for r in rows)
    print(f"\n{off} of {len(rows)} protections off. skedaddle never edits these files.")
    return 0
