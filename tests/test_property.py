"""Property: an ordinary command that installs package X either puts X on the check list or asks the user. Never silent.

Eight review rounds found the same class of bug: a new spelling of an install that the parser skipped. Instead of
adding one case per finding, this generates the spellings: package managers, boolean flags, version suffixes,
wrappers (sudo, nice, timeout, env, NAME=VALUE, time), `cd dir &&`, chains, and `sh -c` / `bash -ec` / `bash -o
pipefail -c` wrapping. Value-taking flags are excluded on purpose: `pip install -t x pkg` is a different command.
"""

import shlex

from hypothesis import given, settings
from hypothesis import strategies as st

from skedaddle_mcp.hook import plan

PKG = "zzq-hallucinated-pkg"

TEMPLATES = {
    "npm": [
        "npm install {f}{p}",
        "npm i {p} {f}",
        "npm add {f}{p}",
        "pnpm add {f}{p}",
        "pnpm i {p}",
        "yarn add {f}{p}",
        "yarn global add {p}",
        "bun add {f}{p}",
        "npx {f}{p}",
        "pnpm dlx {p}",
        "bunx {p}",
        "bun x {p}",
        "npm exec {p}",
        "npm it {p}",
    ],
    "pypi": [
        "pip install {f}{p}",
        "pip3 install {p} {f}",
        "pip3.12 install {p}",
        "python3 -m pip install {f}{p}",
        "python -m pip install {p}",
        "uv add {f}{p}",
        "uv pip install {f}{p}",
        "uvx {p}",
        "pipx install {p}",
        "poetry add {p}",
        "uv tool install {p}",
    ],
    "crates": ["cargo add {p}", "cargo install {p}"],
}
BOOL_FLAGS = {
    "npm": ["-D ", "--save ", "-g ", "--save-exact ", "--no-audit ", "-E ", "--legacy-peer-deps ", ""],
    "pypi": ["-U ", "--user ", "-q ", "--no-cache-dir ", "--upgrade ", ""],
    "crates": [""],
}
VERSIONS = {"npm": ["", "@1.2.3", "@^1.0.0", "@latest"], "pypi": ["", "==1.2.3", ">=1.0"], "crates": [""]}
WRAPPERS = ["", "sudo ", "nice ", "timeout 30 ", "env FOO=1 ", "FOO=bar ", "time ", "sudo -u node ", "nice -n 5 "]
PREFIXES = ["", "cd sub && ", "true; ", "echo start && ", "cd sub; "]
SHELLS = [None, "sh -c", "bash -c", "bash -ec", "bash -lc", "bash -o pipefail -c", "zsh -c", "bash -opipefail -c"]


@st.composite
def install_command(draw):
    eco = draw(st.sampled_from(sorted(TEMPLATES)))
    tpl = draw(st.sampled_from(TEMPLATES[eco]))
    pkg = PKG + (draw(st.sampled_from(VERSIONS[eco])) if "{p}" in tpl else "")
    cmd = tpl.format(f=draw(st.sampled_from(BOOL_FLAGS[eco])), p=pkg).strip()
    cmd = draw(st.sampled_from(WRAPPERS)) + cmd
    cmd = draw(st.sampled_from(PREFIXES)) + cmd
    sh = draw(st.sampled_from(SHELLS))
    if sh:
        cmd = f"{sh} {shlex.quote(cmd)}"
    return eco, cmd


@settings(max_examples=600, deadline=None)
@given(install_command())
def test_an_install_is_checked_or_asked(tmp_path_factory, ec):
    eco, cmd = ec
    cwd = tmp_path_factory.mktemp("w")
    (cwd / "sub").mkdir()
    targets, asks = plan(cmd, str(cwd), {})
    checked = any(e == eco and s.split("==")[0].split(">=")[0].startswith(PKG) for e, s in targets)
    assert checked or asks, f"silent: {cmd!r} -> targets={targets} asks={asks}"
