# skedaddle-mcp

Check an open-source package **before an AI coding agent installs it**. A pre-install hook and an MCP server for npm,
PyPI and crates.io that blocks:

- names that do not exist (hallucinated or mistyped, the "slopsquatting" vector),
- known malware and packages npm has taken down,
- HIGH/CRITICAL CVEs in the exact version when a fixed version exists (it tells you which one),
- and **signs of a compromised release**: provenance attestation lost, a new publisher, an install script or new
  dependencies appearing in a patch release, a version that was published and then pulled.

No account, no API key, no telemetry. Apache-2.0.

```console
$ skedaddle-mcp check npm axios@1.14.1 | jq -r '"\(.verdict): \(.findings[0].message)"'
block: axios@1.14.1 was published on 2026-03-31T00:21:58.168Z and later removed from the registry (removal usually follows a compromise or malware report)
$ skedaddle-mcp check npm event-stream@3.3.5 | jq -r '"\(.verdict): \(.findings[0].message)"'
warn: event-stream@3.3.5 was published by 'right9ctrl', who published none of the previous 10 releases (dominictarr), without provenance
```

The full output is JSON: verdict, and each finding with its signal, severity, evidence and source URL.

## Why this exists

- Agents run `npm install` and `pip install` in shells nobody hardened. The package manager's own protections
  (release cooldowns, provenance checks, build-script allowlists) are off unless someone turned them on.
- Compromised releases are short-lived and high-impact. axios 1.14.1 was live for about three hours on 2026-03-31
  ([StepSecurity](https://stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)) on a
  package with about 108M weekly downloads ([opensourcemalware.com](https://opensourcemalware.com/blog/the-software-supply-chain-malware-landscape-january-may-2026));
  litellm 1.82.7/1.82.8 reached PyPI with a stolen token on 2026-03-24 ([HN](https://news.ycombinator.com/item?id=47501426)).
- On npm, OSV holds about 223,000 malicious-package records against about 8,100 ordinary advisories (counted from
  the [OSV npm dump](https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip), 2026-11-08; records, not incidents).
- LLMs invent package names: at least 5.2% of commercial-model and 21.7% of open-model code samples referenced a
  package that does not exist ([Spracklen et al., USENIX Security 2025](https://arxiv.org/abs/2406.10279)).
- The #1 reason developers mute security tools is noise: false positives and unactionable alerts
  ([npm maintainer survey, arXiv 2601.20240](https://arxiv.org/html/2601.20240v1)). So skedaddle stays quiet by
  default: ordinary CVEs are not reported, a fresh release alone is not a warning, and every finding carries the
  evidence and the URL it came from.

## Install

```bash
uv tool install git+https://github.com/altairzhambyl/skedaddle-mcp
skedaddle-mcp --version
```

### As a Claude Code pre-install hook (enforcing — recommended)

An MCP tool is advisory: the model may not call it. A hook runs on every shell command. Add to
`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "skedaddle-mcp hook", "timeout": 60, "onFailure": "block" }] }
    ]
  }
}
```

`"onFailure": "block"` (Claude Code 2.1.295+) makes a crashed or timed-out hook block the command instead of letting it
run; skedaddle itself answers within `SKEDADDLE_HOOK_BUDGET` seconds (default 20) and asks about anything it did not
finish.

On **block** the agent is denied (the user can still run the command themselves). On **warn** the install proceeds
and the agent is told why. If a registry or OSV cannot be reached, the user is **asked** (set
`SKEDADDLE_ON_ERROR=allow` or `deny` to change that). Anything skedaddle cannot check is **asked about, never silently allowed**: a git/URL/
tarball source, a custom registry or index (`--registry`, `-i`, `--extra-index-url`, `npm_config_registry`,
`PIP_INDEX_URL`, `UV_INDEX_URL`, an index line inside a requirements file), or more than 50 packages in one command.
A bare `npm install` / `npm ci` after the agent edited `package.json` or the lockfile is checked too: dependencies the
lockfile does not pin yet, and lockfile entries that changed since git HEAD. `npm:` aliases are checked as the real
package; `cd dir && ...` and `sh -c '...'` are followed.

### As an MCP server (any MCP client)

```bash
claude mcp add skedaddle -- skedaddle-mcp
```

Tools: `check_package(ecosystem, package)` and `audit_lockfile(path)`.

### From a shell or CI

```bash
skedaddle-mcp check pypi requests==2.32.3
skedaddle-mcp audit package-lock.json      # also npm-shrinkwrap.json, requirements*.txt
skedaddle-mcp doctor                       # which package-manager protections are off, and the lines to add
```

Exit codes: 0 allow, 1 warn, 2 block, 3 could not verify.

## Signals

| Signal | Severity | Ecosystems | What it means |
|---|---|---|---|
| `not-found` | block | all | the name does not exist (hallucinated / typo) |
| `malware`, `security-placeholder` | block | all / npm | OSV `MAL-*` or a malware advisory; npm replaced the package with a `-security` placeholder |
| `unpublished-version`, `yanked` | block | npm / PyPI, crates | the version was pulled after publication |
| `provenance-lost` | block | npm, PyPI | earlier releases had a provenance attestation (npm) or PEP 740 attestation (PyPI); this one does not |
| `install-script-added` | block | npm | a `preinstall`/`install`/`postinstall` script appears that the previous release did not have |
| `cve` | block | all | HIGH/CRITICAL in this exact version **and** a fixed version exists (`SKEDADDLE_ALL_CVES=1` reports the rest as info) |
| `fresh-package` | block | all | the package itself is under 30 days old |
| `new-publisher` | warn | npm, PyPI | published by an account / trusted publisher that published none of the recent releases, without provenance (info on a major bump) |
| `deps-added-in-patch`, `no-git-head` | warn | npm | a patch release adds dependencies; not published from a git checkout |
| `fresh-release` | info (warn next to another signal) | all | the version is under 3 days old |
| `low-downloads` | warn | npm | under 50 downloads last week |

## What leaves your machine

Only package names and versions, sent to the public registries (`registry.npmjs.org`, `api.npmjs.org`, `pypi.org`,
`crates.io`) and to [OSV](https://osv.dev) (`api.osv.dev`). Nothing else, no telemetry.

## How it compares (credit where due)

Most of this problem is solved by settings you should turn on anyway; `skedaddle-mcp doctor` shows which are off:
npm `min-release-age`, `ignore-scripts`; pnpm `minimumReleaseAge`, `trustPolicy: no-downgrade`, `strictDepBuilds`;
uv `exclude-newer`. A cooldown alone would have stopped the axios and litellm releases.

| Tool | Overlap | Difference |
|---|---|---|
| [npq](https://github.com/lirantal/npq) (Apache-2.0) | provenance regression, new maintainer, install scripts (npm) | skedaddle adds PyPI/crates, the agent hook and MCP |
| [pnpm](https://pnpm.io/settings/dependency-resolution) settings | cooldown, trust downgrade, build scripts | only when pnpm is the package manager and configured |
| [Aikido safe-chain](https://github.com/AikidoSec/safe-chain), [Socket sfw](https://github.com/SocketDev/sfw-free) | malware gating as an install wrapper, no account | different licences; skedaddle adds release-integrity signals |
| [Socket MCP](https://github.com/SocketDev/socket-mcp) | package scores over MCP | needs a Socket sign-in per call |

## Threat model

skedaddle catches the mistakes of a **cooperative agent using ordinary commands**: a hallucinated name, a pinned
version that was compromised, a lockfile edit, a git or custom-registry source it did not notice. It is not a sandbox:
an agent (or a prompt injection) that deliberately hides an install — a script file, `eval`, base64, a binary that
fetches packages — is out of scope. For that, run installs without network access or in a container.

## Limitations

- A custom registry in your *global* `~/.npmrc` or `pip.conf` is not detected (a project `.npmrc` is): the checks run
  against the public registries.

- No tarball-vs-source diff yet (the xz-utils class); `no-git-head` is a weak proxy.
- Typosquats that sit quietly for months, and long-con maintainers, pass the integrity signals; only OSV catches them
  once reported.
- The hook understands: `npm|pnpm|yarn|bun install/add/i/it/ci`, `npm exec|x|create|init`, `npx`, `pnpm|yarn dlx`,
  `bun x`, `bunx`; `pip`/`pipX.Y`/`python -m pip install`, `uv add`, `uv pip install|sync`, `uv tool install`,
  `uv run --with`, `uvx`, `pipx install|run|inject`, `poetry add`; `cargo add|install`. Also through `cd`, `sh -c`,
  `env`, `sudo`, `nice`, `timeout`. Not yet: `uv sync` / `poetry install` from `pyproject.toml`, pnpm/yarn/bun
  lockfile diffs (only `package-lock.json` is diffed against git HEAD). A script that installs packages by other
  means is not seen.
- Thresholds (30-day package age, 3-day release age, 50 downloads) are judgement calls; open an issue with data.

## Development

```bash
uv sync
uv run pytest            # offline: recorded registry/OSV answers in tests/fixtures
uv run ruff check src tests
uv run python tests/record_fixtures.py   # re-record fixtures (network)
```

Tests cover real incidents from recorded registry data (event-stream, axios 1.14.1, ua-parser-js, crossenv,
hallucinated names), honest packages (no false alarms), and synthetic versions of incident patterns whose malicious
releases are no longer in the registry.

## License

Apache-2.0. See [LICENSE](LICENSE).
